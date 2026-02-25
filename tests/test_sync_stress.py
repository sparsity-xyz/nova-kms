"""
High-concurrency stress tests for SyncManager.

Simulates a cluster of KMS nodes with a mocked inter-node network to validate:
1. Data convergence (LWW/VectorClock) under concurrent writes.
2. Gossip stability.
3. Node churn resilience.
"""

import logging
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

import config
from data_store import DataStore
from sync_manager import PeerCache, SyncManager
from nova_registry import InstanceStatus

# =============================================================================
# Mocking & Setup
# =============================================================================

@pytest.fixture
def network():
    return SimulatedNetwork()

@pytest.fixture(autouse=True)
def _setup_stress_mocks(monkeypatch, network):
    """Bypass real encryption and specific verification for stress tests."""
    monkeypatch.setattr(config, "IN_ENCLAVE", False)
    
    # Mock encryption to avoid CPU bottlenecks in logic tests
    import secure_channel
    monkeypatch.setattr(secure_channel, "encrypt_json_envelope", lambda odyn, data, pk: data)
    monkeypatch.setattr(secure_channel, "decrypt_json_envelope", lambda odyn, body: body)
    monkeypatch.setattr(secure_channel, "verify_peer_identity", lambda *a, **kw: True)
    monkeypatch.setattr(secure_channel, "get_tee_pubkey_der_hex", lambda *a: "01"*32)

    import auth
    monkeypatch.setattr(auth, "verify_wallet_signature", lambda *a, **kw: True)
    monkeypatch.setattr(auth, "recover_wallet_from_signature", lambda msg, sig: sig if (sig and sig.startswith("0x")) else "0xRecovered")
    monkeypatch.setattr(auth, "_require_fresh_timestamp", lambda ts: True)
    
    # Bypass nonce store validation
    monkeypatch.setattr(auth._nonce_store, "validate_and_consume", lambda nonce: True)
    monkeypatch.setattr(auth, "issue_nonce", lambda: b"fake-nonce")

    # Bypass AppAuthorizer for node-to-node auth
    from auth import AppAuthorizer, AuthResult
    monkeypatch.setattr(AppAuthorizer, "verify", lambda self, identity: AuthResult(authorized=True))

    # Global interceptor for all outbound sync requests
    def _mock_make_request(mgr_inst, url, body, timeout=None):
        return network.global_make_request(mgr_inst, url, body, timeout)

    monkeypatch.setattr(SyncManager, "_make_request", _mock_make_request)

    from data_store import _Namespace
    monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
    monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)

# =============================================================================
# Simulated Environment
# =============================================================================

class SimulatedNetwork:
    """Intercepts and routes 'outbound' requests to node instances."""
    
    def __init__(self):
        self.nodes = {}  # wallet -> SimulatedNode
        self.mgr_to_node = {} # SyncManager -> SimulatedNode
        self.lock = threading.Lock()

    def register_mgr(self, mgr, node):
        with self.lock:
            self.mgr_to_node[mgr] = node
            self.nodes[node.wallet.lower()] = node

    def global_make_request(self, sender_sync_mgr, url, body, timeout=None):
        """Simulate an outbound request reaching the target node's handler."""
        base_url = url.rsplit("/", 1)[0].rstrip("/")
        
        target_wallet = sender_sync_mgr.peer_cache.get_wallet_by_url(base_url)
        if not target_wallet:
            print(f"DEBUG: Network error - unknown wallet for {base_url}")
            return None
        
        target_node = self.nodes.get(target_wallet.lower())
        if not target_node:
            print(f"DEBUG: Network error - {target_wallet} not registered")
            return None

        client_sig = sender_sync_mgr.node_wallet
        pop_headers = {
            "nonce": "ZmFrZS1ub25jZQ==", # "fake-nonce" in base64
            "timestamp": str(int(time.time())),
            "signature": client_sig,
            "wallet": sender_sync_mgr.node_wallet
        }
        
        response = MagicMock()
        response.ok = True
        response.headers = {"X-KMS-Peer-Signature": "fake-mutual-auth-sig"}
        
        try:
            res_dict = target_node.sync_mgr.handle_incoming_sync(
                body, 
                kms_pop=pop_headers,
                signature=None
            )
            
            response.json.return_value = res_dict
            if res_dict.get("status") != "ok":
                print(f"DEBUG: Handler returned error: {res_dict.get('reason')}")
                response.ok = False
                response.status_code = 400
            else:
                response.status_code = 200
                
            response._decrypted_json = res_dict
            # print(f"DEBUG: {sender_sync_mgr.node_wallet} -> {target_wallet} ({body.get('type')}) -> {response.status_code}")
                
        except Exception as exc:
            print(f"DEBUG: Exception during routing: {exc}")
            response.ok = False
            response.status_code = 500

        return response

class SimulatedNode:
    """Wraps the KMS components for a single node instance."""
    
    def __init__(self, wallet, network: SimulatedNetwork, kms_app_id=49):
        self.wallet = wallet
        self.network = network
        self.ds = DataStore(node_id=wallet)
        
        # Mocks
        self.kms_reg = MagicMock()
        self.nova_reg = MagicMock()
        self.odyn = MagicMock()
        self.odyn.eth_address.return_value = wallet
        
        # Peer cache setup
        self.peer_cache = PeerCache(kms_registry_client=self.kms_reg, nova_registry=self.nova_reg)
        
        # Sync manager setup
        self.sync_mgr = SyncManager(self.ds, wallet, self.peer_cache, odyn=self.odyn)
        # Register in network by sync_mgr instance for easier routing
        network.register_mgr(self.sync_mgr, self)
        
        # Internal state for background sync
        self.stop_event = threading.Event()

    def set_peers(self, peer_list):
        """peer_list: list of {'tee_wallet_address': ..., 'node_url': ...}"""
        normalized = []
        for idx, p in enumerate(peer_list, start=1):
            wallet = (p.get("tee_wallet_address") or "").lower()
            if wallet == self.wallet.lower():
                continue
            normalized.append(
                {
                    "tee_wallet_address": wallet,
                    "node_url": p.get("node_url", ""),
                    "tee_pubkey": "01" * 32,
                    "app_id": 49,
                    "operator": wallet,
                    "status": InstanceStatus.ACTIVE,
                    "zk_verified": True,
                    "version_id": 1,
                    "instance_id": idx,
                    "registered_at": 0,
                }
            )
        self.peer_cache._peers = normalized
        self.peer_cache._last_refresh = time.time() + 1000  # Prevent auto-refresh

    def sync_loop(self):
        """Continuously push deltas while active."""
        while not self.stop_event.is_set():
            try:
                self.sync_mgr.push_deltas()
            except Exception:
                pass
            time.sleep(random.uniform(0.1, 0.3))

# =============================================================================
# Stress Test Cases
# =============================================================================

def test_cluster_convergence_under_concurrent_writes(network):
    """
    Stress test 5 nodes with 10 concurrent writers pushing random updates.
    Verify all nodes eventually reach identical states.
    """
    num_nodes = 5
    nodes = []
    
    # Init nodes
    for i in range(num_nodes):
        wallet = f"0xNode{i}"
        node = SimulatedNode(wallet, network)
        nodes.append(node)

    # Establish mesh connectivity
    peer_list = [{"tee_wallet_address": n.wallet, "node_url": f"http://{n.wallet}"} for n in nodes]
    for node in nodes:
        node.set_peers(peer_list)

    # Start background syncers
    for node in nodes:
        t = threading.Thread(target=node.sync_loop, daemon=True)
        t.start()

    # Writer function
    num_apps = 3
    keys_per_app = 10
    total_writes = 500
    
    def writer(thread_id):
        for _ in range(total_writes // 10):
            node = random.choice(nodes)
            app_id = random.randint(1, num_apps)
            key = f"key_{random.randint(1, keys_per_app)}"
            val = f"val_{thread_id}_{random.random()}".encode()
            
            # Simulated node writer thread
            node.ds.put(app_id, key, val)
            time.sleep(random.uniform(0.01, 0.05))

    # Run writers
    with ThreadPoolExecutor(max_workers=10) as executor:
        for i in range(10):
            executor.submit(writer, i)

    # Wait for eventual convergence with bounded polling to reduce flakiness.
    logging.info("Waiting for data convergence...")
    deadline = time.time() + 20
    converged = False

    def _snapshot_fingerprint(node):
        snap = node.ds.full_snapshot()
        out = {}
        for app_id, records in snap.items():
            per_app = {}
            for rec in records:
                per_app[rec.key] = (rec.value, dict(rec.version.clock))
            out[app_id] = per_app
        return out

    while time.time() < deadline:
        reference = _snapshot_fingerprint(nodes[0])
        if all(_snapshot_fingerprint(n) == reference for n in nodes[1:]):
            converged = True
            break
        time.sleep(0.3)

    for node in nodes:
        node.stop_event.set()

    assert converged, "Cluster did not converge before timeout"

    logging.info(f"Convergence verified across {num_nodes} nodes.")

def test_sync_snapshot_under_load(network):
    """
    A new node joins a busy cluster and performs a snapshot request.
    """
    existing_nodes = []
    for i in range(3):
        wallet = f"0xExisting{i}"
        node = SimulatedNode(wallet, network)
        existing_nodes.append(node)
        
    peer_list = [{"tee_wallet_address": n.wallet, "node_url": f"http://{n.wallet}"} for n in existing_nodes]
    for node in existing_nodes:
        node.set_peers(peer_list)
        
    # Populate cluster with data
    for i in range(100):
        random.choice(existing_nodes).ds.put(1, f"load_{i}", b"data")
    
    # Manually trigger gossip so existing_nodes converge
    for _ in range(3): 
        for node in existing_nodes:
            node.sync_mgr.push_deltas()

    # New node joins
    new_wallet = "0xNewJoiner"
    new_node = SimulatedNode(new_wallet, network)

    # Both sides refresh peer cache to include the new node before /sync auth.
    expanded_peer_list = peer_list + [{"tee_wallet_address": new_wallet, "node_url": f"http://{new_wallet}"}]
    for node in existing_nodes:
        node.set_peers(expanded_peer_list)
    new_node.set_peers(expanded_peer_list)
    
    # It requests a snapshot from one of them
    target_peer_url = f"http://{existing_nodes[0].wallet}"
    merged_count = new_node.sync_mgr.request_snapshot(target_peer_url)
    
    assert merged_count == 100
    assert len(new_node.ds.keys(1)) == 100
    logging.info("New node successfully synced snapshot under load.")

def test_concurrent_conflict_lww(network):
    """
    Two nodes write to the same key with identical vector clocks but different timestamps.
    Verify LWW (Last Write Wins) resolution.
    """
    from data_store import VectorClock, DataRecord
    
    n1 = SimulatedNode("0xN1", network)
    n2 = SimulatedNode("0xN2", network)
    
    n1.set_peers([{"tee_wallet_address": "0xN2", "node_url": "http://0xN2"}])
    n2.set_peers([{"tee_wallet_address": "0xN1", "node_url": "http://0xN1"}])

    # Node 1 writes at T
    t_base = int(time.time() * 1000)
    rec1 = DataRecord(
        key="conflict", 
        value=b"v1", 
        version=VectorClock({"shared": 1}), 
        updated_at_ms=t_base
    )
    n1.ds.merge_record(10, rec1)
    
    # Node 2 writes at T + 100
    rec2 = DataRecord(
        key="conflict", 
        value=b"v2", 
        version=VectorClock({"shared": 1}), 
        updated_at_ms=t_base + 100
    )
    n2.ds.merge_record(10, rec2)
    
    # Sync N1 -> N2
    n1.sync_mgr.push_deltas()
    # N2 should keep its own (newer)
    assert n2.ds.get(10, "conflict").value == b"v2"
    
    # Sync N2 -> N1
    n2.sync_mgr.push_deltas()
    # N1 should overwrite with N2's (newer)
    assert n1.ds.get(10, "conflict").value == b"v2"
    
    logging.info("Concurrent conflict LWW resolution verified.")
