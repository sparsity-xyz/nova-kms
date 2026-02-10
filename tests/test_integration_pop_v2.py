"""
Integration Tests for KMS PoP Authentication.

These tests spin up a full "Server" node using simulation components (no mocks)
and verify that a "Client" (simulated via requests + eth-account) can successfully
authenticate using the Mutual PoP handshake described in kms-core-workflows.md.
"""

import time
import pytest
from fastapi.testclient import TestClient
from eth_account import Account
from eth_account.messages import encode_defunct

from simulation import build_sim_components, DEFAULT_SIM_PEERS
import routes

@pytest.fixture
def sim_server():
    """
    Spin up a Simulation KMS instance in a TestClient.
    This initializes all simulation components: ephemeral Registry, DataStore, Authorizer.
    """
    # 1. Build components
    # Also pass a fixed master secret to avoid any initialization logic that might try to sync
    print("\n[DEBUG] Building sim components...")
    sim = build_sim_components(
        scheduler=False,
        kms_app_id=9999,
    )
    print(f"[DEBUG] Sim components built: {list(sim.keys())}")
    
    # NEW: Create a fresh FastAPI app for this test, avoiding the global `app`'s heavy startup
    from fastapi import FastAPI
    import routes
    
    test_app = FastAPI()
    test_app.include_router(routes.router)
    
    
    # 2. Wire up routes (manual dependency injection for test)
    #    This mimics what `lifespan` does but synchronously and without Side Effects.
    routes.init(
        odyn=sim["odyn"],
        data_store=sim["data_store"],
        master_secret_mgr=sim["master_secret_mgr"],
        authorizer=sim["authorizer"],
        kms_registry=sim["kms_registry"],
        sync_manager=sim["sync_manager"],
        node_info={
            "tee_wallet": sim["tee_wallet"],
            "node_url": sim["node_url"],
            "is_operator": True,
            "kms_app_id": 9999,
            "kms_registry_address": "0xSIM",
            "simulation_mode": True,
        },
    )
    
    # 3. Create Client
    # raise_server_exceptions=False allows 403/500 to be returned as response instead of raising.
    with TestClient(test_app, raise_server_exceptions=False) as client:
        print("[DEBUG] TestClient created")
        yield client, sim
    print("[DEBUG] TestClient yielded")



def _sign_pop_headers(client, path: str, signer_key: str, signer_wallet: str) -> dict:
    """Helper to perform the Client-side PoP handshake steps."""
    # 1. Get Nonce
    nonce_resp = client.get("/nonce")
    assert nonce_resp.status_code == 200
    nonce = nonce_resp.json()["nonce"]
    
    # 2. Sign
    ts = str(int(time.time()))
    # Message: NovaKMS:AppAuth:<Nonce>:<KMS_Wallet>:<Timestamp>
    # Note: In Sim, we treat AppAuth and NodeAuth similarly for the server check.
    # But strictly:
    #   Node->Node: NovaKMS:Auth:<Nonce>:<Recipient>:<Timestamp>
    #   App->Node:  NovaKMS:AppAuth:<Nonce>:<Recipient>:<Timestamp>
    #
    # Let's inspect `enclave/auth.py` and `enclave/routes.py` to see which message format is enforced.
    # `auth.py` `app_identity_from_signature` uses "NovaKMS:AppAuth:..."
    # `sync_manager.py` `kms_identity_from_pop` uses "NovaKMS:Auth:..."
    
    schema = "NovaKMS:Auth" if path == "/sync" else "NovaKMS:AppAuth"
    
    # In simulation, the "Server" wallet is what we are authenticating TO.
    # We need to know the server's wallet address.
    # The helper `sim_server` returns `sim` dict which has `tee_wallet`.
    # BUT, this helper function doesn't have access to `sim`.
    # Let's pass the recipient wallet in.
    pass

def _make_auth_headers(client, signer_key: str, scope: str, recipient_wallet: str) -> dict:
    """
    Generate valid PoP headers.
    scope: 'Auth' (for /sync) or 'AppAuth' (for /kms/...)
    """
    account = Account.from_key(signer_key)
    
    # 1. Challenge
    resp = client.get("/nonce")
    nonce = resp.json()["nonce"]
    ts = str(int(time.time()))
    
    # 2. Sign
    # Format: NovaKMS:<Scope>:<Nonce>:<Recipient>:<Timestamp>
    msg = f"NovaKMS:{scope}:{nonce}:{recipient_wallet}:{ts}"
    sig = account.sign_message(encode_defunct(text=msg)).signature.hex()
    
    return {
        "x-app-signature": sig, # Routes middleware might normalize this?
        # Wait, /sync uses X-KMS-..., /kms uses X-App-...
        # We need to distinguish based on scope.
    }


class TestMutualPopIntegration:
    
    def test_node_to_node_mutual_auth(self, sim_server):
        """
        Verify that a 2nd Operator can sync with the Server using Mutual PoP.
        """
        client, sim = sim_server
        server_wallet = sim["tee_wallet"]
        
        # 1. Identify a valid peer wallet that is NOT the server
        # In `DEFAULT_SIM_PEERS`, index 0 is server, index 1 is another op.
        peer_wallet = DEFAULT_SIM_PEERS[1].tee_wallet
        # We need the private key for this wallet.
        # In simulation, keys are deterministically derived from hash(wallet) or similar? 
        # Actually `simulation.py` doesn't expose private keys for default peers.
        # We must ADD a new operator to the ephemeral registry whose key WE know.
        
        my_key = "0x" + "bb" * 32
        my_account = Account.from_key(my_key)
        my_wallet = my_account.address
        
        # Add 'my_wallet' as an operator in the SimRegistry
        sim["kms_registry"]._peers.append(
            MagicMock(tee_wallet=my_wallet, node_url="http://me", operator=my_wallet)
        )
        
        # 2. Prepare /sync payload
        # Headers: X-KMS-Signature, X-KMS-Nonce, ...
        nonce = client.get("/nonce").json()["nonce"]
        ts = str(int(time.time()))
        msg = f"NovaKMS:Auth:{nonce}:{server_wallet}:{ts}"
        sig = my_account.sign_message(encode_defunct(text=msg)).signature.hex()
        
        headers = {
            "x-kms-signature": sig,
            "x-kms-nonce": nonce,
            "x-kms-timestamp": ts,
            "x-kms-wallet": my_wallet
        }
        
        payload = {
            "type": "delta",
            "sender_wallet": my_wallet,
            "data": {} 
        }
        
        # 3. Send Request
        resp = client.post("/sync", json=payload, headers=headers)
        assert resp.status_code == 200, f"Sync failed: {resp.text}"
        
        # 4. Verify Server's Mutual Auth Response
        # Header: X-KMS-Peer-Signature
        peer_sig = resp.headers.get("x-kms-peer-signature")
        assert peer_sig, "Missing X-KMS-Peer-Signature in response"
        
        # 5. Recover Server's Signature
        # Msg: NovaKMS:Response:<Sig_A>:<Server_Wallet>
        expected_msg = f"NovaKMS:Response:{sig}:{server_wallet}"
        server_pub = Account.recover_message(encode_defunct(text=expected_msg), signature=peer_sig)
        
        assert server_pub.lower() == server_wallet.lower(), "Server signature invalid!"

    def test_app_to_node_mutual_auth(self, sim_server):
        """
        Verify that a valid App can access /kms/derive using Mutual PoP.
        """
        import secrets
        client, sim = sim_server
        server_wallet = sim["tee_wallet"]
        
        # 1. Create a random App Wallet & Key
        app_key = "0x" + secrets.token_hex(32)
        app_account = Account.from_key(app_key)
        app_wallet = app_account.address
        
        # 2. Register this App in SimNovaRegistry
        # We need to Mock the registry to return an instance for this wallet.
        # sim["nova_registry"] is a SimNovaRegistry instance.
        # accessing its internal _instances dict is dirty but effective for test.
        from nova_registry import RuntimeInstance, InstanceStatus, App, AppStatus, AppVersion, VersionStatus
        
        # Create full chain of trust: Instance -> App -> Version
        sim["nova_registry"]._apps[123] = App(123, "0xOwner", b"", "0x", "", 1, 0, AppStatus.ACTIVE)
        sim["nova_registry"]._versions[(123, 1)] = AppVersion(1, "v1", b"", "", "", "", "", VersionStatus.ENROLLED, 0, "0x")
        
        # Register Instance
        inst = RuntimeInstance(
            instance_id=99,
            app_id=123,
            version_id=1,
            tee_wallet_address=app_wallet,
            instance_url="http://app",
            attestation=b"",
            code_measurement=b"fake", # Auth no longer checks this against req, but checks registry consistency?
            zk_verified=True,
            status=InstanceStatus.ACTIVE,
            last_updated_ts=0
        )
        sim["nova_registry"]._instances[app_wallet.lower()] = inst
        
        # 3. Prepare /kms/derive Headers
        nonce = client.get("/nonce").json()["nonce"]
        ts = str(int(time.time()))
        msg = f"NovaKMS:AppAuth:{nonce}:{server_wallet}:{ts}"
        sig = app_account.sign_message(encode_defunct(text=msg)).signature.hex()
        
        headers = {
            "x-app-signature": sig,
            "x-app-nonce": nonce,
            "x-app-timestamp": ts,
            "x-app-wallet": app_wallet
        }
        
        # 4. Request
        resp = client.post("/kms/derive", json={"path": "m/0"}, headers=headers)
        assert resp.status_code == 200, f"Derive failed: {resp.text}"
        
        # 5. Verify Server's Mutual Auth Response
        # Header: X-KMS-Response-Signature (Note: Different header name than /sync)
        srv_sig = resp.headers.get("x-kms-response-signature")
        assert srv_sig, "Missing X-KMS-Response-Signature"
        
        # 6. Recover
        # Msg: NovaKMS:Response:<Sig_A>:<Server_Wallet>
        expected_msg = f"NovaKMS:Response:{sig}:{server_wallet}"
        server_pub = Account.recover_message(encode_defunct(text=expected_msg), signature=srv_sig)
        
        assert server_pub.lower() == server_wallet.lower()
