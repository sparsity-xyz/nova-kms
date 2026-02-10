"""
Tests for sync_manager.py - SyncManager delta and snapshot operations.
"""

import time
from unittest.mock import MagicMock, patch

import base64

import pytest

from data_store import DataStore
from sync_manager import PeerCache, SyncManager


def _make_kms_pop(*, recipient_wallet: str, private_key_hex: str = "44" * 32) -> tuple[dict, str]:
    from auth import issue_nonce
    from eth_account import Account
    from eth_account.messages import encode_defunct

    nonce_b64 = base64.b64encode(issue_nonce()).decode()
    ts = str(int(time.time()))
    msg = f"NovaKMS:Auth:{nonce_b64}:{recipient_wallet}:{ts}"
    pk = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex
    acct = Account.from_key(bytes.fromhex(pk))
    sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
    return ({"signature": sig, "timestamp": ts, "nonce": nonce_b64, "wallet": acct.address}, acct.address)


class TestSyncManagerLocal:
    """Test sync operations without real HTTP calls."""

    def test_handle_delta(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "key1", b"val1")

        mock_kms = MagicMock()
        mock_kms.is_operator.return_value = True
        mgr = SyncManager(ds, "0xNode1", PeerCache(kms_registry_client=mock_kms))

        kms_pop, sender_wallet = _make_kms_pop(recipient_wallet=mgr.node_wallet)

        # Simulate incoming delta
        delta_payload = {
            "1": [
                {
                    "key": "key2",
                    "value": "deadbeef",
                    "version": {"node2": 1},
                    "updated_at_ms": int(time.time() * 1000),
                    "tombstone": False,
                    "ttl_ms": 0,
                }
            ]
        }

        result = mgr.handle_incoming_sync(
            {
                "type": "delta",
                "sender_wallet": sender_wallet,
                "data": delta_payload,
            },
            kms_pop=kms_pop,
        )
        assert result["status"] == "ok"
        assert result["merged"] == 1
        assert ds.get(1, "key2").value == bytes.fromhex("deadbeef")

    def test_handle_snapshot_request(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "a", b"aaa")
        ds.put(2, "b", b"bbb")

        mock_kms = MagicMock()
        mock_kms.is_operator.return_value = True
        mgr = SyncManager(ds, "0xNode1", PeerCache(kms_registry_client=mock_kms))

        kms_pop, sender_wallet = _make_kms_pop(recipient_wallet=mgr.node_wallet)

        result = mgr.handle_incoming_sync(
            {
                "type": "snapshot_request",
                "sender_wallet": sender_wallet,
            },
            kms_pop=kms_pop,
        )
        assert result["status"] == "ok"
        assert "1" in result["data"]
        assert "2" in result["data"]

    def test_handle_unknown_type(self):
        ds = DataStore(node_id="node1")
        mock_kms = MagicMock()
        mock_kms.is_operator.return_value = True
        mgr = SyncManager(ds, "0xNode1", PeerCache(kms_registry_client=mock_kms))

        kms_pop, _sender_wallet = _make_kms_pop(recipient_wallet=mgr.node_wallet)

        result = mgr.handle_incoming_sync(
            {"type": "invalid"},
            kms_pop=kms_pop,
        )
        assert result["status"] == "error"

    def test_push_deltas_no_data(self):
        ds = DataStore(node_id="node1")
        mgr = SyncManager(ds, "0xNode1", PeerCache())
        count = mgr.push_deltas()
        assert count == 0


class TestPeerCache:
    def test_refresh(self):
        from nova_registry import RuntimeInstance, InstanceStatus

        mock_kms = MagicMock()
        mock_kms.get_operators.return_value = ["0xA", "0xB"]

        mock_nova = MagicMock()
        mock_nova.get_instance_by_wallet.side_effect = [
            RuntimeInstance(1, 1, 1, "0xA", "https://a.example.com", b"", "0xA", True, InstanceStatus.ACTIVE, 0),
            RuntimeInstance(2, 1, 1, "0xB", "https://b.example.com", b"", "0xB", True, InstanceStatus.ACTIVE, 0),
        ]

        cache = PeerCache(kms_registry_client=mock_kms, nova_registry=mock_nova)
        peers = cache.get_peers()
        assert len(peers) == 2

    def test_exclude_self(self):
        from nova_registry import RuntimeInstance, InstanceStatus

        mock_kms = MagicMock()
        mock_kms.get_operators.return_value = ["0xself", "0xother"]

        mock_nova = MagicMock()
        mock_nova.get_instance_by_wallet.side_effect = [
            RuntimeInstance(1, 1, 1, "0xself", "https://self.example.com", b"", "0xself", True, InstanceStatus.ACTIVE, 0),
            RuntimeInstance(2, 1, 1, "0xother", "https://other.example.com", b"", "0xother", True, InstanceStatus.ACTIVE, 0),
        ]

        cache = PeerCache(kms_registry_client=mock_kms, nova_registry=mock_nova)
        peers = cache.get_peers(exclude_wallet="0xSELF")
        assert len(peers) == 1
        assert peers[0]["tee_wallet_address"] == "0xother"


class TestSyncAuth:
    """Tests for sync authentication (rejecting non-operators)."""

    def test_handle_sync_from_non_operator(self):
        ds = DataStore(node_id="node1")
        mock_kms = MagicMock()
        # Simulation: Valid signature, but NOT in operator list
        mock_kms.is_operator.return_value = False

        mgr = SyncManager(ds, "0xNode1", PeerCache(kms_registry_client=mock_kms))

        # Generate a valid PoP signature from an unknown wallet
        kms_pop, sender_wallet = _make_kms_pop(recipient_wallet=mgr.node_wallet)

        result = mgr.handle_incoming_sync(
            {
                "type": "delta",
                "sender_wallet": sender_wallet,
                "data": {},
            },
            kms_pop=kms_pop,
        )

        assert result["status"] == "error"
        assert "Not a registered KMS operator" in result["reason"]


class TestMasterSecretInitialization:
    """Tests for the split-brain prevention logic in wait_for_master_secret."""

    @pytest.fixture
    def mgr_deps(self):
        ds = MagicMock(spec=DataStore)
        kms_reg = MagicMock()
        peer_cache = MagicMock(spec=PeerCache)
        secret_mgr = MagicMock()
        # Initially False to enter loop
        secret_mgr.is_initialized = False
        odyn = MagicMock()

        sync_mgr = SyncManager(ds, "0xSelf", peer_cache, odyn=odyn)
        return sync_mgr, kms_reg, secret_mgr, peer_cache

    def test_init_solo(self, mgr_deps):
        """If I am the only operator, initialize from random (seed node)."""
        sync_mgr, kms_reg, secret_mgr, peer_cache = mgr_deps

        # Setup: Peer cache returns only self
        peer_cache.get_peers.return_value = [
            {"tee_wallet_address": "0xSelf", "node_url": "http://self", "status": "ACTIVE"}
        ]

        sync_mgr.wait_for_master_secret(kms_reg, secret_mgr)

        secret_mgr.initialize_from_random.assert_called_once_with(sync_mgr.odyn)

    def test_init_peers_inactive(self, mgr_deps):
        """If other operators exist but are not ACTIVE, initialize from random."""
        sync_mgr, kms_reg, secret_mgr, peer_cache = mgr_deps
        from nova_registry import InstanceStatus

        # Peers exist but are STOPPED/inactive
        peer_cache.get_peers.return_value = [
            {"tee_wallet_address": "0xSelf", "node_url": "http://self", "status": InstanceStatus.ACTIVE},
            {"tee_wallet_address": "0xOther", "node_url": "http://other", "status": InstanceStatus.STOPPED},
        ]

        sync_mgr.wait_for_master_secret(kms_reg, secret_mgr)

        secret_mgr.initialize_from_random.assert_called_once_with(sync_mgr.odyn)

    def test_init_peers_active(self, mgr_deps):
        """If active peers exist, must sync from them (do not gen random)."""
        sync_mgr, kms_reg, secret_mgr, peer_cache = mgr_deps
        from nova_registry import InstanceStatus

        # Peer is ACTIVE
        peer_cache.get_peers.return_value = [
            {"tee_wallet_address": "0xSelf", "node_url": "http://self", "status": InstanceStatus.ACTIVE},
            {"tee_wallet_address": "0xOther", "node_url": "http://other", "status": InstanceStatus.ACTIVE},
        ]

        # Mock _sync_master_secret_from_peer to succeed
        with patch.object(sync_mgr, "_sync_master_secret_from_peer", return_value=True) as mock_sync:
            # Side effect: when sync succeeds, mark manager as initialized so loop breaks
            def mark_initialized(*args, **kwargs):
                secret_mgr.is_initialized = True
                return True
            mock_sync.side_effect = mark_initialized

            sync_mgr.wait_for_master_secret(kms_reg, secret_mgr)

            mock_sync.assert_called_once()
            # Crucially: should NOT initialize from random if peers exist
            secret_mgr.initialize_from_random.assert_not_called()

