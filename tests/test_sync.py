"""
Tests for sync_manager.py - SyncManager delta and snapshot operations.
"""

import time
from unittest.mock import MagicMock, patch

import base64

import pytest

from data_store import DataStore
from sync_manager import PeerCache, SyncManager


def _make_kms_pop(*, recipient_wallet: str, private_key_hex: str = "44" * 32) -> dict:
    from auth import issue_nonce
    from eth_account import Account
    from eth_account.messages import encode_defunct

    nonce_b64 = base64.b64encode(issue_nonce()).decode()
    ts = str(int(time.time()))
    msg = f"NovaKMS:Auth:{nonce_b64}:{recipient_wallet}:{ts}"
    pk = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex
    sig = Account.from_key(bytes.fromhex(pk)).sign_message(encode_defunct(text=msg)).signature.hex()
    return {"signature": sig, "timestamp": ts, "nonce": nonce_b64}


class TestSyncManagerLocal:
    """Test sync operations without real HTTP calls."""

    def test_handle_delta(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "key1", b"val1")

        mock_kms = MagicMock()
        mock_kms.is_operator.return_value = True
        mgr = SyncManager(ds, "0xNode1", PeerCache(kms_registry_client=mock_kms))

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
                "sender_wallet": "0xNode2",
                "data": delta_payload,
            },
            kms_pop=_make_kms_pop(recipient_wallet=mgr.node_wallet),
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

        result = mgr.handle_incoming_sync(
            {
                "type": "snapshot_request",
                "sender_wallet": "0xNode2",
            },
            kms_pop=_make_kms_pop(recipient_wallet=mgr.node_wallet),
        )
        assert result["status"] == "ok"
        assert "1" in result["data"]
        assert "2" in result["data"]

    def test_handle_unknown_type(self):
        ds = DataStore(node_id="node1")
        mock_kms = MagicMock()
        mock_kms.is_operator.return_value = True
        mgr = SyncManager(ds, "0xNode1", PeerCache(kms_registry_client=mock_kms))

        result = mgr.handle_incoming_sync(
            {"type": "invalid"},
            kms_pop=_make_kms_pop(recipient_wallet=mgr.node_wallet),
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
