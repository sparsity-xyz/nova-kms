"""
Tests for sync_manager.py — PeerCache, SyncManager, HMAC helpers.

Covers:
  - _compute_hmac / _verify_hmac
  - PeerCache init, refresh, get_peers, remove_peer, get_wallet_by_url, TTL stale
  - SyncManager construction (scheduler disabled), set_sync_key
  - Delta serialisation / application
  - handle_incoming_sync (PoP flow, HMAC, delta, snapshot_request, master_secret_request)
  - verify_and_sync_peers (probe, operator check, peer removal, master secret sync)
  - push_deltas (outbound), request_snapshot, request_master_secret
  - _make_request (URL validation, PoP handshake, HMAC signing, mutual auth)
"""

import base64
import hashlib
import hmac as hmac_mod
import json
import time
from dataclasses import dataclass
from unittest.mock import MagicMock, Mock, patch

import pytest

import config
from data_store import DataRecord, DataStore
from kdf import MasterSecretManager, derive_sync_key, seal_master_secret
from sync_manager import (
    PeerCache,
    SyncManager,
    _compute_hmac,
    _verify_hmac,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def _plaintext_fallback(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PLAINTEXT_FALLBACK", True)
    monkeypatch.setattr(config, "IN_ENCLAVE", False)


@pytest.fixture
def kms_reg():
    reg = MagicMock()
    reg.get_operators.return_value = ["0xOp1", "0xOp2"]
    reg.is_operator.return_value = True
    reg.operator_count.return_value = 2
    return reg


@dataclass
class _FakeInstance:
    tee_wallet_address: str
    instance_url: str
    operator: str
    status: int = 1


@pytest.fixture
def nova_reg():
    reg = MagicMock()
    reg.get_instance_by_wallet.side_effect = lambda w: _FakeInstance(
        tee_wallet_address=w,
        instance_url=f"http://localhost:{5000 + hash(w) % 1000}",
        operator=w,
    )
    return reg


@pytest.fixture
def ds():
    return DataStore(node_id="test-node")


@pytest.fixture
def peer_cache(kms_reg, nova_reg):
    return PeerCache(kms_registry_client=kms_reg, nova_registry=nova_reg)


@pytest.fixture
def sync_mgr(ds, peer_cache):
    return SyncManager(ds, "0xME", peer_cache, scheduler=False)


# =============================================================================
# HMAC
# =============================================================================


class TestHMAC:
    def test_compute_verify_roundtrip(self):
        key = b"test-key"
        data = b"payload"
        sig = _compute_hmac(key, data)
        assert _verify_hmac(key, data, sig)

    def test_verify_wrong_key(self):
        key = b"k1"
        data = b"hello"
        sig = _compute_hmac(key, data)
        assert not _verify_hmac(b"k2", data, sig)

    def test_verify_wrong_data(self):
        key = b"k"
        sig = _compute_hmac(key, b"a")
        assert not _verify_hmac(key, b"b", sig)

    def test_consistent_with_stdlib(self):
        key = b"secret"
        data = b"body"
        expected = hmac_mod.new(key, data, hashlib.sha256).hexdigest()
        assert _compute_hmac(key, data) == expected


# =============================================================================
# PeerCache
# =============================================================================


class TestPeerCache:
    def test_empty_on_init(self, peer_cache):
        # Before any refresh, _peers is empty
        assert peer_cache._peers == []

    def test_refresh(self, peer_cache, kms_reg, nova_reg, monkeypatch):
        # Mock validate_peer_url to accept any URL in tests
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peer_cache.refresh()
        assert len(peer_cache._peers) == 2

    def test_get_peers_auto_refreshes(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peers = peer_cache.get_peers()
        assert len(peers) == 2

    def test_get_peers_exclude_wallet(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peers = peer_cache.get_peers()
        assert len(peers) == 2
        filtered = peer_cache.get_peers(exclude_wallet="0xOp1")
        assert len(filtered) == 1

    def test_remove_peer(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peer_cache.refresh()
        peer_cache.remove_peer("0xOp1")
        assert all(p["tee_wallet_address"] != "0xOp1" for p in peer_cache._peers)

    def test_get_wallet_by_url(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peer_cache.refresh()
        url = peer_cache._peers[0]["node_url"]
        wallet = peer_cache.get_wallet_by_url(url)
        assert wallet == peer_cache._peers[0]["tee_wallet_address"]

    def test_get_wallet_by_url_unknown(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peer_cache.refresh()
        assert peer_cache.get_wallet_by_url("http://nobody") is None

    def test_refresh_skip_invalid_url(self, peer_cache, monkeypatch):
        from sync_manager import URLValidationError
        call_count = {"n": 0}

        def _validate(url):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise URLValidationError("bad")
            return url

        monkeypatch.setattr("sync_manager.validate_peer_url", _validate)
        peer_cache.refresh()
        # One peer skipped due to URL validation failure
        assert len(peer_cache._peers) == 1

    def test_refresh_handles_instance_lookup_error(self, peer_cache, nova_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        nova_reg.get_instance_by_wallet.side_effect = RuntimeError("chain error")
        peer_cache.refresh()
        assert len(peer_cache._peers) == 0

    def test_stale_triggers_refresh(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peer_cache.refresh()
        # Manually mark as stale
        peer_cache._last_refresh = 0
        peers = peer_cache.get_peers()
        assert len(peers) == 2  # refreshed again


# =============================================================================
# SyncManager — construction / basic
# =============================================================================


class TestSyncManagerBasic:
    def test_scheduler_disabled(self, sync_mgr):
        assert sync_mgr.scheduler is None

    def test_set_sync_key(self, sync_mgr):
        sync_mgr.set_sync_key(b"mykey")
        assert sync_mgr._sync_key == b"mykey"

    def test_sign_payload_without_key(self, sync_mgr):
        assert sync_mgr._sign_payload("test") is None

    def test_sign_payload_with_key(self, sync_mgr):
        sync_mgr.set_sync_key(b"secret")
        sig = sync_mgr._sign_payload("body")
        assert sig is not None
        expected = hmac_mod.new(b"secret", b"body", hashlib.sha256).hexdigest()
        assert sig == expected


# =============================================================================
# SyncManager — delta serialization / merge
# =============================================================================


class TestDeltaSerialization:
    def test_serialize_deltas(self):
        from data_store import VectorClock
        rec = DataRecord(key="k", value=b"v", version=VectorClock({"n": 1}), updated_at_ms=1000)
        out = SyncManager._serialize_deltas({10: [rec]})
        assert "10" in out
        assert out["10"][0]["key"] == "k"

    def test_apply_deltas(self, sync_mgr):
        data = {
            "42": [{
                "key": "synced_key",
                "value": "aabb",
                "version": {"peer": 1},
                "updated_at_ms": int(time.time() * 1000),
                "tombstone": False,
                "ttl_ms": 0,
            }]
        }
        merged = sync_mgr._apply_deltas(data)
        assert merged == 1
        rec = sync_mgr.data_store.get(42, "synced_key")
        assert rec is not None


# =============================================================================
# SyncManager — handle_incoming_sync (PoP)
# =============================================================================


class TestHandleIncomingSync:
    """Test the incoming sync handler with PoP authentication."""

    def _make_pop(self, sync_mgr, *, private_key_hex: str = "11" * 32):
        """Create valid KMS PoP headers targeting this sync_mgr's node_wallet."""
        from auth import issue_nonce
        from eth_account import Account
        from eth_account.messages import encode_defunct

        nonce = issue_nonce()
        nonce_b64 = base64.b64encode(nonce).decode()
        ts = str(int(time.time()))
        acct = Account.from_key(bytes.fromhex(private_key_hex))
        msg = f"NovaKMS:Auth:{nonce_b64}:{sync_mgr.node_wallet}:{ts}"
        sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
        return {
            "wallet": acct.address,
            "signature": sig,
            "timestamp": ts,
            "nonce": nonce_b64,
        }, acct.address

    def test_missing_pop_returns_error(self, sync_mgr):
        result = sync_mgr.handle_incoming_sync({"type": "delta", "data": {}})
        assert result["status"] == "error"
        assert "PoP" in result["reason"]

    def test_incomplete_pop_returns_error(self, sync_mgr):
        result = sync_mgr.handle_incoming_sync(
            {"type": "delta", "data": {}},
            kms_pop={"signature": None, "timestamp": None, "nonce": None},
        )
        assert result["status"] == "error"

    def test_delta_sync_via_pop(self, sync_mgr, kms_reg):
        pop, wallet = self._make_pop(sync_mgr)
        body = {
            "type": "delta",
            "sender_wallet": wallet,
            "data": {
                "10": [{
                    "key": "k",
                    "value": "aa",
                    "version": {"peer": 1},
                    "updated_at_ms": int(time.time() * 1000),
                    "tombstone": False,
                    "ttl_ms": 0,
                }]
            },
        }
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
        assert result["status"] == "ok"
        assert result["merged"] == 1

    def test_snapshot_request_via_pop(self, sync_mgr, kms_reg):
        pop, wallet = self._make_pop(sync_mgr)
        body = {"type": "snapshot_request", "sender_wallet": wallet}
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
        assert result["status"] == "ok"
        assert "data" in result

    def test_unknown_type_returns_error(self, sync_mgr, kms_reg):
        pop, wallet = self._make_pop(sync_mgr)
        body = {"type": "unknown", "sender_wallet": wallet}
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
        assert result["status"] == "error"
        assert "Unknown sync type" in result["reason"]

    def test_sender_wallet_mismatch_returns_error(self, sync_mgr, kms_reg):
        pop, wallet = self._make_pop(sync_mgr)
        body = {"type": "delta", "sender_wallet": "0xSomeoneElse", "data": {}}
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
        assert result["status"] == "error"
        assert "sender_wallet does not match" in result["reason"]

    def test_non_operator_rejected(self, sync_mgr, kms_reg):
        kms_reg.is_operator.return_value = False
        pop, wallet = self._make_pop(sync_mgr)
        body = {"type": "delta", "sender_wallet": wallet, "data": {}}
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
        assert result["status"] == "error"
        assert "Not a registered" in result["reason"]

    def test_hmac_required_when_key_set(self, sync_mgr, kms_reg):
        sync_mgr.set_sync_key(b"shared-key")
        pop, wallet = self._make_pop(sync_mgr)
        body = {"type": "delta", "sender_wallet": wallet, "data": {}}
        # No signature → rejected
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
        assert result["status"] == "error"
        assert "HMAC" in result["reason"]

    def test_hmac_valid_passes(self, sync_mgr, kms_reg):
        key = b"shared-key"
        sync_mgr.set_sync_key(key)
        pop, wallet = self._make_pop(sync_mgr)
        body = {"type": "delta", "sender_wallet": wallet, "data": {}}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        sig = _compute_hmac(key, payload.encode())
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop, signature=sig)
        assert result["status"] == "ok"

    def test_hmac_invalid_rejected(self, sync_mgr, kms_reg):
        sync_mgr.set_sync_key(b"k")
        pop, wallet = self._make_pop(sync_mgr)
        body = {"type": "delta", "sender_wallet": wallet, "data": {}}
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop, signature="bad")
        assert result["status"] == "error"

    def test_expired_timestamp_rejected(self, sync_mgr, kms_reg):
        from auth import issue_nonce
        from eth_account import Account
        from eth_account.messages import encode_defunct

        nonce = issue_nonce()
        nonce_b64 = base64.b64encode(nonce).decode()
        ts = str(int(time.time()) - 9999)  # very old
        acct = Account.from_key(bytes.fromhex("11" * 32))
        msg = f"NovaKMS:Auth:{nonce_b64}:{sync_mgr.node_wallet}:{ts}"
        sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
        pop = {"wallet": acct.address, "signature": sig, "timestamp": ts, "nonce": nonce_b64}

        result = sync_mgr.handle_incoming_sync(
            {"type": "delta", "sender_wallet": acct.address, "data": {}},
            kms_pop=pop,
        )
        assert result["status"] == "error"


# =============================================================================
# SyncManager — master_secret_request flow
# =============================================================================


class TestMasterSecretRequest:
    def test_sealed_exchange(self, sync_mgr, kms_reg):
        """master_secret_request with ecdh_pubkey returns sealed envelope."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        import app as app_module

        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xAB" * 32)
        # Patch app_module.master_secret_mgr
        with patch.object(app_module, "master_secret_mgr", mgr, create=True):
            ecdh_key = ec.generate_private_key(ec.SECP256R1())
            pub_bytes = ecdh_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            body = {
                "type": "master_secret_request",
                "sender_wallet": "0xSender",
                "ecdh_pubkey": pub_bytes.hex(),
            }

            # Build PoP
            from auth import issue_nonce
            from eth_account import Account
            from eth_account.messages import encode_defunct

            nonce = issue_nonce()
            nonce_b64 = base64.b64encode(nonce).decode()
            ts = str(int(time.time()))
            acct = Account.from_key(bytes.fromhex("44" * 32))
            msg = f"NovaKMS:Auth:{nonce_b64}:{sync_mgr.node_wallet}:{ts}"
            sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
            pop = {"wallet": acct.address, "signature": sig, "timestamp": ts, "nonce": nonce_b64}

            body["sender_wallet"] = acct.address

            result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
            assert result["status"] == "ok"
            assert "sealed" in result


# =============================================================================
# SyncManager — verify_and_sync_peers
# =============================================================================


class TestVerifyAndSyncPeers:
    def test_verified_count(self, sync_mgr, kms_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        sync_mgr.peer_cache.refresh()
        with patch("sync_manager.SyncManager.verify_and_sync_peers.__wrapped__", create=True):
            pass

        # Mock probe_node to return True
        with patch("probe.probe_node", return_value=True):
            count = sync_mgr.verify_and_sync_peers(kms_reg)
        assert count == 2

    def test_unreachable_peer_skipped(self, sync_mgr, kms_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        sync_mgr.peer_cache.refresh()

        with patch("probe.probe_node", return_value=False):
            count = sync_mgr.verify_and_sync_peers(kms_reg)
        assert count == 0

    def test_non_operator_removed(self, sync_mgr, kms_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        sync_mgr.peer_cache.refresh()
        kms_reg.is_operator.return_value = False

        initial = len(sync_mgr.peer_cache._peers)
        with patch("probe.probe_node", return_value=True):
            count = sync_mgr.verify_and_sync_peers(kms_reg)
        assert count == 0
        assert len(sync_mgr.peer_cache._peers) < initial


# =============================================================================
# SyncManager — _make_request
# =============================================================================


class TestMakeRequest:
    def test_invalid_url_rejected(self, sync_mgr, monkeypatch):
        from sync_manager import URLValidationError
        monkeypatch.setattr("sync_manager.validate_peer_url",
                            Mock(side_effect=URLValidationError("nope")))
        result = sync_mgr._make_request("http://evil.example.com/sync", {})
        assert result is None

    def test_unknown_peer_wallet_rejected(self, sync_mgr, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        # peer_cache won't find a wallet for this URL
        result = sync_mgr._make_request("http://unknown-peer:8000/sync", {})
        assert result is None
