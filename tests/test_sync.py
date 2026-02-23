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
from concurrent.futures import ThreadPoolExecutor
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
def _setup_encryption(monkeypatch):
    monkeypatch.setattr(config, "IN_ENCLAVE", False)
    monkeypatch.setattr(config, "KMS_APP_ID", 49)
    
    # Mock encryption helpers to bypass real ECIES logic
    import secure_channel
    monkeypatch.setattr(secure_channel, "encrypt_json_envelope", lambda odyn, data, pk: data)
    monkeypatch.setattr(secure_channel, "decrypt_json_envelope", lambda odyn, body: body)
    
    # Mock identity verification for peers
    monkeypatch.setattr(secure_channel, "verify_peer_identity", lambda *a, **kw: True)
    monkeypatch.setattr(secure_channel, "get_tee_pubkey_der_hex", lambda *a: "01"*32)

    # Mock DataStore encryption to avoid AES errors with fake data
    from data_store import DataStore, _Namespace
    monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
    monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)


from nova_registry import AppStatus, InstanceStatus, VersionStatus


@dataclass
class _FakeApp:
    app_id: int = 49
    latest_version_id: int = 1
    status: object = AppStatus.ACTIVE


@dataclass
class _FakeVersion:
    version_id: int = 1
    status: object = VersionStatus.ENROLLED


@dataclass
class _FakeInstance:
    instance_id: int = 1
    app_id: int = 49
    version_id: int = 1
    tee_wallet_address: str = ""
    instance_url: str = ""
    operator: str = ""
    status: object = InstanceStatus.ACTIVE
    zk_verified: bool = True
    tee_pubkey: bytes = b"\x01" * 32


# Peer definitions reused across fixtures
_PEER_WALLETS = ["0xOp1", "0xOp2"]
_PEER_URLS = {
    "0xop1": "http://localhost:5001",
    "0xop2": "http://localhost:5002",
}


@pytest.fixture
def kms_reg():
    reg = MagicMock()
    reg.get_operators.return_value = list(_PEER_WALLETS)
    reg.is_operator.return_value = True
    reg.operator_count.return_value = len(_PEER_WALLETS)
    # Simulation-compatible hash methods
    reg.get_master_secret_hash.return_value = b"\x00" * 32
    return reg


@pytest.fixture
def nova_reg():
    """NovaRegistry mock supporting PeerCache's version/instance discovery."""
    from nova_registry import InstanceStatus, VersionStatus

    reg = MagicMock()

    reg.get_app.return_value = _FakeApp(app_id=49, latest_version_id=1)
    reg.get_version.return_value = _FakeVersion(version_id=1, status=VersionStatus.ENROLLED)

    # Build instances
    instances = {}
    for idx, wallet in enumerate(_PEER_WALLETS, start=1):
        url = _PEER_URLS.get(wallet.lower(), f"http://localhost:{5000 + idx}")
        instances[idx] = _FakeInstance(
            instance_id=idx,
            app_id=49,
            version_id=1,
            tee_wallet_address=wallet,
            instance_url=url,
            operator=wallet,
            status=InstanceStatus.ACTIVE,
        )

    reg.get_active_instances.return_value = list(_PEER_WALLETS)
    reg.get_instance.side_effect = lambda iid: instances[iid]

    # Counter for dynamic instance IDs
    _next_instance_id = [100]

    def _get_instance_by_wallet(w: str) -> _FakeInstance:
        """Return known instance or create a valid one for any wallet (for sync tests)."""
        for k, v in instances.items():
            if v.tee_wallet_address.lower() == w.lower():
                return v
        # For sync tests: return a valid instance for any wallet
        _next_instance_id[0] += 1
        return _FakeInstance(
            instance_id=_next_instance_id[0],
            app_id=49,
            version_id=1,
            tee_wallet_address=w,
            instance_url="",
            operator=w,
            status=InstanceStatus.ACTIVE,
            zk_verified=True,
        )

    reg.get_instance_by_wallet.side_effect = _get_instance_by_wallet

    return reg


@pytest.fixture
def ds():
    return DataStore(node_id="test-node")


@pytest.fixture(autouse=True)
def _mock_identity_verification(monkeypatch):
    """Auto-mock H1 teePubkey verification so unit tests don't need real keys.

    Tests that specifically verify identity checks should override this
    by patching ``secure_channel.verify_peer_in_kms_operator_set`` and
    ``secure_channel.verify_peer_identity`` in their own test body.
    """
    monkeypatch.setattr(
        "secure_channel.verify_peer_in_kms_operator_set", lambda *a, **kw: True
    )
    monkeypatch.setattr(
        "secure_channel.verify_peer_identity", lambda *a, **kw: True
    )


@pytest.fixture
def peer_cache(kms_reg, nova_reg):
    return PeerCache(kms_registry_client=kms_reg, nova_registry=nova_reg)


@pytest.fixture
def sync_mgr(ds, peer_cache):
    return SyncManager(ds, "0xME", peer_cache)


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
        assert len(peer_cache._peers) == len(_PEER_WALLETS)

    def test_get_peers_auto_refreshes(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peers = peer_cache.get_peers()
        assert len(peers) == len(_PEER_WALLETS)

    def test_get_peers_exclude_wallet(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peers = peer_cache.get_peers()
        assert len(peers) == len(_PEER_WALLETS)
        filtered = peer_cache.get_peers(exclude_wallet="0xOp1")
        assert len(filtered) == len(_PEER_WALLETS) - 1

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
        assert len(peer_cache._peers) == len(_PEER_WALLETS) - 1

    def test_refresh_handles_instance_lookup_error(self, peer_cache, nova_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        nova_reg.get_instance_by_wallet.side_effect = RuntimeError("chain error")
        peer_cache.refresh()
        assert len(peer_cache._peers) == 0

    def test_refresh_skips_non_zk_verified_instances(self, peer_cache, nova_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        original = nova_reg.get_instance_by_wallet.side_effect

        def _instance_side_effect(wallet: str):
            inst = original(wallet)
            if wallet.lower() == _PEER_WALLETS[0].lower():
                inst.zk_verified = False
            return inst

        nova_reg.get_instance_by_wallet.side_effect = _instance_side_effect
        peer_cache.refresh()
        assert len(peer_cache._peers) == len(_PEER_WALLETS) - 1

    def test_refresh_fails_closed_when_version_lookup_errors(self, peer_cache, nova_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        nova_reg.get_version.side_effect = RuntimeError("version lookup failed")
        peer_cache.refresh()
        assert len(peer_cache._peers) == 0

    def test_get_peers_uses_singleflight_refresh(self, peer_cache, monkeypatch):
        calls = {"count": 0}

        def _slow_fetch():
            calls["count"] += 1
            time.sleep(0.05)
            return []

        monkeypatch.setattr(peer_cache, "_fetch_peers_from_chain", _slow_fetch)
        peer_cache._last_refresh = 0

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: peer_cache.get_peers(), range(4)))

        assert calls["count"] == 1

    def test_stale_triggers_refresh(self, peer_cache, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        peer_cache.refresh()
        # Manually mark as stale
        peer_cache._last_refresh = 0
        peers = peer_cache.get_peers()
        assert len(peers) == len(_PEER_WALLETS)  # refreshed again


# =============================================================================
# SyncManager — construction / basic
# =============================================================================


class TestSyncManagerBasic:
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
            "49": [{
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
        rec = sync_mgr.data_store.get(49, "synced_key")
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

    def test_non_operator_rejected(self, sync_mgr, kms_reg, nova_reg, monkeypatch):
        """Non-KMS peer (different app_id) should be rejected."""
        kms_reg.is_operator.return_value = False
        
        # Override registry to return an instance with wrong app_id (not KMS_APP_ID)
        def _get_non_kms_instance(w):
            return _FakeInstance(
                instance_id=999,
                app_id=123,  # Not KMS_APP_ID (49)
                version_id=1,
                tee_wallet_address=w,
                status=InstanceStatus.ACTIVE,
                zk_verified=True,
            )
        nova_reg.get_instance_by_wallet.side_effect = _get_non_kms_instance
        
        pop, wallet = self._make_pop(sync_mgr)
        body = {"type": "delta", "sender_wallet": wallet, "data": {}}
        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
        assert result["status"] == "error"
        assert "Peer authorization failed" in result["reason"]

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

        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xAB" * 32)
        sync_mgr._master_secret_mgr = mgr
        ecdh_key = ec.generate_private_key(ec.SECP384R1())
        pub_bytes = ecdh_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
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

    def test_master_secret_request_fails_when_manager_unavailable(self, sync_mgr, kms_reg):
        sync_mgr._master_secret_mgr = None
        body = {"type": "master_secret_request", "sender_wallet": "0xSender"}

        from auth import issue_nonce
        from eth_account import Account
        from eth_account.messages import encode_defunct

        nonce = issue_nonce()
        nonce_b64 = base64.b64encode(nonce).decode()
        ts = str(int(time.time()))
        acct = Account.from_key(bytes.fromhex("55" * 32))
        msg = f"NovaKMS:Auth:{nonce_b64}:{sync_mgr.node_wallet}:{ts}"
        sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
        pop = {"wallet": acct.address, "signature": sig, "timestamp": ts, "nonce": nonce_b64}
        body["sender_wallet"] = acct.address

        result = sync_mgr.handle_incoming_sync(body, kms_pop=pop)
        assert result["status"] == "error"
        assert "manager unavailable" in result["reason"]


# =============================================================================
# SyncManager — verify_and_sync_peers
# =============================================================================


class TestVerifyAndSyncPeers:
    def test_verified_count(self, sync_mgr, nova_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        sync_mgr.peer_cache.refresh()

        # Mock probe_node to return True
        with patch("probe.probe_node", return_value=True):
            count = sync_mgr.verify_and_sync_peers(nova_reg)
        assert count == len(_PEER_WALLETS)

    def test_unreachable_peer_skipped(self, sync_mgr, nova_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        sync_mgr.peer_cache.refresh()

        with patch("probe.probe_node", return_value=False):
            count = sync_mgr.verify_and_sync_peers(nova_reg)
        assert count == 0

    def test_non_operator_removed(self, sync_mgr, nova_reg, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        sync_mgr.peer_cache.refresh()

        # Make nova_reg return instances with wrong app_id so they fail validation
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.side_effect = lambda w: _FakeInstance(
            instance_id=999, app_id=0, tee_wallet_address=w, status=InstanceStatus.ACTIVE,
        )

        initial = len(sync_mgr.peer_cache._peers)
        with patch("probe.probe_node", return_value=True):
            count = sync_mgr.verify_and_sync_peers(nova_reg)
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

    def test_non_zk_peer_rejected_without_exception(self, sync_mgr, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        sync_mgr.peer_cache._peers = [
            {
                "tee_wallet_address": "0xPeerWallet",
                "node_url": "http://peer-wallet",
            }
        ]
        monkeypatch.setattr(
            "secure_channel.verify_peer_identity",
            lambda *args, **kwargs: False,
        )

        result = sync_mgr._make_request("http://peer-wallet/sync", {"type": "delta"})
        assert result is None


# =============================================================================
# SyncManager — push_deltas resilience
# =============================================================================


class TestPushDeltasResilience:
    def test_peer_exception_does_not_abort_fanout(self, sync_mgr, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
        sync_mgr.peer_cache.refresh()
        sync_mgr.data_store.put(1, "k", b"v")

        calls = {"count": 0}

        def _make_request(url, body, timeout=None):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("preflight failed")
            resp = MagicMock()
            resp.status_code = 200
            return resp

        sync_mgr._make_request = _make_request
        peer_count = len(sync_mgr.peer_cache.get_peers(exclude_wallet=sync_mgr.node_wallet))
        success = sync_mgr.push_deltas()
        assert success == max(0, peer_count - 1)


# =============================================================================
# SyncManager — node_tick  (hash-based online/offline state machine)
# =============================================================================


class TestNodeTick:
    """Tests for the core hash-based online/offline lifecycle in node_tick().

    Invariant: /kms/* is available ONLY when:
        1) self is in the KMS node list (from NovaAppRegistry)
        2) on-chain masterSecretHash is non-zero
        3) local master secret hash matches the on-chain hash
    """

    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)

    @pytest.fixture
    def routes_mod(self):
        """Provide a mock routes module capturing set_service_availability calls."""
        mod = MagicMock()
        mod.set_service_availability = MagicMock()
        return mod

    @pytest.fixture
    def master_mgr(self):
        return MasterSecretManager()

    def _make_tick_mgr(self, ds, kms_reg, nova_reg, *, node_wallet="0xOp1"):
        """Build a SyncManager wired for node_tick testing."""
        pc = PeerCache(kms_registry_client=kms_reg, nova_registry=nova_reg)
        odyn = MagicMock()
        odyn.get_random_bytes.return_value = b"\xAB" * 32
        odyn.sign_tx.return_value = {"raw_transaction": "0xdeadbeef"}
        mgr = SyncManager(ds, node_wallet, pc, odyn=odyn)
        return mgr

    # ------------------------------------------------------------------
    # 1) Self not in node list → offline
    # ------------------------------------------------------------------

    def test_offline_when_self_not_in_node_list(self, ds, kms_reg, nova_reg, master_mgr, monkeypatch):
        """If self wallet is not among discovered ACTIVE instances → offline."""
        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xNotInList")

        with patch("sync_manager.SyncManager.node_tick.__module__", "sync_manager"):
            mgr.node_tick(master_mgr)

        assert master_mgr.is_initialized is False

    def test_offline_when_self_not_in_node_list_service_unavailable(
        self, ds, kms_reg, nova_reg, master_mgr, routes_mod, monkeypatch
    ):
        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xNotInList")
        monkeypatch.setattr("sync_manager.routes", routes_mod, raising=False)

        import sync_manager as sm_mod
        # Patch the lazy import inside node_tick
        with patch.dict("sys.modules", {"routes": routes_mod}):
            mgr.node_tick(master_mgr)

        # Service should be set unavailable
        routes_mod.set_service_availability.assert_called()
        last_call = routes_mod.set_service_availability.call_args_list[-1]
        assert last_call[0][0] is False  # available = False

    # ------------------------------------------------------------------
    # 2) Chain hash == 0 → generate secret, set hash, stay offline
    # ------------------------------------------------------------------

    def test_chain_hash_zero_generates_secret_and_stays_offline(
        self, ds, kms_reg, nova_reg, master_mgr, monkeypatch
    ):
        """When chain hash is 0, node generates secret, submits tx, stays offline."""
        kms_reg.get_master_secret_hash.return_value = b"\x00" * 32
        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xOp1")

        import routes as routes_module
        monkeypatch.setattr(routes_module, "set_service_availability",
                            MagicMock(), raising=False)

        mgr.node_tick(master_mgr)

        # Secret should have been generated
        assert master_mgr.is_initialized is True
        # set_master_secret_hash should have been called
        kms_reg.set_master_secret_hash.assert_called_once()
        # But service should still be unavailable
        avail_calls = routes_module.set_service_availability.call_args_list
        # Last call should be set_service_availability(False, ...)
        assert avail_calls[-1][0][0] is False

    def test_chain_hash_zero_set_fails_stays_offline(
        self, ds, kms_reg, nova_reg, master_mgr, monkeypatch
    ):
        """If setMasterSecretHash tx fails, node stays offline."""
        kms_reg.get_master_secret_hash.return_value = b"\x00" * 32
        kms_reg.set_master_secret_hash.side_effect = RuntimeError("tx failed")
        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xOp1")

        import routes as routes_module
        monkeypatch.setattr(routes_module, "set_service_availability",
                            MagicMock(), raising=False)

        mgr.node_tick(master_mgr)

        avail_calls = routes_module.set_service_availability.call_args_list
        assert avail_calls[-1][0][0] is False

    # ------------------------------------------------------------------
    # 3) Chain hash non-zero, local matches → online, sync_key set
    # ------------------------------------------------------------------

    def test_chain_hash_matches_local_goes_online(
        self, ds, kms_reg, nova_reg, master_mgr, monkeypatch
    ):
        """When chain hash matches local secret hash → service online + sync_key set."""
        from eth_hash.auto import keccak

        master_mgr.initialize_from_peer(b"\xBB" * 32)
        local_hash = keccak(master_mgr.secret)

        kms_reg.get_master_secret_hash.return_value = local_hash
        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xOp1")

        import routes as routes_module
        monkeypatch.setattr(routes_module, "set_service_availability",
                            MagicMock(), raising=False)

        mgr.node_tick(master_mgr)

        # Service should be online
        avail_calls = routes_module.set_service_availability.call_args_list
        assert avail_calls[-1][0][0] is True
        # Sync key should be set
        assert mgr._sync_key is not None

    # ------------------------------------------------------------------
    # 4) Chain hash non-zero, local mismatch → sync from peers → online
    # ------------------------------------------------------------------

    def test_chain_hash_mismatch_syncs_from_peer(
        self, ds, kms_reg, nova_reg, monkeypatch
    ):
        """When chain hash doesn't match local, attempt sync from peers."""
        from eth_hash.auto import keccak

        correct_secret = b"\xCC" * 32
        chain_hash = keccak(correct_secret)
        kms_reg.get_master_secret_hash.return_value = chain_hash

        master_mgr = MasterSecretManager()
        # Local secret is wrong
        master_mgr.initialize_from_peer(b"\xDD" * 32)

        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xOp1")

        import routes as routes_module
        monkeypatch.setattr(routes_module, "set_service_availability",
                            MagicMock(), raising=False)

        # Mock _sync_master_secret_from_peer to provide correct secret
        def fake_sync(peer_url, msm):
            msm.initialize_from_peer(correct_secret)
            return True

        with patch.object(mgr, "_sync_master_secret_from_peer", side_effect=fake_sync):
            mgr.node_tick(master_mgr)

        avail_calls = routes_module.set_service_availability.call_args_list
        assert avail_calls[-1][0][0] is True
        assert mgr._sync_key is not None

    # ------------------------------------------------------------------
    # 5) Chain hash non-zero, sync fails → offline
    # ------------------------------------------------------------------

    def test_chain_hash_mismatch_sync_fails_stays_offline(
        self, ds, kms_reg, nova_reg, monkeypatch
    ):
        """When sync fails, node stays offline."""
        from eth_hash.auto import keccak

        kms_reg.get_master_secret_hash.return_value = keccak(b"\xEE" * 32)
        master_mgr = MasterSecretManager()  # uninitialized

        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xOp1")

        import routes as routes_module
        monkeypatch.setattr(routes_module, "set_service_availability",
                            MagicMock(), raising=False)

        # Mock _sync_master_secret_from_peer to fail
        with patch.object(mgr, "_sync_master_secret_from_peer", return_value=False):
            mgr.node_tick(master_mgr)

        avail_calls = routes_module.set_service_availability.call_args_list
        assert avail_calls[-1][0][0] is False

    # ------------------------------------------------------------------
    # 6) Cannot read chain hash → offline
    # ------------------------------------------------------------------

    def test_chain_hash_read_fails_stays_offline(
        self, ds, kms_reg, nova_reg, master_mgr, monkeypatch
    ):
        kms_reg.get_master_secret_hash.side_effect = RuntimeError("RPC error")
        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xOp1")

        import routes as routes_module
        monkeypatch.setattr(routes_module, "set_service_availability",
                            MagicMock(), raising=False)

        mgr.node_tick(master_mgr)

        avail_calls = routes_module.set_service_availability.call_args_list
        assert avail_calls[-1][0][0] is False

    # ------------------------------------------------------------------
    # 7) Full seed-node lifecycle across multiple ticks
    # ------------------------------------------------------------------

    def test_seed_node_lifecycle_multi_tick(
        self, ds, kms_reg, nova_reg, master_mgr, monkeypatch
    ):
        """Simulate full seed-node lifecycle:
        Tick 1: chain hash = 0 → generate + set → offline
        Tick 2: chain hash = local hash → online + sync_key set
        """
        from eth_hash.auto import keccak

        stored_hash = [b"\x00" * 32]

        def fake_get_hash():
            return stored_hash[0]

        def fake_set_hash(odyn, *, setter_wallet, secret_hash32):
            stored_hash[0] = bytes(secret_hash32)
            return "0xfaketx"

        kms_reg.get_master_secret_hash = MagicMock(side_effect=lambda: fake_get_hash())
        kms_reg.set_master_secret_hash = MagicMock(side_effect=fake_set_hash)

        mgr = self._make_tick_mgr(ds, kms_reg, nova_reg, node_wallet="0xOp1")

        import routes as routes_module
        mock_avail = MagicMock()
        monkeypatch.setattr(routes_module, "set_service_availability", mock_avail, raising=False)

        # Tick 1: hash is 0 → generate, set, stay offline
        mgr.node_tick(master_mgr)
        assert master_mgr.is_initialized is True
        assert mock_avail.call_args_list[-1][0][0] is False  # offline

        # Chain hash now equals local hash (simulating tx confirmation)
        assert stored_hash[0] == keccak(master_mgr.secret)

        # Tick 2: hash matches → online
        mock_avail.reset_mock()
        mgr.node_tick(master_mgr)
        assert mock_avail.call_args_list[-1][0][0] is True  # online
        assert mgr._sync_key is not None
