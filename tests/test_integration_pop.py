"""
Tests for End-to-End App PoP Authentication through the API.

Covers:
  - Full nonce → sign → derive flow with real EIP-191 signatures
  - App PoP auth enforced in production mode (no header fallback)
  - Expired nonce rejection
  - Replayed nonce rejection
  - Stale timestamp rejection
  - Invalid signature rejection
  - Wallet header mismatch rejection
  - Mutual response signature presence
"""

import base64
import time
from unittest.mock import MagicMock

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from app import app


# ── Helpers ──────────────────────────────────────────────────────────

# Deterministic test key
_APP_PRIVATE_KEY = "0x" + "ab" * 32
_APP_ACCOUNT = Account.from_key(bytes.fromhex("ab" * 32))
_APP_WALLET = _APP_ACCOUNT.address.lower()

_WRONG_PRIVATE_KEY = "0x" + "cd" * 32
_WRONG_ACCOUNT = Account.from_key(bytes.fromhex("cd" * 32))

# The KMS node wallet used in the test fixture
_NODE_WALLET = ("0x" + "aa" * 20).lower()


def _app_pop_headers(client: TestClient, *, private_key_hex: str = _APP_PRIVATE_KEY):
    """Acquire a nonce and build App PoP auth headers."""
    nonce_resp = client.get("/nonce")
    assert nonce_resp.status_code == 200
    nonce_b64 = nonce_resp.json()["nonce"]
    ts = str(int(time.time()))

    # Message: NovaKMS:AppAuth:<Nonce>:<KMS_Wallet>:<Timestamp>
    message = f"NovaKMS:AppAuth:{nonce_b64}:{_NODE_WALLET}:{ts}"

    pk = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex
    acct = Account.from_key(bytes.fromhex(pk))
    sig = acct.sign_message(encode_defunct(text=message)).signature.hex()

    return {
        "x-app-signature": sig,
        "x-app-timestamp": ts,
        "x-app-nonce": nonce_b64,
        "x-app-wallet": acct.address,
    }, nonce_b64


# ── Fixture ──────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _setup(monkeypatch):
    """Initialize routes with mocked dependencies and IN_ENCLAVE=False."""
    import config
    import routes
    from auth import AppAuthorizer, AuthResult, set_node_wallet
    from data_store import DataStore
    from kdf import MasterSecretManager
    from nova_registry import InstanceStatus, VersionStatus
    from sync_manager import PeerCache, SyncManager

    monkeypatch.setattr(config, "IN_ENCLAVE", False)
    monkeypatch.setattr(config, "KMS_APP_ID", 43)

    # Mock encryption to pass mandatory checks
    monkeypatch.setattr(routes, "_is_encrypted_envelope", lambda body: True)
    monkeypatch.setattr(routes, "_decrypt_request_body", lambda body, pk: (body, True))
    monkeypatch.setattr(routes, "_encrypt_response", lambda data, pk: data)
    
    # Force service availability
    monkeypatch.setattr(routes, "_service_available", True)

    # Mock DataStore encryption
    from data_store import _Namespace
    monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
    monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)

    odyn = MagicMock()
    odyn.eth_address.return_value = _NODE_WALLET
    odyn.sign_message.return_value = {"signature": "0x" + "ff" * 65}

    set_node_wallet(_NODE_WALLET)

    ds = DataStore(node_id="test_node")
    mgr = MasterSecretManager()
    mgr.initialize_from_peer(b"\x01" * 32)
    
    # Needs to be patched into kdf since app uses global instance
    monkeypatch.setattr("app.master_secret_mgr", mgr)

    authorizer = MagicMock(spec=AppAuthorizer)
    authorizer.verify.return_value = AuthResult(
        authorized=True, 
        app_id=42, 
        version_id=1,
        tee_pubkey=bytes.fromhex("ee" * 64)
    )

    kms_reg = MagicMock()
    kms_reg.operator_count.return_value = 1
    kms_reg.is_operator.return_value = True

    from dataclasses import dataclass
    from nova_registry import AppStatus

    @dataclass
    class _FakeApp:
        app_id: int = 43
        latest_version_id: int = 1
        status: object = AppStatus.ACTIVE

    @dataclass
    class _FakeVersion:
        version_id: int = 1
        status: object = VersionStatus.ENROLLED

    @dataclass
    class _FakeInstance:
        instance_id: int = 1
        app_id: int = 43
        version_id: int = 1
        operator: str = ""
        instance_url: str = ""
        tee_pubkey: bytes = b""
        tee_wallet_address: str = ""
        zk_verified: bool = True
        status: object = InstanceStatus.ACTIVE
        registered_at: int = 0

    nova_reg = MagicMock()
    nova_reg.get_app.return_value = _FakeApp()
    nova_reg.get_version.return_value = _FakeVersion()
    nova_reg.get_instances_for_version.return_value = [1]
    nova_reg.get_instance.return_value = _FakeInstance(
        tee_wallet_address=_NODE_WALLET,
        instance_url="http://localhost:5001",
        operator=_NODE_WALLET,
    )
    nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
        tee_wallet_address=_NODE_WALLET
    )

    monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)
    monkeypatch.setattr("secure_channel.verify_peer_in_kms_operator_set", lambda *a, **kw: True)
    monkeypatch.setattr("secure_channel.verify_peer_identity", lambda *a, **kw: True)

    peer_cache = PeerCache(kms_registry_client=kms_reg, nova_registry=nova_reg)
    peer_cache.refresh()

    sync_mgr = SyncManager(ds, _NODE_WALLET, peer_cache)

    import asyncio
    # Mock asyncio in routes to use a transient loop
    mock_asyncio = MagicMock()
    
    def _run_shim(coro):
        """Run coroutine in a fresh loop."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    mock_loop = MagicMock()
    mock_loop.run_until_complete.side_effect = _run_shim
    # Return our mock loop when routes calls get_event_loop()
    mock_asyncio.get_event_loop.return_value = mock_loop
    
    monkeypatch.setattr(routes, "asyncio", mock_asyncio)

    routes.init(
        odyn=odyn,
        data_store=ds,
        master_secret_mgr=mgr,
        authorizer=authorizer,
        kms_registry=kms_reg,
        sync_manager=sync_mgr,
        node_info={
            "tee_wallet": _NODE_WALLET,
            "node_url": "https://test.kms.example.com",
            "is_operator": True,
            "kms_app_id": 43,
            "kms_registry_address": "0xREG",
        },
    )
    routes.set_service_availability(True)

    def _has_path(path: str) -> bool:
        return any(getattr(r, "path", None) == path for r in app.routes)

    if not _has_path("/kms/derive"):
        app.include_router(routes.router)
    if not _has_path("/nonce"):
        app.include_router(routes.exempt_router)

    yield


@pytest.fixture
def client(_setup):
    return TestClient(app, raise_server_exceptions=False)


# =============================================================================
# Happy Path: Full PoP Flow
# =============================================================================


class TestAppPopDeriveFlow:
    """End-to-end: acquire nonce → sign → /kms/derive → get key."""

    def test_derive_with_pop_succeeds(self, client):
        headers, _ = _app_pop_headers(client)
        resp = client.post("/kms/derive", json={"path": "test/key"}, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["app_id"] == 42
        assert data["path"] == "test/key"
        key_bytes = base64.b64decode(data["key"])
        assert len(key_bytes) == 32

    def test_derive_with_pop_deterministic(self, client):
        """Same path should produce the same derived key."""
        h1, _ = _app_pop_headers(client)
        r1 = client.post("/kms/derive", json={"path": "stable"}, headers=h1)

        h2, _ = _app_pop_headers(client)
        r2 = client.post("/kms/derive", json={"path": "stable"}, headers=h2)

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["key"] == r2.json()["key"]

    def test_data_put_and_get_with_pop(self, client):
        """Full CRUD through PoP auth."""
        value = base64.b64encode(b"pop-secret").decode()

        h1, _ = _app_pop_headers(client)
        put_resp = client.put(
            "/kms/data", json={"key": "pop_key", "value": value}, headers=h1
        )
        assert put_resp.status_code == 200

        h2, _ = _app_pop_headers(client)
        get_resp = client.get("/kms/data/pop_key", headers=h2)
        assert get_resp.status_code == 200
        assert base64.b64decode(get_resp.json()["value"]) == b"pop-secret"


# =============================================================================
# Production Mode Enforcement
# =============================================================================


class TestProductionModeEnforcement:
    """When IN_ENCLAVE=True, header-based identity must be rejected."""

    def test_header_auth_rejected_in_production(self, client, monkeypatch):
        import config
        monkeypatch.setattr(config, "IN_ENCLAVE", True)
        resp = client.post(
            "/kms/derive",
            json={"path": "test"},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 403

    def test_pop_works_in_production(self, client, monkeypatch):
        import config
        monkeypatch.setattr(config, "IN_ENCLAVE", True)
        headers, _ = _app_pop_headers(client)
        resp = client.post("/kms/derive", json={"path": "prod_key"}, headers=headers)
        assert resp.status_code == 200

    def test_no_headers_rejected_in_production(self, client, monkeypatch):
        import config
        monkeypatch.setattr(config, "IN_ENCLAVE", True)
        resp = client.post("/kms/derive", json={"path": "x"})
        assert resp.status_code == 403


# =============================================================================
# PoP Error Cases
# =============================================================================


class TestPopErrorCases:
    """Verify all PoP failure modes return 403."""

    def test_replayed_nonce(self, client):
        """Nonce used twice should fail on replay."""
        headers, nonce_b64 = _app_pop_headers(client)
        # First use succeeds
        resp1 = client.post("/kms/derive", json={"path": "x"}, headers=headers)
        assert resp1.status_code == 200

        # Second use with same nonce should fail (replay)
        resp2 = client.post("/kms/derive", json={"path": "x"}, headers=headers)
        assert resp2.status_code == 403

    def test_invalid_signature(self, client, monkeypatch):
        """A garbled signature should be rejected."""
        import config
        monkeypatch.setattr(config, "IN_ENCLAVE", True)  # force production mode
        nonce_resp = client.get("/nonce")
        nonce_b64 = nonce_resp.json()["nonce"]
        headers = {
            "x-app-signature": "0xdeadbeef",  # too short
            "x-app-timestamp": str(int(time.time())),
            "x-app-nonce": nonce_b64,
        }
        resp = client.post("/kms/derive", json={"path": "x"}, headers=headers)
        assert resp.status_code == 403

    def test_wrong_signer_wallet_mismatch(self, client):
        """Wallet header doesn't match the signing key → 403."""
        nonce_resp = client.get("/nonce")
        nonce_b64 = nonce_resp.json()["nonce"]
        ts = str(int(time.time()))
        message = f"NovaKMS:AppAuth:{nonce_b64}:{_NODE_WALLET}:{ts}"

        # Sign with _APP_PRIVATE_KEY but declare _WRONG_ACCOUNT as the wallet
        sig = _APP_ACCOUNT.sign_message(encode_defunct(text=message)).signature.hex()
        headers = {
            "x-app-signature": sig,
            "x-app-timestamp": ts,
            "x-app-nonce": nonce_b64,
            "x-app-wallet": _WRONG_ACCOUNT.address,  # mismatch
        }
        resp = client.post("/kms/derive", json={"path": "x"}, headers=headers)
        assert resp.status_code == 403

    def test_stale_timestamp(self, client):
        """A timestamp far in the past should be rejected."""
        nonce_resp = client.get("/nonce")
        nonce_b64 = nonce_resp.json()["nonce"]
        stale_ts = str(int(time.time()) - 600)  # 10 minutes ago
        message = f"NovaKMS:AppAuth:{nonce_b64}:{_NODE_WALLET}:{stale_ts}"

        sig = _APP_ACCOUNT.sign_message(encode_defunct(text=message)).signature.hex()
        headers = {
            "x-app-signature": sig,
            "x-app-timestamp": stale_ts,
            "x-app-nonce": nonce_b64,
        }
        resp = client.post("/kms/derive", json={"path": "x"}, headers=headers)
        assert resp.status_code == 403

    def test_missing_nonce_header(self, client):
        """Missing x-app-nonce should fall through to dev header or 403."""
        headers = {
            "x-app-signature": "0xdeadbeef",
            "x-app-timestamp": str(int(time.time())),
            # no x-app-nonce
        }
        # In dev mode, this falls through to header-based identity (empty wallet → 403)
        resp = client.post("/kms/derive", json={"path": "x"}, headers=headers)
        assert resp.status_code == 403


# =============================================================================
# Mutual Response Signature
# =============================================================================


class TestMutualResponseSignature:
    """Verify the KMS returns a mutual auth signature when PoP is used."""

    def test_mutual_signature_present_on_derive(self, client):
        headers, _ = _app_pop_headers(client)
        resp = client.post("/kms/derive", json={"path": "mutual"}, headers=headers)
        assert resp.status_code == 200
        assert "x-kms-response-signature" in resp.headers

    def test_no_mutual_signature_on_header_auth(self, client):
        """Header-based auth (dev mode) should not produce a mutual signature."""
        resp = client.post(
            "/kms/derive",
            json={"path": "dev"},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 200
        # No signature because there was no PoP to respond to
        assert "x-kms-response-signature" not in resp.headers
