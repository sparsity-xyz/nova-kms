"""
Tests for routes.py — API endpoint tests via FastAPI TestClient.

Covers:
  - /health, /status, /nodes
  - /nonce (challenge issuance, rate limiting)
  - /kms/derive (success, uninitialized master secret)
  - /kms/data CRUD (GET, PUT, DELETE, list, errors)
  - /sync (delta, snapshot_request, missing PoP, bad type)
  - Auth 403 enforcement
"""

import base64
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app import app


def _kms_pop_headers(client: TestClient, *, recipient_wallet: str, private_key_hex: str):
    """Build KMS PoP headers for /sync requests."""
    from eth_account import Account
    from eth_account.messages import encode_defunct

    nonce_resp = client.get("/nonce")
    assert nonce_resp.status_code == 200
    nonce_b64 = nonce_resp.json()["nonce"]
    ts = str(int(time.time()))
    msg = f"NovaKMS:Auth:{nonce_b64}:{recipient_wallet}:{ts}"
    pk = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex
    acct = Account.from_key(bytes.fromhex(pk))
    sig = acct.sign_message(encode_defunct(text=msg)).signature.hex()
    return ({
        "x-kms-signature": sig,
        "x-kms-timestamp": ts,
        "x-kms-nonce": nonce_b64,
        "x-kms-wallet": acct.address,
    }, acct.address)


@pytest.fixture(autouse=True)
def _setup_routes(monkeypatch):
    """Initialize routes with mocked dependencies."""
    import importlib
    import asyncio
    
    # 1. Mock asyncio in routes to use a transient loop
    # This avoids "no current event loop" errors and prevents hangs
    # from sharing a loop between TestClient and the app.
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
    
    # 2. Mock config
    import config
    monkeypatch.setattr(config, "IN_ENCLAVE", False)
    monkeypatch.setattr(config, "KMS_APP_ID", 43)
    
    # 3. Reload routes to reset state
    import routes
    importlib.reload(routes)
    
    # 4. Apply the asyncio mock to routes
    monkeypatch.setattr(routes, "asyncio", mock_asyncio)
    
    # 5. Mock routes encryption helpers AFTER reload
    monkeypatch.setattr(routes, "_is_encrypted_envelope", lambda body: True)
    monkeypatch.setattr(routes, "_decrypt_request_body", lambda body, pk: (body, True))
    monkeypatch.setattr(routes, "_encrypt_response", lambda data, pk, request_was_encrypted=True: data)
    
    # Patch logger to see errors
    logger_mock = MagicMock()
    logger_mock.error = lambda msg: print(f"DEBUG_ERROR: {msg}")
    monkeypatch.setattr(routes, "logger", logger_mock)
    
    # Force service availability
    monkeypatch.setattr(routes, "_service_available", True)

    import secure_channel
    monkeypatch.setattr(secure_channel, "decrypt_json_envelope", lambda odyn, body: body)
    monkeypatch.setattr(secure_channel, "encrypt_json_envelope", lambda odyn, data, pk: data)

    # Mock DataStore encryption to bypass key management
    from data_store import DataStore, _Namespace
    monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
    monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)

    odyn = MagicMock()
    odyn.eth_address.return_value = "0x" + "aa" * 20
    
    # Mock mutual signature to avoid odyn dependency issues
    monkeypatch.setattr(routes, "_add_mutual_signature", lambda resp, sig: None)

    ds = DataStore(node_id="test_node")
    from kdf import MasterSecretManager
    mgr = MasterSecretManager()
    mgr.initialize_from_peer(b"\x01" * 32)
    
    # Mock authorizer
    from auth import AppAuthorizer, AuthResult, ClientIdentity
    from sync_manager import PeerCache, SyncManager
    authorizer = MagicMock(spec=AppAuthorizer)
    
    # Important: authorizer must return valid result for test cases
    def verify_side_effect(identity):
        # Allow specific wallet used in test_derive to pass
        if identity.tee_wallet and identity.tee_wallet.lower().startswith("0x"):
            return AuthResult(
                authorized=True, 
                app_id=42, 
                version_id=1, 
                tee_pubkey=bytes.fromhex("ee" * 64)
            )
        return AuthResult(authorized=False, reason="Mock unauthorized")
    
    authorizer.verify.side_effect = verify_side_effect

    kms_reg = MagicMock()
    kms_reg.operator_count.return_value = 3
    kms_reg.is_operator.return_value = True
    kms_reg.get_operators.return_value = ["0x" + "AA" * 20, "0x" + "BB" * 20]

    # NovaAppRegistry mock for PeerCache
    from dataclasses import dataclass
    from nova_registry import AppStatus, VersionStatus, InstanceStatus

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
        instance_id: int = 0
        app_id: int = 43
        version_id: int = 1
        operator: str = ""
        instance_url: str = ""
        tee_pubkey: bytes = b""
        tee_wallet_address: str = ""
        zk_verified: bool = True
        status: object = InstanceStatus.ACTIVE
        registered_at: int = 0

    _instances = {
        1: _FakeInstance(instance_id=1, tee_wallet_address="0x" + "AA" * 20,
                         instance_url="http://localhost:5001", operator="0x" + "AA" * 20),
        2: _FakeInstance(instance_id=2, tee_wallet_address="0x" + "BB" * 20,
                         instance_url="http://localhost:5002", operator="0x" + "BB" * 20),
    }

    _next_instance_id = [100]

    def _get_instance_by_wallet(w: str) -> _FakeInstance:
        for inst in _instances.values():
            if inst.tee_wallet_address.lower() == w.lower():
                return inst
        _next_instance_id[0] += 1
        return _FakeInstance(
            instance_id=_next_instance_id[0],
            app_id=43,
            version_id=1,
            tee_wallet_address=w,
            status=InstanceStatus.ACTIVE,
            zk_verified=True,
        )

    nova_reg = MagicMock()
    nova_reg.get_app.return_value = _FakeApp()
    nova_reg.get_version.return_value = _FakeVersion()
    nova_reg.get_instances_for_version.return_value = list(_instances.keys())
    nova_reg.get_active_instances.return_value = [inst.tee_wallet_address for inst in _instances.values()]
    nova_reg.get_instance.side_effect = lambda iid: _instances[iid]
    nova_reg.get_instance_by_wallet.side_effect = _get_instance_by_wallet

    monkeypatch.setattr("sync_manager.validate_peer_url", lambda url: url)

    monkeypatch.setattr("secure_channel.verify_peer_in_kms_operator_set", lambda *a, **kw: True)
    monkeypatch.setattr("secure_channel.verify_peer_identity", lambda *a, **kw: True)

    peer_cache = PeerCache(kms_registry_client=kms_reg, nova_registry=nova_reg)
    peer_cache.refresh()

    sync_mgr = SyncManager(
        ds, "0xTestNode",
        peer_cache,
    )

    routes.init(
        odyn=odyn,
        data_store=ds,
        master_secret_mgr=mgr,
        authorizer=authorizer,
        kms_registry=kms_reg,
        sync_manager=sync_mgr,
        node_info={
            "tee_wallet": "0xTestNode",
            "node_url": "https://test.kms.example.com",
            "is_operator": True,
            "kms_app_id": 43,
            "kms_registry_address": "0xREG",
        },
    )

    routes.set_service_availability(True)

    # Clear existing routes to ensure we use the reloaded versions
    # This prevents stale route definitions from holding refs to old modules/asyncio
    app.routes.clear()

    # Mount routers
    app.include_router(routes.router)
    app.include_router(routes.exempt_router)

    yield
    
    # Teardown
    importlib.reload(routes)


@pytest.fixture
def client(_setup_routes):
    return TestClient(app, raise_server_exceptions=True)


# =============================================================================
# Health & Status
# =============================================================================


class TestHealth:
    def test_root_overview(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "Nova KMS"
        assert data["docs"]["openapi_json"] == "/openapi.json"
        # Should advertise key endpoints
        advertised = {(e["method"], e["path"]) for e in data["endpoints"]}
        assert ("GET", "/health") in advertised
        assert ("POST", "/kms/derive") in advertised

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_service_unavailable_returns_503(self, client):
        """All router endpoints should 503 when service is unavailable."""
        import routes
        routes.set_service_availability(False, reason="test-offline")
        try:
            resp = client.post(
                "/kms/derive",
                json={"path": "x"},
                headers={"x-tee-wallet": "0x1234"},
            )
            assert resp.status_code == 503
            assert "test-offline" in resp.json()["detail"]["reason"]

            resp_sync = client.post(
                "/sync",
                json={"type": "delta", "sender_wallet": "0x0", "data": {}},
            )
            assert resp_sync.status_code == 503
        finally:
            routes.set_service_availability(True)

    def test_status(self, client):
        resp = client.get("/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "node" in data
        assert "cluster" in data
        assert "data_store" in data

    def test_status_contains_node_info(self, client):
        resp = client.get("/status")
        data = resp.json()
        assert data["node"]["tee_wallet"] == "0xTestNode"
        assert data["node"]["master_secret_initialized"] is True
        assert data["node"]["master_secret"]["state"] in ("generated", "synced")


# =============================================================================
# /nonce
# =============================================================================


class TestNonce:
    def test_returns_nonce(self, client):
        resp = client.get("/nonce")
        assert resp.status_code == 200
        nonce = resp.json()["nonce"]
        # Must be valid base64
        decoded = base64.b64decode(nonce)
        assert len(decoded) == 16

    def test_nonces_are_unique(self, client):
        n1 = client.get("/nonce").json()["nonce"]
        n2 = client.get("/nonce").json()["nonce"]
        assert n1 != n2


# =============================================================================
# /nodes
# =============================================================================


class TestNodes:
    def test_list_operators(self, client):
        resp = client.get("/nodes")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["operators"]) == 2
        assert data["count"] == 2
        item = data["operators"][0]
        assert "operator" in item
        assert "instance" in item
        assert "connection" in item


# =============================================================================
# /kms/derive
# =============================================================================


class TestDerive:
    def test_derive(self, client):
        resp = client.post(
            "/kms/derive",
            json={"path": "test_key"},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["app_id"] == 42
        assert data["path"] == "test_key"
        key_bytes = base64.b64decode(data["key"])
        assert len(key_bytes) == 32

    def test_derive_custom_length(self, client):
        resp = client.post(
            "/kms/derive",
            json={"path": "key", "length": 64},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 200
        key_bytes = base64.b64decode(resp.json()["key"])
        assert len(key_bytes) == 64

    def test_derive_deterministic(self, client):
        h = {"x-tee-wallet": "0x1234"}
        r1 = client.post("/kms/derive", json={"path": "d"}, headers=h)
        r2 = client.post("/kms/derive", json={"path": "d"}, headers=h)
        assert r1.json()["key"] == r2.json()["key"]

    def test_derive_unauthorized(self, client, _setup_routes):
        """Derive returns 403 when authorizer rejects."""
        import routes
        from auth import AuthResult
        # Clear fixture side_effect so return_value is used
        routes._authorizer.verify.side_effect = None
        routes._authorizer.verify.return_value = AuthResult(
            authorized=False, reason="Unauthorized"
        )
        resp = client.post(
            "/kms/derive",
            json={"path": "x"},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 403


# =============================================================================
# /kms/data CRUD
# =============================================================================


class TestData:
    def test_put_and_get(self, client):
        value = base64.b64encode(b"hello world").decode()
        resp = client.put(
            "/kms/data",
            json={"key": "mykey", "value": value},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 200

        resp = client.get("/kms/data/mykey", headers={"x-tee-wallet": "0x1234"})
        assert resp.status_code == 200
        assert base64.b64decode(resp.json()["value"]) == b"hello world"

    def test_get_not_found(self, client):
        resp = client.get("/kms/data/nonexistent", headers={"x-tee-wallet": "0x1234"})
        assert resp.status_code == 404

    def test_list_keys(self, client):
        value = base64.b64encode(b"v").decode()
        client.put("/kms/data", json={"key": "a", "value": value}, headers={"x-tee-wallet": "0x1234"})
        client.put("/kms/data", json={"key": "b", "value": value}, headers={"x-tee-wallet": "0x1234"})

        resp = client.get("/kms/data", headers={"x-tee-wallet": "0x1234"})
        assert resp.status_code == 200
        assert "a" in resp.json()["keys"]
        assert "b" in resp.json()["keys"]

    def test_delete(self, client):
        value = base64.b64encode(b"v").decode()
        client.put("/kms/data", json={"key": "del_me", "value": value}, headers={"x-tee-wallet": "0x1234"})
        resp = client.request(
            "DELETE", "/kms/data",
            json={"key": "del_me"},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 200
        assert resp.json()["deleted"]

    def test_delete_not_found(self, client):
        resp = client.request(
            "DELETE", "/kms/data",
            json={"key": "no_such_key"},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 404

    def test_put_invalid_base64(self, client):
        resp = client.put(
            "/kms/data",
            json={"key": "k", "value": "not_valid_base64!!!"},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 400


# =============================================================================
# /sync
# =============================================================================


class TestSync:
    def test_sync_delta(self, client):
        headers, sender_wallet = _kms_pop_headers(
            client, recipient_wallet="0xTestNode", private_key_hex="0x" + "11" * 32
        )
        resp = client.post(
            "/sync",
            json={
                "type": "delta",
                "sender_wallet": sender_wallet,
                "sender_tee_pubkey": "0xSenderPubkey", # Required by strict envelope check
                "data": {
                    "10": [{
                        "key": "synced",
                        "value": "cafe",
                        "version": {"peer": 1},
                        "updated_at_ms": int(time.time() * 1000),
                        "tombstone": False,
                        "ttl_ms": 0,
                    }]
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["merged"] == 1

    def test_sync_snapshot_request(self, client):
        headers, sender_wallet = _kms_pop_headers(
            client, recipient_wallet="0xTestNode", private_key_hex="0x" + "22" * 32
        )
        resp = client.post(
            "/sync",
            json={"type": "snapshot_request", "sender_wallet": sender_wallet, "sender_tee_pubkey": "0xSenderPubkey"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert "data" in resp.json()

    def test_sync_without_pop_rejected(self, client):
        """Sync without PoP headers should be rejected."""
        resp = client.post(
            "/sync",
            json={"type": "delta", "sender_wallet": "0xAnon", "data": {}},
        )
        assert resp.status_code == 403

    def test_sync_invalid_type(self, client):
        headers, sender_wallet = _kms_pop_headers(
            client, recipient_wallet="0xTestNode", private_key_hex="0x" + "33" * 32
        )
        resp = client.post(
            "/sync",
            json={"type": "bad_type", "sender_wallet": sender_wallet},
            headers=headers,
        )
        assert resp.status_code == 403
