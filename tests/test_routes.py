"""
Tests for routes.py — API endpoint integration tests using FastAPI TestClient.
"""

import base64
import json
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app import app


@pytest.fixture(autouse=True)
def _setup_routes():
    """
    Initialize routes with mocked dependencies so TestClient works
    without real chain / Odyn.
    """
    import routes
    from auth import AppAuthorizer, AuthResult, ClientAttestation, KMSNodeVerifier
    from data_store import DataStore
    from kdf import CertificateAuthority, MasterSecretManager
    from sync_manager import SyncManager, PeerCache

    odyn = MagicMock()
    odyn.eth_address.return_value = "0x" + "aa" * 20

    ds = DataStore(node_id="test_node")

    mgr = MasterSecretManager()
    mgr.initialize_from_peer(b"\x01" * 32)

    ca = CertificateAuthority(mgr)

    # Mock authorizer that always succeeds with app_id=42
    authorizer = MagicMock(spec=AppAuthorizer)
    authorizer.verify.return_value = AuthResult(authorized=True, app_id=42, version_id=1)

    # Mock node verifier that always succeeds
    node_verifier = MagicMock(spec=KMSNodeVerifier)
    node_verifier.verify_peer.return_value = (True, None)

    # Mock KMS registry
    kms_reg = MagicMock()
    kms_reg.operator_count.return_value = 3
    kms_reg.get_operators.return_value = [
        "0x" + "AA" * 20,
        "0x" + "BB" * 20,
    ]

    sync_mgr = SyncManager(ds, "0xTestNode", PeerCache())

    routes.init(
        odyn=odyn,
        data_store=ds,
        master_secret_mgr=mgr,
        ca=ca,
        authorizer=authorizer,
        node_verifier=node_verifier,
        kms_registry=kms_reg,
        sync_manager=sync_mgr,
        node_info={
            "tee_wallet": "0xTestNode",
            "node_url": "https://test.kms.example.com",
            "is_operator": True,
            "kms_app_id": 9001,
            "kms_registry_address": "0xREG",
        },
    )

    # Include router so endpoints are registered
    # (in normal startup this is done in lifespan, but for test we add directly)
    if routes.router not in [r for r in app.routes]:
        app.include_router(routes.router)

    yield


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# =============================================================================
# Health & Status
# =============================================================================


class TestHealth:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_status(self, client):
        resp = client.get("/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "node" in data
        assert "cluster" in data


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
        # Verify key is base64
        key_bytes = base64.b64decode(data["key"])
        assert len(key_bytes) == 32


# =============================================================================
# /kms/data
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

        resp = client.get(
            "/kms/data/mykey",
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 200
        assert base64.b64decode(resp.json()["value"]) == b"hello world"

    def test_get_not_found(self, client):
        resp = client.get(
            "/kms/data/nonexistent",
            headers={"x-tee-wallet": "0x1234"},
        )
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
            "DELETE",
            "/kms/data",
            json={"key": "del_me"},
            headers={"x-tee-wallet": "0x1234"},
        )
        assert resp.status_code == 200
        assert resp.json()["deleted"]


# =============================================================================
# /sync
# =============================================================================


class TestSync:
    def test_sync_delta(self, client):
        import time
        resp = client.post(
            "/sync",
            json={
                "type": "delta",
                "sender_wallet": "0xPeer",
                "data": {
                    "10": [
                        {
                            "key": "synced",
                            "value": "cafe",
                            "version": {"peer": 1},
                            "updated_at_ms": int(time.time() * 1000),
                            "tombstone": False,
                            "ttl_ms": 0,
                        }
                    ]
                },
            },
            headers={"x-tee-wallet": "0xPeerWallet"},
        )
        assert resp.status_code == 200
        assert resp.json()["merged"] == 1

    def test_sync_snapshot_request(self, client):
        resp = client.post(
            "/sync",
            json={"type": "snapshot_request", "sender_wallet": "0xPeer"},
            headers={"x-tee-wallet": "0xPeerWallet"},
        )
        assert resp.status_code == 200
        assert "data" in resp.json()
