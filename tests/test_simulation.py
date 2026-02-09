"""
Tests for simulation.py — Simulation mode components.

Exercises:
  - SimKMSRegistryClient  (in-memory operator set)
  - SimNovaRegistry        (fake App / Version / Instance)
  - build_sim_components() (wiring factory)
  - Helper functions       (is_simulation_mode, get_sim_*, etc.)
  - App startup in sim     (TestClient integration hitting APIs)
"""

import hashlib
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from simulation import (
    DEFAULT_SIM_PEERS,
    SimKMSRegistryClient,
    SimNovaRegistry,
    SimPeer,
    build_sim_components,
    get_sim_master_secret,
    get_sim_node_index,
    get_sim_peers,
    get_sim_port,
    is_simulation_mode,
)


# =============================================================================
# SimPeer
# =============================================================================


class TestSimPeer:
    def test_defaults(self):
        p = SimPeer(tee_wallet="0xAA", node_url="http://localhost:9000")
        assert p.operator == "0xAA"  # auto-set from tee_wallet

    def test_explicit_operator(self):
        p = SimPeer(tee_wallet="0xAA", node_url="http://localhost:9000", operator="0xOP")
        assert p.operator == "0xOP"


# =============================================================================
# SimKMSRegistryClient
# =============================================================================


class TestSimKMSRegistryClient:
    @pytest.fixture()
    def peers(self):
        return [
            SimPeer(tee_wallet="0xA1", node_url="http://localhost:8000"),
            SimPeer(tee_wallet="0xB2", node_url="http://localhost:8001"),
        ]

    @pytest.fixture()
    def registry(self, peers):
        return SimKMSRegistryClient(peers)

    def test_get_operators(self, registry):
        ops = registry.get_operators()
        assert ops == ["0xA1", "0xB2"]

    def test_is_operator_true(self, registry):
        assert registry.is_operator("0xA1") is True

    def test_is_operator_case_insensitive(self, registry):
        assert registry.is_operator("0xa1") is True

    def test_is_operator_false(self, registry):
        assert registry.is_operator("0xZZ") is False

    def test_operator_count(self, registry):
        assert registry.operator_count() == 2

    def test_operator_at(self, registry):
        assert registry.operator_at(0) == "0xA1"
        assert registry.operator_at(1) == "0xB2"

    def test_operator_at_out_of_range(self, registry):
        with pytest.raises(IndexError):
            registry.operator_at(5)
        with pytest.raises(IndexError):
            registry.operator_at(-1)

    def test_default_peers_when_none(self):
        reg = SimKMSRegistryClient(None)
        assert reg.operator_count() == len(DEFAULT_SIM_PEERS)

    def test_empty_list(self):
        reg = SimKMSRegistryClient([])
        assert reg.operator_count() == 0
        assert reg.get_operators() == []


# =============================================================================
# SimNovaRegistry
# =============================================================================


class TestSimNovaRegistry:
    @pytest.fixture()
    def peers(self):
        return [
            SimPeer(tee_wallet="0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", node_url="http://localhost:8000"),
            SimPeer(tee_wallet="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", node_url="http://localhost:8001"),
        ]

    @pytest.fixture()
    def nova(self, peers):
        return SimNovaRegistry(peers, kms_app_id=100)

    def test_get_instance_by_known_wallet(self, nova):
        inst = nova.get_instance_by_wallet("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        assert inst.instance_id == 1
        assert inst.app_id == 100
        assert inst.tee_wallet_address == "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    def test_get_instance_by_wallet_case_insensitive(self, nova):
        inst = nova.get_instance_by_wallet("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert inst.instance_id == 1

    def test_get_instance_by_wallet_open_auth(self, nova):
        """Unknown wallet should return a fabricated instance when open_auth is on."""
        unknown = "0x1234567890123456789012345678901234567890"
        inst = nova.get_instance_by_wallet(unknown)
        assert inst.tee_wallet_address == unknown
        assert inst.app_id == 100

    def test_get_instance_by_wallet_closed_auth_raises(self, peers):
        nova = SimNovaRegistry(peers, open_auth=False)
        with pytest.raises(ValueError, match="Instance not found"):
            nova.get_instance_by_wallet("0x0000000000000000000000000000000000FFFFFF")

    def test_get_app(self, nova):
        app_obj = nova.get_app(100)
        assert app_obj.app_id == 100

    def test_get_version(self, nova):
        ver = nova.get_version(100, 1)
        assert ver.version_id == 1
        assert ver.version_name == "sim-v1"

    def test_get_instance_by_id(self, nova):
        inst = nova.get_instance(1)
        assert inst.tee_wallet_address == "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    def test_get_instance_by_id_not_found(self, nova):
        with pytest.raises(ValueError, match="Instance 999 not found"):
            nova.get_instance(999)


# =============================================================================
# Helper functions
# =============================================================================


class TestIsSimulationMode:
    def test_env_true(self):
        with patch.dict(os.environ, {"SIMULATION_MODE": "1"}):
            assert is_simulation_mode() is True

    def test_env_true_word(self):
        with patch.dict(os.environ, {"SIMULATION_MODE": "true"}):
            assert is_simulation_mode() is True

    def test_env_false(self):
        with patch.dict(os.environ, {"SIMULATION_MODE": "0"}):
            assert is_simulation_mode() is False

    def test_env_unset_config_false(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIMULATION_MODE", None)
            import config
            original = getattr(config, "SIMULATION_MODE", False)
            try:
                config.SIMULATION_MODE = False
                assert is_simulation_mode() is False
            finally:
                config.SIMULATION_MODE = original

    def test_env_unset_config_true(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIMULATION_MODE", None)
            import config
            original = getattr(config, "SIMULATION_MODE", False)
            try:
                config.SIMULATION_MODE = True
                assert is_simulation_mode() is True
            finally:
                config.SIMULATION_MODE = original


class TestGetSimPort:
    def test_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIM_PORT", None)
            assert get_sim_port() == 8000

    def test_env_override(self):
        with patch.dict(os.environ, {"SIM_PORT": "9090"}):
            assert get_sim_port() == 9090


class TestGetSimNodeIndex:
    def test_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIM_NODE_INDEX", None)
            assert get_sim_node_index() == 0

    def test_env_override(self):
        with patch.dict(os.environ, {"SIM_NODE_INDEX": "2"}):
            assert get_sim_node_index() == 2


class TestGetSimPeers:
    def test_default_peers(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIM_PEERS_CSV", None)
            import config
            original = getattr(config, "SIM_PEERS", [])
            try:
                config.SIM_PEERS = []
                peers = get_sim_peers()
                assert len(peers) == len(DEFAULT_SIM_PEERS)
            finally:
                config.SIM_PEERS = original

    def test_env_csv_override(self):
        csv = "0xAA|http://a:8000,0xBB|http://b:8001"
        with patch.dict(os.environ, {"SIM_PEERS_CSV": csv}):
            peers = get_sim_peers()
            assert len(peers) == 2
            assert peers[0].tee_wallet == "0xAA"
            assert peers[1].node_url == "http://b:8001"


class TestGetSimMasterSecret:
    def test_default_deterministic(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIM_MASTER_SECRET", None)
            expected = hashlib.sha256(b"nova-kms-simulation-master-secret").digest()
            assert get_sim_master_secret() == expected

    def test_env_override_hex(self):
        secret_hex = "ab" * 32
        with patch.dict(os.environ, {"SIM_MASTER_SECRET": secret_hex}):
            result = get_sim_master_secret()
            assert result == bytes.fromhex(secret_hex)


# =============================================================================
# build_sim_components
# =============================================================================


class TestBuildSimComponents:
    def test_default_build(self):
        with patch.dict(os.environ, {"SIM_NODE_INDEX": "0"}, clear=False):
            os.environ.pop("SIM_PEERS_CSV", None)
            comp = build_sim_components()

        assert "tee_wallet" in comp
        assert "node_url" in comp
        assert "kms_registry" in comp
        assert "nova_registry" in comp
        assert "authorizer" in comp
        assert "odyn" in comp
        assert "master_secret" in comp
        assert isinstance(comp["kms_registry"], SimKMSRegistryClient)
        assert isinstance(comp["nova_registry"], SimNovaRegistry)
        assert isinstance(comp["master_secret"], bytes)
        assert len(comp["master_secret"]) == 32

    def test_custom_peers(self):
        custom = [
            SimPeer(tee_wallet="0xDEAD", node_url="http://localhost:7777"),
            SimPeer(tee_wallet="0xBEEF", node_url="http://localhost:7778"),
        ]
        with patch.dict(os.environ, {"SIM_NODE_INDEX": "1"}):
            comp = build_sim_components(peers=custom)
        assert comp["tee_wallet"] == "0xBEEF"

    def test_node_index_out_of_range_fallback(self):
        with patch.dict(os.environ, {"SIM_NODE_INDEX": "99"}):
            comp = build_sim_components()
        # Falls back to index 0
        assert comp["tee_wallet"] == DEFAULT_SIM_PEERS[0].tee_wallet

    def test_authorizer_verify_succeeds(self):
        """AppAuthorizer backed by SimNovaRegistry should accept known wallets."""
        comp = build_sim_components()
        from auth import ClientAttestation

        att = ClientAttestation(
            tee_wallet=DEFAULT_SIM_PEERS[0].tee_wallet,
            measurement=None,
        )
        result = comp["authorizer"].verify(att)
        assert result.authorized is True

    def test_odyn_signer_available(self):
        comp = build_sim_components()
        sig = comp["odyn"].sign_message("hello")
        assert "signature" in sig


# =============================================================================
# Integration — TestClient with simulation app startup
# =============================================================================


@pytest.fixture()
def sim_client():
    """
    Start the app in simulation mode using TestClient.
    Routes are initialized via the lifespan with sim components.
    """
    with patch.dict(os.environ, {"SIMULATION_MODE": "1", "SIM_NODE_INDEX": "0"}):
        from app import app as fastapi_app

        with TestClient(fastapi_app) as client:
            yield client


class TestSimulationApp:
    """End-to-end API tests with the app running in simulation mode."""

    def test_health(self, sim_client):
        r = sim_client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    def test_status(self, sim_client):
        r = sim_client.get("/status")
        assert r.status_code == 200
        body = r.json()
        # simulation_mode is in node_info which propagates through /status
        assert body["node"]["is_operator"] is True
        assert body["cluster"]["total_operators"] == len(DEFAULT_SIM_PEERS)

    def test_nodes(self, sim_client):
        r = sim_client.get("/nodes")
        assert r.status_code == 200
        body = r.json()
        assert "operators" in body
        assert len(body["operators"]) == len(DEFAULT_SIM_PEERS)

    def test_derive(self, sim_client):
        """Derive endpoint should return a deterministic derived key."""
        headers = {
            "x-tee-wallet": DEFAULT_SIM_PEERS[0].tee_wallet,
        }
        r = sim_client.post(
            "/kms/derive",
            json={"path": "m/test/1"},
            headers=headers,
        )
        assert r.status_code == 200
        body = r.json()
        assert "key" in body

    def test_derive_deterministic(self, sim_client):
        """Same path must yield the same derived key each time."""
        headers = {"x-tee-wallet": DEFAULT_SIM_PEERS[0].tee_wallet}
        r1 = sim_client.post("/kms/derive", json={"path": "m/det/1"}, headers=headers)
        r2 = sim_client.post("/kms/derive", json={"path": "m/det/1"}, headers=headers)
        assert r1.json()["key"] == r2.json()["key"]

    def test_data_crud(self, sim_client):
        """Store, get, list, delete a data blob in sim mode."""
        import base64

        headers = {"x-tee-wallet": DEFAULT_SIM_PEERS[0].tee_wallet}
        val_b64 = base64.b64encode(b"hello sim").decode()

        # PUT
        r = sim_client.put(
            "/kms/data",
            json={"key": "mykey", "value": val_b64},
            headers=headers,
        )
        assert r.status_code == 200

        # GET
        r = sim_client.get("/kms/data/mykey", headers=headers)
        assert r.status_code == 200
        assert r.json()["key"] == "mykey"

        # LIST
        r = sim_client.get("/kms/data", headers=headers)
        assert r.status_code == 200
        assert "mykey" in r.json()["keys"]

        # DELETE
        r = sim_client.request("DELETE", "/kms/data", json={"key": "mykey"}, headers=headers)
        assert r.status_code == 200

    def test_cert_issue(self, sim_client):
        """Certificate signing should work in sim mode."""
        import base64
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim-test")]))
            .sign(key, hashes.SHA256())
        )
        csr_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)).decode()

        headers = {"x-tee-wallet": DEFAULT_SIM_PEERS[0].tee_wallet}
        r = sim_client.post("/kms/sign_cert", json={"csr": csr_b64}, headers=headers)
        assert r.status_code == 200
        assert "certificate" in r.json()

    def test_sync_endpoint(self, sim_client):
        """Sync endpoint should accept incoming sync messages."""
        import time
        from eth_account import Account
        from eth_account.messages import encode_defunct
        from simulation import get_sim_private_key_hex

        nonce = sim_client.get("/nonce").json()["nonce"]
        ts = str(int(time.time()))
        recipient_wallet = DEFAULT_SIM_PEERS[0].tee_wallet
        sender_wallet = DEFAULT_SIM_PEERS[1].tee_wallet
        pk_hex = get_sim_private_key_hex(sender_wallet)
        assert pk_hex is not None
        msg = f"NovaKMS:Auth:{nonce}:{recipient_wallet}:{ts}"
        sig = Account.from_key(bytes.fromhex(pk_hex)).sign_message(encode_defunct(text=msg)).signature.hex()

        r = sim_client.post(
            "/sync",
            json={
                "type": "delta",
                "sender_wallet": sender_wallet,
                "data": {},
            },
            headers={
                "x-kms-signature": sig,
                "x-kms-timestamp": ts,
                "x-kms-nonce": nonce,
            },
        )
        assert r.status_code == 200
