"""
Tests for security hardening features.

Covers:
  - URL validator (SSRF protection)
  - Rate limiter (token bucket)
  - Data store eviction bug fix
  - Data store clock skew rejection
  - KDF epoch rotation and sealed key exchange
  - CA key derivation fix (scalar in valid range)
  - Auth measurement enforcement in production mode
  - Sync manager HMAC signing
  - Simulation mode safety guard
  - CachedNovaRegistry TTL cache
"""

import hashlib
import hmac
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest


# =============================================================================
# URL Validator
# =============================================================================


class TestURLValidator:
    def test_valid_https_url(self):
        from url_validator import validate_peer_url
        result = validate_peer_url("https://peer.example.com:8443/sync", allow_private_ips=True)
        assert result == "https://peer.example.com:8443/sync"

    def test_valid_http_dev_mode(self):
        from url_validator import validate_peer_url
        result = validate_peer_url(
            "http://localhost:8000",
            allowed_schemes=["http", "https"],
            allow_private_ips=True,
        )
        assert result == "http://localhost:8000"

    def test_rejects_ftp_scheme(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="scheme"):
            validate_peer_url("ftp://evil.com/data", allowed_schemes=["https"])

    def test_rejects_empty_url(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="Empty"):
            validate_peer_url("")

    def test_rejects_no_hostname(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="hostname"):
            validate_peer_url("https://", allowed_schemes=["https"], allow_private_ips=True)

    def test_rejects_private_ip_in_production(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="blocked range"):
            validate_peer_url(
                "https://10.0.0.1:8443",
                allowed_schemes=["https"],
                allow_private_ips=False,
            )

    def test_rejects_loopback_ip_in_production(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="blocked range"):
            validate_peer_url(
                "https://127.0.0.1:8000",
                allowed_schemes=["https"],
                allow_private_ips=False,
            )

    def test_rejects_credentials_in_url(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="credentials"):
            validate_peer_url(
                "https://user:pass@peer.example.com",
                allow_private_ips=True,
            )

    def test_rejects_blocked_port(self):
        from url_validator import URLValidationError, validate_peer_url
        with pytest.raises(URLValidationError, match="Port"):
            validate_peer_url("https://peer.example.com:6379", allow_private_ips=True)

    def test_allows_private_ip_in_dev(self):
        from url_validator import validate_peer_url
        result = validate_peer_url(
            "http://192.168.1.5:8000",
            allowed_schemes=["http", "https"],
            allow_private_ips=True,
        )
        assert "192.168.1.5" in result


# =============================================================================
# Rate Limiter
# =============================================================================


class TestTokenBucket:
    def test_allows_initial_requests(self):
        from rate_limiter import TokenBucket
        bucket = TokenBucket(rate_per_minute=10)
        assert bucket.allow("client1") is True
        assert bucket.allow("client1") is True

    def test_rejects_after_exhaustion(self):
        from rate_limiter import TokenBucket
        bucket = TokenBucket(rate_per_minute=3)
        for _ in range(3):
            assert bucket.allow("client1") is True
        # Next request should be rejected (no time to refill)
        assert bucket.allow("client1") is False

    def test_separate_keys(self):
        from rate_limiter import TokenBucket
        bucket = TokenBucket(rate_per_minute=2)
        bucket.allow("a")
        bucket.allow("a")
        assert bucket.allow("a") is False
        assert bucket.allow("b") is True  # different key

    def test_zero_rate_allows_all(self):
        from rate_limiter import TokenBucket
        bucket = TokenBucket(rate_per_minute=0)
        assert bucket.allow("x") is True

    def test_cleanup_stale(self):
        from rate_limiter import TokenBucket
        bucket = TokenBucket(rate_per_minute=100)
        bucket.allow("old_client")
        # Simulate aging
        with bucket._lock:
            bucket._buckets["old_client"] = (0, time.monotonic() - 600)
        bucket.cleanup(max_age=300)
        assert "old_client" not in bucket._buckets


# =============================================================================
# Data Store: Eviction Fix
# =============================================================================


class TestEvictionFix:
    def test_eviction_decrements_total_bytes(self):
        """
        Regression test: _evict_lru must properly decrement _total_bytes.
        Previously it set value=None then called value_size() → 0.
        """
        from data_store import DataStore
        import config

        ds = DataStore(node_id="node1")
        ns = ds._ns(1)

        # Fill namespace with 3 records
        ds.put(1, "a", b"x" * 100)
        ds.put(1, "b", b"y" * 200)
        ds.put(1, "c", b"z" * 300)

        assert ns._total_bytes == 600

        # Trigger eviction for 250 bytes
        with ns._lock:
            ns._evict_lru(250)

        # After eviction, total_bytes should have decreased
        assert ns._total_bytes < 600
        # At least 250 bytes should have been freed
        assert ns._total_bytes <= 350


# =============================================================================
# Data Store: Clock Skew Rejection
# =============================================================================


class TestClockSkewProtection:
    def test_rejects_far_future_timestamp(self):
        """Records with timestamps far in the future should be rejected."""
        from data_store import DataStore, DataRecord, VectorClock

        ds = DataStore(node_id="node1")
        far_future = int(time.time() * 1000) + 120_000  # 2 minutes ahead

        incoming = DataRecord(
            key="key1",
            value=b"data",
            version=VectorClock({"node2": 1}),
            updated_at_ms=far_future,
            tombstone=False,
        )
        merged = ds.merge_record(1, incoming)
        assert merged is False

    def test_rejects_far_past_timestamp(self):
        """Records with timestamps far in the past should be rejected."""
        from data_store import DataStore, DataRecord, VectorClock

        ds = DataStore(node_id="node1")
        far_past = int(time.time() * 1000) - 120_000  # 2 minutes ago

        incoming = DataRecord(
            key="key2",
            value=b"old_data",
            version=VectorClock({"node2": 1}),
            updated_at_ms=far_past,
            tombstone=False,
        )
        merged = ds.merge_record(1, incoming)
        assert merged is False

    def test_accepts_within_skew_threshold(self):
        """Records within the skew threshold should be accepted."""
        from data_store import DataStore, DataRecord, VectorClock

        ds = DataStore(node_id="node1")
        within_range = int(time.time() * 1000) + 5_000  # 5 seconds ahead

        incoming = DataRecord(
            key="key3",
            value=b"ok_data",
            version=VectorClock({"node2": 1}),
            updated_at_ms=within_range,
            tombstone=False,
        )
        merged = ds.merge_record(1, incoming)
        assert merged is True
        assert ds.get(1, "key3").value == b"ok_data"


# =============================================================================
# KDF: Epoch Rotation
# =============================================================================


class TestEpochRotation:
    def test_different_epochs_produce_different_keys(self):
        from kdf import derive_app_key
        secret = b"a" * 32
        k0 = derive_app_key(secret, 42, "path", epoch=0)
        k1 = derive_app_key(secret, 42, "path", epoch=1)
        assert k0 != k1

    def test_manager_epoch_starts_at_zero(self):
        from kdf import MasterSecretManager
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        assert mgr.epoch == 0

    def test_manager_rotate_increments_epoch(self):
        from kdf import MasterSecretManager
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        new_epoch = mgr.rotate()
        assert new_epoch == 1
        assert mgr.epoch == 1

    def test_manager_derive_uses_current_epoch(self):
        from kdf import MasterSecretManager
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        k0 = mgr.derive(42, "test")
        mgr.rotate()
        k1 = mgr.derive(42, "test")
        assert k0 != k1

    def test_sync_key_derivation(self):
        from kdf import MasterSecretManager
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        sync_key = mgr.get_sync_key()
        assert len(sync_key) == 32

    def test_rotate_without_init_raises(self):
        from kdf import MasterSecretManager
        mgr = MasterSecretManager()
        with pytest.raises(RuntimeError, match="not initialized"):
            mgr.rotate()


# =============================================================================
# KDF: Sealed Key Exchange
# =============================================================================


class TestSealedKeyExchange:
    def test_seal_and_unseal(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from kdf import seal_master_secret, unseal_master_secret

        # Generate receiver keypair
        receiver_key = ec.generate_private_key(ec.SECP256R1())
        receiver_pub = receiver_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        secret = b"\xab" * 32
        epoch = 7

        sealed = seal_master_secret(secret, epoch, receiver_pub)
        assert "ephemeral_pubkey" in sealed
        assert "ciphertext" in sealed
        assert "nonce" in sealed

        recovered_secret, recovered_epoch = unseal_master_secret(sealed, receiver_key)
        assert recovered_secret == secret
        assert recovered_epoch == epoch

    def test_different_key_fails(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from kdf import seal_master_secret, unseal_master_secret

        receiver_key = ec.generate_private_key(ec.SECP256R1())
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        receiver_pub = receiver_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        sealed = seal_master_secret(b"\xcc" * 32, 0, receiver_pub)

        with pytest.raises(Exception):
            unseal_master_secret(sealed, wrong_key)


# =============================================================================
# KDF: CA Key Derivation Fix
# =============================================================================


class TestCAKeyDerivation:
    def test_ca_key_scalar_valid_range(self):
        """CA key derivation must produce a scalar in [1, n-1]."""
        from kdf import CertificateAuthority, MasterSecretManager, _SECP256R1_ORDER

        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xff" * 32)
        ca = CertificateAuthority(mgr)
        ca._ensure_ca()

        # The private key must be valid (no crash)
        assert ca._ca_key is not None
        # Get the private number
        private_num = ca._ca_key.private_numbers().private_value
        assert 1 <= private_num < _SECP256R1_ORDER

    def test_deterministic_across_instances(self):
        """Same secret → same CA public key across instances."""
        from kdf import CertificateAuthority, MasterSecretManager
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        secret = b"\xab" * 32
        ca1 = CertificateAuthority(MasterSecretManager())
        ca1._mgr.initialize_from_peer(secret)
        ca2 = CertificateAuthority(MasterSecretManager())
        ca2._mgr.initialize_from_peer(secret)

        cert1 = load_pem_x509_certificate(ca1.get_ca_cert_pem())
        cert2 = load_pem_x509_certificate(ca2.get_ca_cert_pem())
        pub1 = cert1.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        pub2 = cert2.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        assert pub1 == pub2


# =============================================================================
# Auth: Measurement Enforcement
# =============================================================================


class TestMeasurementEnforcement:
    def test_measurement_required_in_production(self):
        """When REQUIRE_MEASUREMENT=True, missing measurement → rejected."""
        from auth import AppAuthorizer, ClientAttestation
        from nova_registry import (
            App, AppStatus, AppVersion, InstanceStatus, RuntimeInstance, VersionStatus,
        )
        from unittest.mock import MagicMock

        instance = RuntimeInstance(1, 100, 1, "0x00", "url", b"", "0xAA", True, InstanceStatus.ACTIVE, 0)
        app_obj = App(100, "0x00", b"\x00" * 32, "0x00", "", 1, 0, AppStatus.ACTIVE)
        version = AppVersion(1, "v1", b"\xab" * 32, "", "", "", "", VersionStatus.ENROLLED, 0, "0x00")

        reg = MagicMock()
        reg.get_instance_by_wallet.return_value = instance
        reg.get_app.return_value = app_obj
        reg.get_version.return_value = version

        auth = AppAuthorizer(registry=reg)

        with patch("config.REQUIRE_MEASUREMENT", True):
            result = auth.verify(ClientAttestation(tee_wallet="0xAA", measurement=None))
            assert not result.authorized
            assert "required" in result.reason.lower()

    def test_measurement_optional_in_dev(self):
        """When REQUIRE_MEASUREMENT=False, missing measurement → allowed."""
        from auth import AppAuthorizer, ClientAttestation
        from nova_registry import (
            App, AppStatus, AppVersion, InstanceStatus, RuntimeInstance, VersionStatus,
        )
        from unittest.mock import MagicMock

        instance = RuntimeInstance(1, 100, 1, "0x00", "url", b"", "0xAA", True, InstanceStatus.ACTIVE, 0)
        app_obj = App(100, "0x00", b"\x00" * 32, "0x00", "", 1, 0, AppStatus.ACTIVE)
        version = AppVersion(1, "v1", b"\xab" * 32, "", "", "", "", VersionStatus.ENROLLED, 0, "0x00")

        reg = MagicMock()
        reg.get_instance_by_wallet.return_value = instance
        reg.get_app.return_value = app_obj
        reg.get_version.return_value = version

        auth = AppAuthorizer(registry=reg)

        with patch("config.REQUIRE_MEASUREMENT", False):
            result = auth.verify(ClientAttestation(tee_wallet="0xAA", measurement=None))
            assert result.authorized


class TestAttestationModes:
    def test_headers_disabled_in_production(self):
        """attestation_from_headers must raise when IN_ENCLAVE=True."""
        from auth import attestation_from_headers
        with patch("auth.config.IN_ENCLAVE", True), patch("auth.config.SIMULATION_MODE", False):
            with pytest.raises(RuntimeError, match="disabled in production"):
                attestation_from_headers({"x-tee-wallet": "0xAA"})

    def test_headers_work_in_dev(self):
        """attestation_from_headers works when IN_ENCLAVE=False."""
        from auth import attestation_from_headers
        with patch("auth.config.IN_ENCLAVE", False):
            att = attestation_from_headers({"x-tee-wallet": "0xBB"})
            assert att.tee_wallet == "0xBB"


# =============================================================================
# Sync Manager: HMAC Signing
# =============================================================================


class TestSyncHMAC:
    def test_compute_verify_hmac(self):
        from sync_manager import _compute_hmac, _verify_hmac
        key = b"\x01" * 32
        payload = b'{"type":"delta"}'
        sig = _compute_hmac(key, payload)
        assert _verify_hmac(key, payload, sig) is True

    def test_wrong_key_fails(self):
        from sync_manager import _compute_hmac, _verify_hmac
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        payload = b'{"type":"delta"}'
        sig = _compute_hmac(key1, payload)
        assert _verify_hmac(key2, payload, sig) is False

    def test_handle_sync_rejects_bad_signature(self):
        from data_store import DataStore
        from sync_manager import PeerCache, SyncManager
        from auth import issue_nonce

        import base64
        import time
        from eth_account import Account
        from eth_account.messages import encode_defunct
        from unittest.mock import MagicMock

        ds = DataStore(node_id="node1")
        kms_reg = MagicMock()
        kms_reg.is_operator.return_value = True
        mgr = SyncManager(ds, "0xNode1", PeerCache(kms_registry_client=kms_reg))
        mgr.set_sync_key(b"\xab" * 32)

        nonce_b64 = base64.b64encode(issue_nonce()).decode()
        ts = str(int(time.time()))
        msg = f"NovaKMS:Auth:{nonce_b64}:{mgr.node_wallet}:{ts}"
        sig = Account.from_key(bytes.fromhex("33" * 32)).sign_message(encode_defunct(text=msg)).signature.hex()
        kms_pop = {"signature": sig, "timestamp": ts, "nonce": nonce_b64}

        result = mgr.handle_incoming_sync(
            {"type": "delta", "data": {}},
            signature="badsignature",
            kms_pop=kms_pop,
        )
        assert result["status"] == "error"
        assert "signature" in result["reason"].lower()


# =============================================================================
# Simulation Mode: Safety Guard
# =============================================================================


class TestSimulationSafety:
    def test_sim_mode_blocked_in_enclave(self):
        """is_simulation_mode must return False when IN_ENCLAVE=True."""
        import config
        with patch.dict(os.environ, {"SIMULATION_MODE": "1"}):
            original = config.IN_ENCLAVE
            try:
                config.IN_ENCLAVE = True
                from simulation import is_simulation_mode
                assert is_simulation_mode() is False
            finally:
                config.IN_ENCLAVE = original

    def test_sim_mode_works_outside_enclave(self):
        """is_simulation_mode returns True when IN_ENCLAVE=False."""
        import config
        with patch.dict(os.environ, {"SIMULATION_MODE": "1"}):
            original = config.IN_ENCLAVE
            try:
                config.IN_ENCLAVE = False
                from simulation import is_simulation_mode
                assert is_simulation_mode() is True
            finally:
                config.IN_ENCLAVE = original


# =============================================================================
# CachedNovaRegistry
# =============================================================================


class TestCachedNovaRegistry:
    def test_caches_app_result(self):
        from nova_registry import App, AppStatus, CachedNovaRegistry

        mock_inner = MagicMock()
        app_obj = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.return_value = app_obj

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)

        # First call hits inner
        result1 = cached.get_app(1)
        assert result1.app_id == 1
        assert mock_inner.get_app.call_count == 1

        # Second call uses cache
        result2 = cached.get_app(1)
        assert result2.app_id == 1
        assert mock_inner.get_app.call_count == 1  # still 1

    def test_cache_expires(self):
        from nova_registry import App, AppStatus, CachedNovaRegistry

        mock_inner = MagicMock()
        app_obj = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.return_value = app_obj

        cached = CachedNovaRegistry(inner=mock_inner, ttl=0)  # TTL=0 → always expired

        cached.get_app(1)
        cached.get_app(1)
        assert mock_inner.get_app.call_count == 2  # cache miss both times

    def test_invalidate_all(self):
        from nova_registry import App, AppStatus, CachedNovaRegistry

        mock_inner = MagicMock()
        app_obj = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.return_value = app_obj

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_app(1)
        assert mock_inner.get_app.call_count == 1

        cached.invalidate()
        cached.get_app(1)
        assert mock_inner.get_app.call_count == 2

    def test_invalidate_specific_key(self):
        from nova_registry import App, AppStatus, CachedNovaRegistry

        mock_inner = MagicMock()
        app_obj = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.return_value = app_obj

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_app(1)
        cached.invalidate("app:1")
        cached.get_app(1)
        assert mock_inner.get_app.call_count == 2

    def test_caches_instance_by_wallet(self):
        from nova_registry import CachedNovaRegistry, InstanceStatus, RuntimeInstance

        mock_inner = MagicMock()
        inst = RuntimeInstance(1, 1, 1, "0x00", "url", b"", "0xAA", True, InstanceStatus.ACTIVE, 0)
        mock_inner.get_instance_by_wallet.return_value = inst

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_instance_by_wallet("0xAA")
        cached.get_instance_by_wallet("0xAA")
        assert mock_inner.get_instance_by_wallet.call_count == 1


# =============================================================================
# Chain: Finality
# =============================================================================


class TestChainFinality:
    def test_eth_call_finalized_exists(self):
        """Chain class should have eth_call_finalized method."""
        from chain import Chain
        chain = Chain.__new__(Chain)
        assert hasattr(chain, "eth_call_finalized")
