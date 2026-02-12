"""
Tests for kdf.py — Key Derivation, Master Secret, Sealed Exchange.

Covers:
  - derive_app_key: determinism, isolation, context, length
  - derive_data_key
  - derive_sync_key
  - MasterSecretManager: lifecycle, derivation
  - seal_master_secret / unseal_master_secret: ECDH round-trip, wrong key
"""

import pytest
from unittest.mock import MagicMock
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kdf import (
    MasterSecretManager,
    derive_app_key,
    derive_data_key,
    derive_sync_key,
    seal_master_secret,
    unseal_master_secret,
)


# =============================================================================
# derive_app_key
# =============================================================================


class TestDeriveAppKey:
    def test_deterministic(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 42, "path_a")
        k2 = derive_app_key(secret, 42, "path_a")
        assert k1 == k2

    def test_different_path(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 42, "path_a")
        k2 = derive_app_key(secret, 42, "path_b")
        assert k1 != k2

    def test_different_app_id(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 1, "path")
        k2 = derive_app_key(secret, 2, "path")
        assert k1 != k2

    def test_different_secret(self):
        k1 = derive_app_key(b"a" * 32, 1, "path")
        k2 = derive_app_key(b"b" * 32, 1, "path")
        assert k1 != k2

    def test_custom_length(self):
        key = derive_app_key(b"x" * 32, 1, "p", length=64)
        assert len(key) == 64

    def test_context(self):
        k1 = derive_app_key(b"x" * 32, 1, "p", context="v1")
        k2 = derive_app_key(b"x" * 32, 1, "p", context="v2")
        assert k1 != k2

    def test_default_length_is_32(self):
        key = derive_app_key(b"a" * 32, 1, "p")
        assert len(key) == 32


# =============================================================================
# derive_data_key
# =============================================================================


class TestDeriveDataKey:
    def test_returns_32_bytes(self):
        key = derive_data_key(b"s" * 32, 100)
        assert len(key) == 32

    def test_different_app_ids(self):
        k1 = derive_data_key(b"s" * 32, 1)
        k2 = derive_data_key(b"s" * 32, 2)
        assert k1 != k2


# =============================================================================
# derive_sync_key
# =============================================================================


class TestDeriveSyncKey:
    def test_returns_32_bytes(self):
        key = derive_sync_key(b"s" * 32)
        assert len(key) == 32

    def test_deterministic(self):
        k1 = derive_sync_key(b"s" * 32)
        k2 = derive_sync_key(b"s" * 32)
        assert k1 == k2


# =============================================================================
# MasterSecretManager
# =============================================================================


class TestMasterSecretManager:
    def test_not_initialized(self):
        mgr = MasterSecretManager()
        assert not mgr.is_initialized
        with pytest.raises(RuntimeError):
            _ = mgr.secret

    def test_initialize_from_peer(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        assert mgr.is_initialized
        assert mgr.secret == b"\x01" * 32

    def test_reject_short_secret(self):
        mgr = MasterSecretManager()
        with pytest.raises(ValueError):
            mgr.initialize_from_peer(b"short")

    def test_truncates_long_secret(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xFF" * 64)
        assert len(mgr.secret) == 32

    def test_derive(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xab" * 32)
        key = mgr.derive(42, "test_path")
        assert len(key) == 32

    def test_epoch_starts_at_zero(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        assert mgr.epoch == 0

    def test_get_sync_key(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        sync_key = mgr.get_sync_key()
        assert len(sync_key) == 32

    def test_initialize_from_random(self):
        odyn = MagicMock()
        odyn.get_random_bytes.return_value = b"\xaa" * 32
        mgr = MasterSecretManager()
        mgr.initialize_from_random(odyn)
        assert mgr.is_initialized
        assert len(mgr.secret) == 32


# =============================================================================
# Sealed Key Exchange
# =============================================================================


class TestSealedKeyExchange:
    """Sealed key exchange now uses P-384 (secp384r1) to match teePubkey curve."""

    def test_seal_and_unseal(self):
        receiver_key = ec.generate_private_key(ec.SECP384R1())
        receiver_pub = receiver_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )

        secret = b"\xab" * 32

        sealed = seal_master_secret(secret, receiver_pub)
        assert "ephemeral_pubkey" in sealed
        assert "encrypted_data" in sealed
        assert "nonce" in sealed

        recovered_secret = unseal_master_secret(sealed, receiver_key)
        assert recovered_secret == secret

    def test_different_key_fails(self):
        receiver_key = ec.generate_private_key(ec.SECP384R1())
        wrong_key = ec.generate_private_key(ec.SECP384R1())
        receiver_pub = receiver_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )

        sealed = seal_master_secret(b"\xcc" * 32, receiver_pub)
        with pytest.raises(Exception):
            unseal_master_secret(sealed, wrong_key)

    def test_round_trip_multiple_secrets(self):
        """Multiple secrets survive the seal/unseal cycle."""
        for secret_byte in [b"\x00", b"\xdd", b"\xff"]:
            key = ec.generate_private_key(ec.SECP384R1())
            pub = key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            sealed = seal_master_secret(secret_byte * 32, pub)
            recovered = unseal_master_secret(sealed, key)
            assert recovered == secret_byte * 32

    def test_sec1_format_accepted(self):
        """Uncompressed SEC1 point format should also work for peer key."""
        key = ec.generate_private_key(ec.SECP384R1())
        pub = key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        sealed = seal_master_secret(b"\xee" * 32, pub)
        recovered = unseal_master_secret(sealed, key)
        assert recovered == b"\xee" * 32
