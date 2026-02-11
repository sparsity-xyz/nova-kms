"""
Tests for secure_channel.py — P-384 teePubkey validation, peer identity
verification, and ECDH session helpers.

Covers:
  - validate_tee_pubkey (DER/SPKI, SEC1 uncompressed, invalid inputs)
  - parse_tee_pubkey (parsing, error handling)
  - verify_peer_identity (ACTIVE instance, wallet match, P-384 teePubkey)
  - verify_peer_in_kms_operator_set (KMS_APP_ID + identity)
  - get_peer_tee_pubkey (retrieval + parsing)
  - generate_ecdh_keypair (P-384 ephemeral keys)
  - derive_ecdh_shared_key (symmetric derivation)
  - Independence of wallet (secp256k1) and teePubkey (P-384)
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import config
from secure_channel import (
    derive_ecdh_shared_key,
    generate_ecdh_keypair,
    get_peer_tee_pubkey,
    parse_tee_pubkey,
    validate_tee_pubkey,
    verify_peer_identity,
    verify_peer_in_kms_operator_set,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_p384_der() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate a P-384 keypair; return (private_key, public_key_der)."""
    key = ec.generate_private_key(ec.SECP384R1())
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, der


def _make_p384_sec1() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generate a P-384 keypair; return (private_key, uncompressed SEC1 point)."""
    key = ec.generate_private_key(ec.SECP384R1())
    sec1 = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return key, sec1


def _make_p256_der() -> bytes:
    """Generate a P-256 public key in DER format (wrong curve)."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@dataclass
class _FakeInstance:
    instance_id: int = 1
    app_id: int = 43
    version_id: int = 1
    tee_wallet_address: str = "0xABCD"
    instance_url: str = "http://localhost:5000"
    tee_pubkey: bytes = b""
    operator: str = "0xABCD"
    zk_verified: bool = True
    status: object = None
    registered_at: int = 0


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def _test_config(monkeypatch):
    monkeypatch.setattr(config, "IN_ENCLAVE", False)
    monkeypatch.setattr(config, "KMS_APP_ID", 43)


@pytest.fixture
def p384_der():
    """A valid P-384 public key in DER/SPKI format."""
    _, der = _make_p384_der()
    return der


@pytest.fixture
def p384_sec1():
    """A valid P-384 public key in uncompressed SEC1 point format."""
    _, sec1 = _make_p384_sec1()
    return sec1


@pytest.fixture
def nova_reg(p384_der):
    """A mock NovaRegistry returning a valid ACTIVE instance with P-384 teePubkey."""
    from nova_registry import InstanceStatus

    inst = _FakeInstance(
        instance_id=1,
        app_id=43,
        tee_wallet_address="0xPeerWallet",
        tee_pubkey=p384_der,
        status=InstanceStatus.ACTIVE,
    )

    reg = MagicMock()
    reg.get_instance_by_wallet.return_value = inst
    return reg


# =============================================================================
# validate_tee_pubkey
# =============================================================================


class TestValidateTeePubkey:
    def test_valid_der(self, p384_der):
        assert validate_tee_pubkey(p384_der) is True

    def test_valid_sec1(self, p384_sec1):
        assert validate_tee_pubkey(p384_sec1) is True

    def test_empty_bytes(self):
        assert validate_tee_pubkey(b"") is False

    def test_none(self):
        assert validate_tee_pubkey(None) is False

    def test_too_short(self):
        assert validate_tee_pubkey(b"\x04" + b"\x00" * 10) is False

    def test_random_garbage(self):
        import os
        assert validate_tee_pubkey(os.urandom(97)) is False

    def test_p256_der_rejected(self):
        """P-256 key should be rejected (wrong curve)."""
        p256_der = _make_p256_der()
        assert validate_tee_pubkey(p256_der) is False

    def test_secp256k1_pubkey_rejected(self):
        """secp256k1 uncompressed key (65 bytes) must be rejected — wrong length for P-384."""
        fake_secp256k1 = b"\x04" + b"\xAA" * 64  # 65 bytes (secp256k1 format)
        assert validate_tee_pubkey(fake_secp256k1) is False


# =============================================================================
# parse_tee_pubkey
# =============================================================================


class TestParseTeePubkey:
    def test_parse_der(self, p384_der):
        key = parse_tee_pubkey(p384_der)
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert isinstance(key.curve, ec.SECP384R1)

    def test_parse_sec1(self, p384_sec1):
        key = parse_tee_pubkey(p384_sec1)
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert isinstance(key.curve, ec.SECP384R1)

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="Empty"):
            parse_tee_pubkey(b"")

    def test_wrong_curve_raises(self):
        p256_der = _make_p256_der()
        with pytest.raises(ValueError, match="P-384"):
            parse_tee_pubkey(p256_der)

    def test_garbage_raises(self):
        with pytest.raises(ValueError):
            parse_tee_pubkey(b"\x30" + b"\x00" * 50)  # looks like DER but isn't

    def test_wrong_length_sec1_raises(self):
        """SEC1 point must be exactly 97 bytes for P-384."""
        with pytest.raises(ValueError):
            parse_tee_pubkey(b"\x04" + b"\x00" * 50)  # 51 bytes, not 97


# =============================================================================
# verify_peer_identity
# =============================================================================


class TestVerifyPeerIdentity:
    def test_valid_peer(self, nova_reg):
        assert verify_peer_identity("0xPeerWallet", nova_reg) is True

    def test_empty_wallet(self, nova_reg):
        assert verify_peer_identity("", nova_reg) is False

    def test_none_registry(self):
        assert verify_peer_identity("0xABC", None) is False

    def test_instance_not_found(self, nova_reg):
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=0, status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xUnknown", nova_reg) is False

    def test_instance_not_active(self, nova_reg, p384_der):
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xPeerWallet",
            tee_pubkey=p384_der,
            status=InstanceStatus.STOPPED,
        )
        assert verify_peer_identity("0xPeerWallet", nova_reg) is False

    def test_wallet_mismatch(self, nova_reg, p384_der):
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xOtherWallet",
            tee_pubkey=p384_der,
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xPeerWallet", nova_reg) is False

    def test_missing_tee_pubkey(self, nova_reg):
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xPeerWallet",
            tee_pubkey=b"",
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xPeerWallet", nova_reg) is False

    def test_invalid_tee_pubkey(self, nova_reg):
        """Non-P-384 teePubkey must fail validation."""
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xPeerWallet",
            tee_pubkey=b"\x04" + b"\xCC" * 64,  # 65 bytes = secp256k1 size, not P-384
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xPeerWallet", nova_reg) is False

    def test_p256_tee_pubkey_rejected(self, nova_reg):
        """P-256 key in teePubkey field must be rejected (wrong curve)."""
        from nova_registry import InstanceStatus
        p256_der = _make_p256_der()
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xPeerWallet",
            tee_pubkey=p256_der,
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xPeerWallet", nova_reg) is False

    def test_require_zk_verified_true(self, nova_reg):
        assert verify_peer_identity("0xPeerWallet", nova_reg, require_zk_verified=True) is True

    def test_require_zk_verified_false(self, nova_reg, p384_der):
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xPeerWallet",
            tee_pubkey=p384_der,
            zk_verified=False,
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity(
            "0xPeerWallet", nova_reg, require_zk_verified=True
        ) is False

    def test_registry_exception(self, nova_reg):
        nova_reg.get_instance_by_wallet.side_effect = RuntimeError("chain error")
        assert verify_peer_identity("0xPeerWallet", nova_reg) is False

    def test_case_insensitive_wallet_match(self, nova_reg, p384_der):
        """Wallet comparison should be case-insensitive."""
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xpeerwallet",
            tee_pubkey=p384_der,
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xPEERWALLET", nova_reg) is True


# =============================================================================
# verify_peer_in_kms_operator_set
# =============================================================================


class TestVerifyPeerInKmsOperatorSet:
    def test_valid_kms_peer(self, nova_reg):
        assert verify_peer_in_kms_operator_set("0xPeerWallet", nova_reg) is True

    def test_empty_wallet(self, nova_reg):
        assert verify_peer_in_kms_operator_set("", nova_reg) is False

    def test_wrong_app_id(self, nova_reg, p384_der):
        """Instance with wrong app_id should be rejected."""
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            app_id=999,
            tee_wallet_address="0xPeerWallet",
            tee_pubkey=p384_der,
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_in_kms_operator_set("0xPeerWallet", nova_reg) is False

    def test_not_active(self, nova_reg, p384_der):
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            app_id=43,
            tee_wallet_address="0xPeerWallet",
            tee_pubkey=p384_der,
            status=InstanceStatus.STOPPED,
        )
        assert verify_peer_in_kms_operator_set("0xPeerWallet", nova_reg) is False

    def test_instance_not_found(self, nova_reg):
        from nova_registry import InstanceStatus
        nova_reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=0,
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_in_kms_operator_set("0xPeerWallet", nova_reg) is False


# =============================================================================
# get_peer_tee_pubkey
# =============================================================================


class TestGetPeerTeePubkey:
    def test_returns_parsed_key(self, nova_reg):
        key = get_peer_tee_pubkey("0xPeerWallet", nova_reg)
        assert key is not None
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert isinstance(key.curve, ec.SECP384R1)

    def test_returns_none_for_missing(self):
        reg = MagicMock()
        reg.get_instance_by_wallet.side_effect = ValueError("not found")
        assert get_peer_tee_pubkey("0xNoOne", reg) is None

    def test_returns_none_for_invalid_pubkey(self):
        from nova_registry import InstanceStatus
        inst = _FakeInstance(
            tee_pubkey=b"\x04" + b"\x00" * 10,
            status=InstanceStatus.ACTIVE,
        )
        reg = MagicMock()
        reg.get_instance_by_wallet.return_value = inst
        assert get_peer_tee_pubkey("0xABCD", reg) is None


# =============================================================================
# generate_ecdh_keypair
# =============================================================================


class TestGenerateEcdhKeypair:
    def test_returns_p384_key_and_der(self):
        priv, der = generate_ecdh_keypair()
        assert isinstance(priv, ec.EllipticCurvePrivateKey)
        assert isinstance(priv.curve, ec.SECP384R1)
        # DER should be parseable back
        pub = serialization.load_der_public_key(der)
        assert isinstance(pub, ec.EllipticCurvePublicKey)
        assert isinstance(pub.curve, ec.SECP384R1)

    def test_unique_keys(self):
        _, der1 = generate_ecdh_keypair()
        _, der2 = generate_ecdh_keypair()
        assert der1 != der2


# =============================================================================
# derive_ecdh_shared_key
# =============================================================================


class TestDeriveEcdhSharedKey:
    def test_shared_key_symmetry(self):
        """ECDH shared key must be the same from both sides."""
        key_a = ec.generate_private_key(ec.SECP384R1())
        key_b = ec.generate_private_key(ec.SECP384R1())

        pub_a_der = key_a.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_b_der = key_b.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        shared_ab = derive_ecdh_shared_key(key_a, pub_b_der)
        shared_ba = derive_ecdh_shared_key(key_b, pub_a_der)
        assert shared_ab == shared_ba

    def test_shared_key_length(self):
        """P-384 ECDH shared secret is 48 bytes."""
        key_a = ec.generate_private_key(ec.SECP384R1())
        key_b = ec.generate_private_key(ec.SECP384R1())
        pub_b_der = key_b.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        shared = derive_ecdh_shared_key(key_a, pub_b_der)
        assert len(shared) == 48

    def test_sec1_format_accepted(self):
        """SEC1 uncompressed point should also work."""
        key_a = ec.generate_private_key(ec.SECP384R1())
        key_b = ec.generate_private_key(ec.SECP384R1())
        pub_b_sec1 = key_b.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        shared = derive_ecdh_shared_key(key_a, pub_b_sec1)
        assert len(shared) == 48

    def test_different_keys_different_secret(self):
        key_a = ec.generate_private_key(ec.SECP384R1())
        key_b = ec.generate_private_key(ec.SECP384R1())
        key_c = ec.generate_private_key(ec.SECP384R1())
        pub_b_der = key_b.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_c_der = key_c.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        shared_ab = derive_ecdh_shared_key(key_a, pub_b_der)
        shared_ac = derive_ecdh_shared_key(key_a, pub_c_der)
        assert shared_ab != shared_ac

    def test_p256_key_rejected(self):
        """P-256 peer key must be rejected."""
        key_a = ec.generate_private_key(ec.SECP384R1())
        p256_der = _make_p256_der()
        with pytest.raises(ValueError, match="P-384"):
            derive_ecdh_shared_key(key_a, p256_der)


# =============================================================================
# Independence of wallet and teePubkey
# =============================================================================


class TestKeyIndependence:
    """Verify that wallet (secp256k1) and teePubkey (P-384) are independent."""

    def test_different_curves(self, p384_der):
        """teePubkey is P-384, wallet comes from secp256k1 — different curves."""
        key = parse_tee_pubkey(p384_der)
        assert isinstance(key.curve, ec.SECP384R1)
        # A secp256k1 key is 32 bytes private / 65 bytes uncompressed public
        # P-384 DER is typically ~120 bytes — they're clearly different
        assert len(p384_der) > 65

    def test_no_wallet_derivation_from_teepubkey(self, p384_der):
        """There is no wallet_from_pubkey function — this is intentional.

        The old code incorrectly derived a wallet address from teePubkey
        using keccak. Since teePubkey is P-384 (not secp256k1), this was
        cryptographically incorrect. This test ensures the function no
        longer exists.
        """
        import secure_channel
        assert not hasattr(secure_channel, "wallet_from_pubkey")

    def test_both_keys_needed_for_verification(self, p384_der):
        """verify_peer_identity needs BOTH a matching wallet AND valid P-384 teePubkey."""
        from nova_registry import InstanceStatus

        # Instance with matching wallet but no teePubkey → should fail
        reg = MagicMock()
        reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xWallet",
            tee_pubkey=b"",
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xWallet", reg) is False

        # Instance with valid teePubkey but wrong wallet → should fail
        reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xDifferentWallet",
            tee_pubkey=p384_der,
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xWallet", reg) is False

        # Instance with both correct → should pass
        reg.get_instance_by_wallet.return_value = _FakeInstance(
            instance_id=1,
            tee_wallet_address="0xWallet",
            tee_pubkey=p384_der,
            status=InstanceStatus.ACTIVE,
        )
        assert verify_peer_identity("0xWallet", reg) is True


# =============================================================================
# Integration: seal/unseal with P-384 ECDH
# =============================================================================


class TestSealUnsealWithP384:
    """End-to-end test that seal_master_secret / unseal_master_secret
    work with P-384 keys (the same curve as teePubkey)."""

    def test_seal_unseal_roundtrip(self):
        from kdf import seal_master_secret, unseal_master_secret

        # Receiver generates P-384 ephemeral key
        receiver_key = ec.generate_private_key(ec.SECP384R1())
        receiver_pub_der = receiver_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        secret = b"\xAB" * 32

        sealed = seal_master_secret(secret, receiver_pub_der)
        assert "ephemeral_pubkey" in sealed
        assert "ciphertext" in sealed
        assert "nonce" in sealed

        recovered = unseal_master_secret(sealed, receiver_key)
        assert recovered == secret

    def test_seal_unseal_sec1_roundtrip(self):
        """Receiver provides SEC1 uncompressed point instead of DER."""
        from kdf import seal_master_secret, unseal_master_secret

        receiver_key = ec.generate_private_key(ec.SECP384R1())
        receiver_pub_sec1 = receiver_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        secret = b"\xDD" * 32

        sealed = seal_master_secret(secret, receiver_pub_sec1)
        recovered = unseal_master_secret(sealed, receiver_key)
        assert recovered == secret

    def test_wrong_key_fails(self):
        from kdf import seal_master_secret, unseal_master_secret

        receiver_key = ec.generate_private_key(ec.SECP384R1())
        wrong_key = ec.generate_private_key(ec.SECP384R1())
        receiver_pub_der = receiver_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        sealed = seal_master_secret(b"\xCC" * 32, receiver_pub_der)
        with pytest.raises(Exception):
            unseal_master_secret(sealed, wrong_key)

    def test_p256_key_rejected(self):
        """P-256 receiver key must be rejected by seal_master_secret."""
        from kdf import seal_master_secret

        p256_der = _make_p256_der()
        with pytest.raises(ValueError, match="P-384"):
            seal_master_secret(b"\xEE" * 32, p256_der)
