"""
=============================================================================
Secure Channel (secure_channel.py)
=============================================================================

Provides teePubkey-based identity verification and ECDH encryption helpers
for enclave-to-enclave communication.  Addresses audit finding H1 (Missing
Enclave-to-Enclave TLS with teePubkey Verification).

Key Architecture
----------------
Every Nova Platform enclave has **two independent keypairs**:

1. **ETH wallet** (secp256k1): ``tee_wallet_address`` + private key.
   Used for PoP message signing (EIP-191 via Odyn ``/v1/eth/sign``).

2. **teePubkey** (NIST P-384 / secp384r1): DER-encoded SPKI public key.
   Used for ECDH-based encryption (via Odyn ``/v1/encryption/*``).

These keypairs live on *different curves* and are *completely independent*.
The wallet address is **not** derived from teePubkey and vice-versa.

This module:
  1. Validates that a peer's ``teePubkey`` (registered on-chain in
     NovaAppRegistry) is a well-formed P-384 public key.
  2. Verifies that the peer's wallet address matches the on-chain
     ``tee_wallet_address`` and the instance is ACTIVE.
  3. Provides ECDH helpers using P-384 keys for session encryption.

Usage: before accepting sync requests or establishing outbound connections,
call ``verify_peer_identity(wallet, registry)`` to confirm the peer's
on-chain registration is valid.
"""

from __future__ import annotations

import logging
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("nova-kms.secure_channel")


# =============================================================================
# P-384 teePubkey Helpers
# =============================================================================


def validate_tee_pubkey(pubkey_bytes: bytes) -> bool:
    """
    Validate that *pubkey_bytes* is a well-formed P-384 (secp384r1) public key.

    Accepts DER/SPKI encoding or uncompressed SEC1 point format (0x04 || x || y,
    97 bytes for P-384).

    Returns True if the key can be parsed successfully.
    """
    if not pubkey_bytes or len(pubkey_bytes) < 48:
        return False
    try:
        parse_tee_pubkey(pubkey_bytes)
        return True
    except Exception:
        return False


def parse_tee_pubkey(pubkey_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """
    Parse *pubkey_bytes* into a ``cryptography`` P-384 public key object.

    Supports:
      - DER / SubjectPublicKeyInfo (SPKI) format (starts with 0x30 …)
      - Uncompressed SEC1 point format (0x04 || x || y, 97 bytes)

    Raises ``ValueError`` if the bytes cannot be parsed as a P-384 key.
    """
    if not pubkey_bytes:
        raise ValueError("Empty teePubkey")

    # Try DER/SPKI first (typical format from Odyn /v1/encryption/public_key)
    if pubkey_bytes[0] == 0x30:
        try:
            key = serialization.load_der_public_key(pubkey_bytes)
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ValueError("DER key is not an EC key")
            if not isinstance(key.curve, ec.SECP384R1):
                raise ValueError(
                    f"Expected P-384, got {key.curve.name}"
                )
            return key
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"Failed to parse DER teePubkey: {exc}") from exc

    # Try uncompressed SEC1 point (97 bytes for P-384: 0x04 + 48 + 48)
    if pubkey_bytes[0] == 0x04 and len(pubkey_bytes) == 97:
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP384R1(), pubkey_bytes
            )
        except Exception as exc:
            raise ValueError(f"Failed to parse SEC1 P-384 point: {exc}") from exc

    raise ValueError(
        f"Unrecognised teePubkey format (length={len(pubkey_bytes)}, "
        f"first_byte=0x{pubkey_bytes[0]:02x})"
    )


# =============================================================================
# Identity Verification
# =============================================================================


def verify_peer_identity(
    peer_wallet: str,
    nova_registry,
    *,
    require_zk_verified: bool = False,
) -> bool:
    """
    Verify that ``peer_wallet`` is backed by a valid on-chain registration
    in the NovaAppRegistry with a well-formed P-384 teePubkey.

    Steps
    -----
    1. ``getInstanceByWallet(peer_wallet)`` → RuntimeInstance
    2. Instance must be ACTIVE.
    3. ``tee_wallet_address`` must match ``peer_wallet``.
    4. ``teePubkey`` must be non-empty and a valid P-384 public key.
    5. (Optional) ``zk_verified`` must be True.

    Note: ``teePubkey`` (P-384) and ``tee_wallet_address`` (secp256k1)
    are **independent** keypairs.  We do NOT derive a wallet from
    teePubkey — they live on different elliptic curves.

    Returns True if all checks pass.
    """
    from nova_registry import InstanceStatus

    if not peer_wallet or not nova_registry:
        return False

    try:
        instance = nova_registry.get_instance_by_wallet(peer_wallet)
    except Exception as exc:
        logger.warning(f"Peer verification failed for {peer_wallet}: instance lookup error: {exc}")
        return False

    if getattr(instance, "instance_id", 0) == 0:
        logger.warning(f"Peer verification failed for {peer_wallet}: instance not found")
        return False

    if getattr(instance, "status", None) != InstanceStatus.ACTIVE:
        logger.warning(f"Peer verification failed for {peer_wallet}: instance not ACTIVE")
        return False

    # Wallet binding: peer_wallet must match the registered tee_wallet_address
    registered_wallet = (getattr(instance, "tee_wallet_address", "") or "").lower()
    if not registered_wallet or peer_wallet.lower() != registered_wallet:
        logger.warning(
            f"Peer verification failed: peer wallet {peer_wallet} != "
            f"registered wallet {registered_wallet}"
        )
        return False

    # teePubkey must be present and parseable as P-384
    tee_pubkey = getattr(instance, "tee_pubkey", b"") or b""
    if not validate_tee_pubkey(tee_pubkey):
        logger.warning(
            f"Peer verification failed for {peer_wallet}: "
            f"teePubkey is missing or not a valid P-384 key "
            f"(length={len(tee_pubkey)} bytes)"
        )
        return False

    if require_zk_verified and not getattr(instance, "zk_verified", False):
        logger.warning(f"Peer verification failed for {peer_wallet}: not zkVerified")
        return False

    logger.debug(f"Peer verification passed for {peer_wallet}")
    return True


def verify_peer_in_kms_operator_set(
    peer_wallet: str,
    nova_registry,
) -> bool:
    """
    Combined verification: peer must be an ACTIVE instance registered
    under KMS_APP_ID in the NovaAppRegistry AND have a valid P-384
    teePubkey on-chain.

    This is the recommended check for KMS-to-KMS sync authentication.

    Note: the KMSRegistry operator list is NOT used here.  Node membership
    is determined solely from NovaAppRegistry (by KMS_APP_ID).
    """
    from nova_registry import InstanceStatus

    if not peer_wallet:
        return False

    # 1. Must be a registered ACTIVE instance for KMS_APP_ID
    try:
        from config import KMS_APP_ID
        kms_app_id = int(KMS_APP_ID or 0)
        instance = nova_registry.get_instance_by_wallet(peer_wallet)
        if getattr(instance, "instance_id", 0) == 0:
            logger.warning(f"Peer {peer_wallet} not found in NovaAppRegistry")
            return False
        if getattr(instance, "app_id", None) != kms_app_id:
            logger.warning(
                f"Peer {peer_wallet} app_id {getattr(instance, 'app_id', '?')} "
                f"!= KMS_APP_ID {kms_app_id}"
            )
            return False
        if getattr(instance, "status", None) != InstanceStatus.ACTIVE:
            logger.warning(f"Peer {peer_wallet} is not ACTIVE in NovaAppRegistry")
            return False
    except Exception as exc:
        logger.warning(f"NovaAppRegistry check failed for {peer_wallet}: {exc}")
        return False

    # 2. Must have valid P-384 teePubkey and matching wallet
    if not verify_peer_identity(peer_wallet, nova_registry):
        return False

    return True


# =============================================================================
# P-384 ECDH Session Helpers
# =============================================================================


def get_peer_tee_pubkey(
    peer_wallet: str,
    nova_registry,
) -> Optional[ec.EllipticCurvePublicKey]:
    """
    Retrieve and parse the on-chain P-384 teePubkey for *peer_wallet*.

    Returns the parsed public key, or None if not found / invalid.
    """
    try:
        instance = nova_registry.get_instance_by_wallet(peer_wallet)
        tee_pubkey_bytes = getattr(instance, "tee_pubkey", b"") or b""
        return parse_tee_pubkey(tee_pubkey_bytes)
    except Exception as exc:
        logger.debug(f"Failed to get teePubkey for {peer_wallet}: {exc}")
        return None


def generate_ecdh_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """
    Generate an ephemeral P-384 keypair for ECDH key exchange.

    Returns (private_key, public_key_der_bytes).
    """
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key_der


def derive_ecdh_shared_key(
    my_private_key: ec.EllipticCurvePrivateKey,
    peer_pubkey_bytes: bytes,
) -> bytes:
    """
    Derive a shared secret via ECDH between *my_private_key* (P-384) and
    the peer's P-384 public key.

    Parameters
    ----------
    my_private_key : ec.EllipticCurvePrivateKey
        Our ephemeral P-384 private key.
    peer_pubkey_bytes : bytes
        The peer's P-384 public key (DER/SPKI or uncompressed SEC1).

    Returns
    -------
    bytes
        The raw ECDH shared secret (48 bytes for P-384).
    """
    peer_pubkey = parse_tee_pubkey(peer_pubkey_bytes)
    return my_private_key.exchange(ec.ECDH(), peer_pubkey)
