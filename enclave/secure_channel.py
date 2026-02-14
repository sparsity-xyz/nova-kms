"""
=============================================================================
Secure Channel (secure_channel.py)
=============================================================================

Provides teePubkey-based identity verification and E2E encryption helpers
for enclave-to-enclave and app-to-enclave communication.

Key Architecture
----------------
Every Nova Platform enclave has **two independent keypairs**:

1. **ETH wallet** (secp256k1): ``tee_wallet_address`` + private key.
   Used for PoP message signing (EIP-191 via Odyn ``/v1/eth/sign``).

2. **teePubkey** (NIST P-384 / secp384r1): DER-encoded SPKI public key.
   Used for ECDH-based encryption (via Odyn ``/v1/encryption/*``).

These keypairs live on *different curves* and are *completely independent*.
The wallet address is **not** derived from teePubkey and vice-versa.

E2E Encryption Protocol
-----------------------
All sensitive payloads (App↔KMS and KMS↔KMS) are encrypted using the
teePubkey-based ECDH + AES-256-GCM scheme provided by Odyn:

  1. Sender fetches receiver's teePubkey from on-chain NovaAppRegistry.
  2. Sender calls ``Odyn.encrypt(plaintext, receiver_teePubkey)`` which
     performs ECDH key agreement and AES-256-GCM encryption.
  3. Envelope format: ``{"sender_tee_pubkey": "<hex>", "nonce": "<hex>",
     "encrypted_data": "<hex>"}``
  4. Receiver calls ``Odyn.decrypt(nonce, sender_teePubkey, encrypted_data)``
     to recover the plaintext.

This ensures confidentiality even if TLS is terminated outside the enclave.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

if TYPE_CHECKING:
    from odyn import Odyn

logger = logging.getLogger("nova-kms.secure_channel")


# =============================================================================
# E2E Envelope Encryption (teePubkey-based)
# =============================================================================


def encrypt_envelope(
    odyn: "Odyn",
    plaintext: str,
    receiver_tee_pubkey_hex: str,
) -> Dict[str, str]:
    """
    Encrypt a plaintext message for a specific receiver using their teePubkey.

    Uses Odyn's built-in ECDH + AES-256-GCM encryption.

    Parameters
    ----------
    odyn : Odyn
        The Odyn SDK instance of the sender.
    plaintext : str
        The plaintext message (typically JSON-encoded).
    receiver_tee_pubkey_hex : str
        The receiver's P-384 teePubkey in hex (DER/SPKI format).

    Returns
    -------
    dict
        Envelope with keys: sender_tee_pubkey, nonce, encrypted_data (all hex).
    """
    # Get sender's teePubkey
    sender_pubkey_der = odyn.get_encryption_public_key_der()
    sender_pubkey_hex = sender_pubkey_der.hex()

    # Encrypt using receiver's teePubkey
    result = odyn.encrypt(plaintext, receiver_tee_pubkey_hex)

    # Odyn returns 'encrypted_data'
    encrypted_data = result.get("encrypted_data") or ""

    nonce_hex = result.get("nonce", "")
    if nonce_hex.startswith("0x"):
        nonce_hex = nonce_hex[2:]

    enc_data_hex = encrypted_data
    if enc_data_hex.startswith("0x"):
        enc_data_hex = enc_data_hex[2:]

    return {
        "sender_tee_pubkey": sender_pubkey_hex,
        "nonce": nonce_hex,
        "encrypted_data": enc_data_hex,
    }


def decrypt_envelope(
    odyn: "Odyn",
    envelope: Dict[str, str],
) -> str:
    """
    Decrypt an envelope that was encrypted for this node's teePubkey.

    Parameters
    ----------
    odyn : Odyn
        The Odyn SDK instance of the receiver.
    envelope : dict
        Envelope with keys: sender_tee_pubkey, nonce, encrypted_data (all hex).

    Returns
    -------
    str
        The decrypted plaintext.

    Raises
    ------
    ValueError
        If the envelope is malformed or decryption fails.
    """
    sender_pubkey_hex = envelope.get("sender_tee_pubkey", "")
    nonce_hex = envelope.get("nonce", "")
    encrypted_data_hex = envelope.get("encrypted_data", "")

    if not all([sender_pubkey_hex, nonce_hex, encrypted_data_hex]):
        raise ValueError("Malformed envelope: missing required fields")

    try:
        plaintext = odyn.decrypt(nonce_hex, sender_pubkey_hex, encrypted_data_hex)
        return plaintext
    except Exception as exc:
        raise ValueError(f"Envelope decryption failed: {exc}") from exc


def encrypt_json_envelope(
    odyn: "Odyn",
    data: Any,
    receiver_tee_pubkey_hex: str,
) -> Dict[str, str]:
    """
    Convenience wrapper: JSON-encode data and encrypt as envelope.
    """
    plaintext = json.dumps(data, separators=(",", ":"))
    return encrypt_envelope(odyn, plaintext, receiver_tee_pubkey_hex)


def decrypt_json_envelope(
    odyn: "Odyn",
    envelope: Dict[str, str],
) -> Any:
    """
    Convenience wrapper: decrypt envelope and JSON-decode the result.
    """
    plaintext = decrypt_envelope(odyn, envelope)
    return json.loads(plaintext)


def get_tee_pubkey_hex_for_wallet(
    wallet: str,
    nova_registry,
) -> Optional[str]:
    """
    Retrieve the on-chain teePubkey (P-384, DER) for a wallet address.

    Returns the hex-encoded teePubkey, or None if not found/invalid.
    """
    try:
        instance = nova_registry.get_instance_by_wallet(wallet)
        tee_pubkey_bytes = getattr(instance, "tee_pubkey", b"") or b""
        if not tee_pubkey_bytes or not validate_tee_pubkey(tee_pubkey_bytes):
            return None
        return tee_pubkey_bytes.hex()
    except Exception as exc:
        logger.debug(f"Failed to get teePubkey for {wallet}: {exc}")
        return None


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
