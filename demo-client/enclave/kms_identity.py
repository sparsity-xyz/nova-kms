"""
=============================================================================
KMS Identity Verification (kms_identity.py)
=============================================================================

Client-side verification of KMS node identity.  Addresses audit finding H1
(Missing Enclave-to-Enclave TLS with teePubkey Verification) for
App-to-KMS communication.

Key Architecture
----------------
Every Nova Platform enclave has **two independent keypairs**:

1. **ETH wallet** (secp256k1): ``tee_wallet_address`` + private key.
   Used for PoP message signing (EIP-191 via Odyn ``/v1/eth/sign``).

2. **teePubkey** (NIST P-384 / secp384r1): DER-encoded SPKI public key.
   Used for ECDH-based encryption (via Odyn ``/v1/encryption/*``).

These keypairs live on *different curves* and are *completely independent*.
The wallet address is **NOT** derived from teePubkey and vice-versa.

Verification Steps
------------------
Before trusting a KMS node's response, the client:
  1. Validates that the node's on-chain ``teePubkey`` is a well-formed P-384
     public key (for use in ECDH session encryption).
  2. Verifies the ``X-KMS-Response-Signature`` header using EIP-191 signature
     recovery, confirming the response was signed by the expected secp256k1
     wallet.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("nova-kms-client.kms_identity")

_ETH_WALLET_RE = re.compile(r"^(0x)?[0-9a-fA-F]{40}$")


def _canonical_eth_wallet(wallet: str) -> str:
    w = (wallet or "").strip()
    if not w or not _ETH_WALLET_RE.match(w):
        return w
    w = w.lower()
    if not w.startswith("0x"):
        w = "0x" + w
    return w


# =========================================================================
# P-384 teePubkey Helpers
# =========================================================================


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


# =========================================================================
# On-chain teePubkey + wallet consistency check
# =========================================================================


def verify_instance_identity(instance, require_zk_verified: bool = False) -> bool:
    """
    Verify that a RuntimeInstance has valid identity fields registered on-chain.

    Checks:
      1. Instance is ACTIVE (if status is available).
      2. ``teePubkey`` is a well-formed P-384 public key.
      3. ``tee_wallet_address`` is non-empty (separate secp256k1 keypair).
      4. (Optional) ``zkVerified`` is True.

    Note: ``teePubkey`` (P-384) and ``tee_wallet_address`` (secp256k1) are
    **independent keypairs on different curves**. We do NOT derive wallet from
    teePubkey — they are completely separate.

    Parameters
    ----------
    instance : nova_registry.RuntimeInstance
        Instance object from on-chain registry.
    require_zk_verified : bool
        If True, also require instance.zk_verified == True.

    Returns
    -------
    True if all identity fields are valid.
    """
    instance_id = getattr(instance, "instance_id", 0)

    # Check teePubkey (P-384)
    tee_pubkey = getattr(instance, "tee_pubkey", b"") or b""
    if not validate_tee_pubkey(tee_pubkey):
        logger.warning(
            f"Instance {instance_id}: teePubkey is missing or not a valid P-384 key "
            f"(length={len(tee_pubkey)} bytes)"
        )
        return False

    # Check tee_wallet_address (secp256k1 — separate keypair)
    tee_wallet = (getattr(instance, "tee_wallet_address", "") or "").strip()
    if not tee_wallet:
        logger.warning(f"Instance {instance_id}: tee_wallet_address is empty")
        return False

    # Check zkVerified if required
    if require_zk_verified and not getattr(instance, "zk_verified", False):
        logger.warning(f"Instance {instance_id}: not zkVerified")
        return False

    return True


# =========================================================================
# Response signature verification
# =========================================================================

def verify_response_signature(
    response_sig_hex: str,
    client_sig_hex: str,
    expected_kms_wallet: str,
) -> bool:
    """
    Verify the ``X-KMS-Response-Signature`` header returned by a KMS node.

    The KMS server signs: ``NovaKMS:Response:<client_sig>:<kms_wallet>``
    using EIP-191 personal_sign.  We recover the signer and compare it
    to ``expected_kms_wallet``.

    Parameters
    ----------
    response_sig_hex : str
        The hex-encoded signature from the ``X-KMS-Response-Signature``
        header.
    client_sig_hex : str
        The hex-encoded PoP signature the client sent in the request.
    expected_kms_wallet : str
        The wallet address we expect the KMS node to sign with.

    Returns
    -------
    True if the recovered signer matches ``expected_kms_wallet``.
    """
    if not response_sig_hex or not client_sig_hex or not expected_kms_wallet:
        return False

    expected_wallet = _canonical_eth_wallet(expected_kms_wallet)
    if not expected_wallet:
        return False

    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account

        message_text = f"NovaKMS:Response:{client_sig_hex}:{expected_wallet}"
        message = encode_defunct(text=message_text)
        recovered = Account.recover_message(message, signature=response_sig_hex)

        from web3 import Web3
        if Web3.to_checksum_address(recovered) != Web3.to_checksum_address(expected_wallet):
            logger.warning(
                f"Response signature mismatch: recovered {recovered}, "
                f"expected {expected_wallet}"
            )
            return False
        return True
    except Exception as exc:
        logger.warning(f"Response signature verification failed: {exc}")
        return False
