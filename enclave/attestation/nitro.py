"""
=============================================================================
AWS Nitro Enclaves Attestation Verification (nitro.py)
=============================================================================

This module verifies AWS Nitro Enclaves attestation documents (CBOR + COSE_Sign1)
inside the enclave application.

Security goals:
- Do NOT trust any external proxy / terminator.
- Treat the attestation as an untrusted blob until verified against a pinned
  AWS Nitro root certificate.
- Extract only signed fields (e.g. user_data) after verification.

References:
- AWS Nitro Enclaves "Verifying the root of trust"
  https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from cose.messages import CoseMessage
from cose.messages.sign1message import Sign1Message
from cose.keys.ec2 import EC2Key
from cose.keys.curves import P384
from cose.keys.keyparam import EC2KpCurve, EC2KpX, EC2KpY

logger = logging.getLogger("nova-kms.attestation.nitro")


AWS_NITRO_ROOT_G1_SHA256_FINGERPRINT_HEX = (
    "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"
)


@dataclass(frozen=True)
class NitroAttestationIdentity:
    tee_wallet: str
    code_measurement: Optional[bytes]
    raw_doc: bytes
    timestamp_ms: int
    nonce: Optional[bytes]


def _load_pinned_root(root_pem: bytes) -> x509.Certificate:
    cert = x509.load_pem_x509_certificate(root_pem)
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    if fp != AWS_NITRO_ROOT_G1_SHA256_FINGERPRINT_HEX:
        raise ValueError("Pinned Nitro root certificate fingerprint mismatch")
    # Basic subject sanity check (defense-in-depth)
    subj = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if subj != "aws.nitro-enclaves":
        raise ValueError("Pinned Nitro root certificate CN mismatch")
    return cert


def _verify_chain(
    *,
    leaf: x509.Certificate,
    cabundle_der: list[bytes],
    pinned_root: x509.Certificate,
    now: Optional[float] = None,
) -> None:
    """
    Verify the leaf certificate chains to the pinned root by checking
    signatures and validity windows. This is a minimal verifier sufficient
    for Nitro attestation trust anchoring.

    cabundle_der is expected to be ordered as AWS specifies:
      [ROOT_CERT, INTERM_1, ..., INTERM_N]
    """
    now_dt = x509.datetime.datetime.now(x509.datetime.timezone.utc) if now is None else x509.datetime.datetime.fromtimestamp(now, tz=x509.datetime.timezone.utc)

    # Parse cabundle
    cabundle: list[x509.Certificate] = [
        x509.load_der_x509_certificate(c) for c in cabundle_der
    ]
    if not cabundle:
        raise ValueError("Missing cabundle in attestation document")

    # Ensure cabundle root matches our pinned root (fingerprint pinning)
    cabundle_root = cabundle[0]
    if cabundle_root.fingerprint(hashes.SHA256()) != pinned_root.fingerprint(hashes.SHA256()):
        raise ValueError("Attestation cabundle root does not match pinned Nitro root")

    # Build chain in verification order: leaf -> interm_N -> ... -> interm_1 -> root
    interms = cabundle[1:]
    chain: list[x509.Certificate] = [leaf] + list(reversed(interms)) + [pinned_root]

    # Validity window checks
    for c in chain:
        if not (c.not_valid_before_utc <= now_dt <= c.not_valid_after_utc):
            raise ValueError("Certificate in chain is not currently valid")

    # Signature checks (child signed by parent)
    for child, parent in zip(chain, chain[1:]):
        pub = parent.public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise ValueError("Unexpected certificate public key type (expected EC)")
        pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )

    # Root self-signature check
    root_pub = pinned_root.public_key()
    if isinstance(root_pub, ec.EllipticCurvePublicKey):
        root_pub.verify(
            pinned_root.signature,
            pinned_root.tbs_certificate_bytes,
            ec.ECDSA(pinned_root.signature_hash_algorithm),
        )


def _cose_key_from_cert(cert: x509.Certificate) -> EC2Key:
    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("Attestation signing cert is not an EC public key")
    nums = pub.public_numbers()
    if not isinstance(nums.curve, ec.SECP384R1):
        # Nitro attestation uses ECDSA P-384 by default (alg -35).
        raise ValueError("Unexpected EC curve for Nitro attestation (expected P-384)")

    x = nums.x.to_bytes(48, "big")
    y = nums.y.to_bytes(48, "big")
    return EC2Key.from_dict({EC2KpCurve: P384, EC2KpX: x, EC2KpY: y})


def _decode_user_data(user_data: bytes) -> Tuple[str, Optional[bytes]]:
    """
    Decode signed user_data to extract:
    - tee_wallet (0x-prefixed string)
    - code_measurement (bytes32) if present

    Protocol: user_data is expected to be either CBOR or JSON.
    CBOR form recommended:
      {"tee_wallet": "0x...", "code_measurement": <bytes32>}
    """
    if not user_data:
        return "", None

    parsed: Any
    try:
        parsed = cbor2.loads(user_data)
    except Exception:
        # JSON fallback (best-effort)
        import json

        parsed = json.loads(user_data.decode("utf-8", errors="strict"))

    if not isinstance(parsed, dict):
        raise ValueError("Invalid attestation user_data (expected map/object)")

    tee_wallet = parsed.get("tee_wallet") or parsed.get("wallet") or ""
    if isinstance(tee_wallet, (bytes, bytearray)):
        tee_wallet = "0x" + bytes(tee_wallet).hex()
    if not isinstance(tee_wallet, str):
        tee_wallet = str(tee_wallet)

    meas = parsed.get("code_measurement") or parsed.get("measurement")
    measurement: Optional[bytes] = None
    if isinstance(meas, (bytes, bytearray)):
        measurement = bytes(meas)
    elif isinstance(meas, str) and meas:
        measurement = bytes.fromhex(meas.replace("0x", ""))

    if measurement is not None and len(measurement) != 32:
        raise ValueError("Invalid code_measurement length (expected 32 bytes)")

    return tee_wallet, measurement


def verify_and_extract_identity(
    *,
    attestation_doc: bytes,
    pinned_root_pem: bytes,
    max_age_seconds: int = 120,
) -> NitroAttestationIdentity:
    """
    Verify a Nitro attestation document and extract the identity fields
    required by Nova KMS authorization.
    """
    if not attestation_doc:
        raise ValueError("Empty attestation document")

    pinned_root = _load_pinned_root(pinned_root_pem)

    # Decode COSE_Sign1
    msg = CoseMessage.decode(attestation_doc)
    if not isinstance(msg, Sign1Message):
        raise ValueError("Attestation blob is not a COSE_Sign1 message")
    if not msg.payload:
        raise ValueError("COSE_Sign1 payload missing")

    # Decode payload (CBOR map) first so we can get signing cert and timestamp.
    payload = cbor2.loads(msg.payload)
    if not isinstance(payload, dict):
        raise ValueError("Attestation payload is not a CBOR map")

    timestamp_ms = int(payload.get("timestamp", 0) or 0)
    if timestamp_ms <= 0:
        raise ValueError("Attestation missing timestamp")
    now_ms = int(time.time() * 1000)
    if max_age_seconds > 0:
        if abs(now_ms - timestamp_ms) > (max_age_seconds * 1000):
            raise ValueError("Attestation timestamp outside allowed window")

    # Extract certs
    cert_der = payload.get("certificate")
    cabundle = payload.get("cabundle") or []
    if not isinstance(cert_der, (bytes, bytearray)):
        raise ValueError("Attestation missing signing certificate")
    if not isinstance(cabundle, list) or not all(isinstance(c, (bytes, bytearray)) for c in cabundle):
        raise ValueError("Invalid cabundle in attestation payload")

    leaf_cert = x509.load_der_x509_certificate(bytes(cert_der))

    # Verify certificate chain to pinned root
    _verify_chain(leaf=leaf_cert, cabundle_der=[bytes(c) for c in cabundle], pinned_root=pinned_root)

    # Verify COSE signature with leaf cert key
    msg.key = _cose_key_from_cert(leaf_cert)
    if not msg.verify_signature():
        raise ValueError("COSE signature verification failed")

    # Extract nonce (challenge) and signed user_data
    nonce = payload.get("nonce") or b""
    if nonce is not None and not isinstance(nonce, (bytes, bytearray)):
        raise ValueError("Invalid nonce in attestation payload")

    user_data = payload.get("user_data") or b""
    if not isinstance(user_data, (bytes, bytearray)):
        raise ValueError("Invalid user_data in attestation payload")

    tee_wallet, measurement = _decode_user_data(bytes(user_data))

    return NitroAttestationIdentity(
        tee_wallet=tee_wallet,
        code_measurement=measurement,
        raw_doc=attestation_doc,
        timestamp_ms=timestamp_ms,
        nonce=bytes(nonce) if nonce else None,
    )


def decode_attestation_header_value(value: str) -> bytes:
    """
    Accept either:
    - base64 string (recommended)
    - hex string (0x... optional)
    """
    v = (value or "").strip()
    if not v:
        return b""
    if v.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in v):
        hx = v[2:] if v.startswith("0x") else v
        # Hex decoding should be strict
        return bytes.fromhex(hx)
    return base64.b64decode(v)

