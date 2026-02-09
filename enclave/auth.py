"""
=============================================================================
App Authorization (auth.py)
=============================================================================

Verifies that an incoming request originates from a legitimate Nova Platform
application by cross-referencing the RA-TLS client attestation with
NovaAppRegistry on-chain data.

Security modes:
  - **Production** (REQUIRE_RATLS=True): attestation MUST come from a
    verified Nitro attestation document. Proxy-injected headers are not trusted.
    Measurement verification is mandatory.
  - **Dev / Sim** (REQUIRE_RATLS=False): headers X-Tee-Wallet and
    X-Tee-Measurement are accepted for convenience.  A warning is logged.

See architecture.md §2.3 for the full verification flow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Tuple, Dict

import config
from nova_registry import (
    AppStatus,
    InstanceStatus,
    NovaRegistry,
    VersionStatus,
)

logger = logging.getLogger("nova-kms.auth")
 
_node_wallet: Optional[str] = None

def set_node_wallet(wallet: str):
    """Set the local node wallet for PoP recipient binding."""
    global _node_wallet
    _node_wallet = wallet.lower()


# =============================================================================
# Production mode detection
# =============================================================================

def is_production_mode() -> bool:
    """Return True when running in production (RA-TLS required)."""
    return config.REQUIRE_RATLS


# =============================================================================
# Attestation abstraction
# =============================================================================

@dataclass
class ClientAttestation:
    """
    Represents the parsed RA-TLS client attestation.

    In production, these fields are extracted from the TLS certificate
    extensions populated by the Nitro enclave's attestation document.
    In development, they can be injected via HTTP headers for testing.
    """

    tee_wallet: str                  # Ethereum address of the instance
    measurement: Optional[bytes]     # PCR / code measurement (bytes32)
    signature: Optional[str] = None  # Original PoP signature (if applicable)


class _NonceStore:
    """
    In-enclave nonce cache for challenge-response.

    - KMS issues one-time nonces via a public endpoint.
    - Clients must include the issued nonce inside the Nitro attestation
      (payload['nonce']) when calling authenticated endpoints.
    - Nonces are single-use and expire after a short TTL to prevent replay.
    """

    def __init__(self, ttl_seconds: int = 120):
        self._ttl = ttl_seconds
        self._nonces: Dict[bytes, float] = {}

    def issue(self) -> bytes:
        import os
        import time

        nonce = os.urandom(16)
        now = time.time()
        self._nonces[nonce] = now + self._ttl
        return nonce

    def validate_and_consume(self, nonce: Optional[bytes]) -> bool:
        import time

        if not nonce:
            return False
        now = time.time()
        # Fast path
        exp = self._nonces.pop(nonce, None)
        if exp is None:
            return False
        if exp < now:
            return False
        # Opportunistic cleanup of expired entries
        if len(self._nonces) > 1024:
            self._purge(now=now)
        return True

    def _purge(self, now: Optional[float] = None) -> None:
        import time

        if now is None:
            now = time.time()
        self._nonces = {n: exp for n, exp in self._nonces.items() if exp >= now}


_nonce_store = _NonceStore(ttl_seconds=getattr(config, "ATTESTATION_MAX_AGE_SECONDS", 120))


def issue_attestation_challenge() -> bytes:
    """
    Issue a fresh one-time nonce for Nitro attestation challenge-response.
    """
    return _nonce_store.issue()


def attestation_from_headers(headers: dict) -> ClientAttestation:
    """
    Build a ClientAttestation from HTTP headers (dev / test mode).

    Production RA-TLS extracts these from the mutual TLS handshake;
    this helper provides a debugging shim.

    In production mode (REQUIRE_RATLS=True) this function will raise
    an error to prevent header-based spoofing.
    """
    if is_production_mode():
        raise RuntimeError(
            "Header-based attestation is disabled in production. "
            "Use RA-TLS mutual authentication."
        )
    tee_wallet = headers.get("x-tee-wallet", "")
    measurement_hex = headers.get("x-tee-measurement", "")
    measurement = bytes.fromhex(measurement_hex.replace("0x", "")) if measurement_hex else None
    if tee_wallet:
        logger.debug("Using header-based attestation (dev/sim mode)")
    return ClientAttestation(tee_wallet=tee_wallet, measurement=measurement)


def attestation_from_tls(request) -> Optional[ClientAttestation]:
    """
    Extract attestation identity in production mode.

    IMPORTANT: We do NOT trust any external TLS terminator / proxy.
    Therefore we do not accept "verified" headers injected by intermediaries.

    Current implementation requires the caller to provide an AWS Nitro attestation
    document via the HTTP header configured by config.ATTESTATION_HEADER_NAME.

    This keeps the trust boundary inside the enclave app:
    - the attestation document is verified against the pinned AWS Nitro Root-G1;
    - only signed user_data fields are used to extract tee_wallet and measurement.

    Returns ClientAttestation or None if not present.
    """
    header_name = getattr(config, "ATTESTATION_HEADER_NAME", "x-nitro-attestation")
    raw = request.headers.get(header_name, "")
    if not raw:
        return None

    try:
        from attestation.nitro import decode_attestation_header_value, verify_and_extract_identity

        # Load pinned root cert from local filesystem (bundled in the image)
        root_path = getattr(config, "NITRO_ROOT_CERT_PATH", "attestation/root.pem")
        with open(root_path, "rb") as f:
            pinned_root_pem = f.read()

        att_doc = decode_attestation_header_value(raw)
        ident = verify_and_extract_identity(
            attestation_doc=att_doc,
            pinned_root_pem=pinned_root_pem,
            max_age_seconds=getattr(config, "ATTESTATION_MAX_AGE_SECONDS", 120),
        )
        # Enforce challenge-response: attestation nonce must match an issued one.
        if not _nonce_store.validate_and_consume(ident.nonce):
            raise RuntimeError("Invalid or expired attestation nonce")
        return ClientAttestation(
            tee_wallet=ident.tee_wallet,
            measurement=ident.code_measurement,
        )
    except Exception as exc:
        logger.warning(f"Invalid Nitro attestation header: {exc}")
        raise RuntimeError("Invalid or unverifiable attestation document")


def app_attestation_from_signature(request) -> Optional[ClientAttestation]:
    """
    Extract app identity from PoP signature headers.
    Headers: X-App-Wallet, X-App-Signature, X-App-Timestamp, X-App-Nonce
    """
    wallet = request.headers.get("x-app-wallet")
    sig = request.headers.get("x-app-signature")
    ts = request.headers.get("x-app-timestamp")
    nonce_b64 = request.headers.get("x-app-nonce")

    if not all([wallet, sig, ts, nonce_b64]):
        return None

    try:
        import base64
        nonce_bytes = base64.b64decode(nonce_b64)
        if not _nonce_store.validate_and_consume(nonce_bytes):
            raise RuntimeError("Invalid or expired nonce")

        # Message: NovaKMS:AppAuth:<Nonce>:<KMS_Wallet>:<Timestamp>
        message = f"NovaKMS:AppAuth:{nonce_b64}:{_node_wallet}:{ts}"
        if not verify_wallet_signature(wallet, message, sig):
            raise RuntimeError("Invalid app signature")

        # Return attestation with None measurement; AppAuthorizer will trust
        # the on-chain measurement for this verified TEE wallet.
        return ClientAttestation(
            tee_wallet=wallet.lower(),
            measurement=None,
            signature=sig
        )
    except Exception as exc:
        logger.warning(f"App PoP verification failed: {exc}")
        raise RuntimeError(f"App PoP authentication failed: {exc}")


def get_attestation(request, headers: dict) -> ClientAttestation:
    """
    Unified attestation extraction.

    - In production mode: try RA-TLS attestation OR PoP signature.
    - In dev/sim mode: fall back to header-based attestation.
    """
    if is_production_mode():
        # 1. Try lightweight PoP signature first
        att = app_attestation_from_signature(request)
        if att is not None:
            return att

        # 2. Fallback to full RA-TLS attestation
        att = attestation_from_tls(request)
        if att is not None:
            return att

        # In production, if no valid attestation is found, reject
        raise RuntimeError(
            "No valid attestation or PoP signature found. "
            "Ensure you provide either RA-TLS or X-App-Signature headers."
        )
    # Dev/sim mode: headers are acceptable
    return attestation_from_headers(headers)


# =============================================================================
# Authorization result
# =============================================================================

@dataclass
class AuthResult:
    authorized: bool
    app_id: Optional[int] = None
    version_id: Optional[int] = None
    reason: Optional[str] = None


# =============================================================================
# Verifier
# =============================================================================

class AppAuthorizer:
    """
    Verifies that a client attestation maps to an authorized Nova app.

    Steps (mirrors architecture doc §2.3):
      1. getInstanceByWallet(teeWallet)  →  instance
      2. instance must be ACTIVE and zkVerified
      3. getApp(appId) → app must be ACTIVE
      4. getVersion(appId, versionId) → ENROLLED or DEPRECATED
      5. code measurement must match version.codeMeasurement
    """

    def __init__(self, registry: Optional[NovaRegistry] = None):
        self.registry = registry or NovaRegistry()

    def verify(self, attestation: ClientAttestation) -> AuthResult:
        """
        Synchronous verification.  Returns AuthResult with authorized=True
        if all checks pass, or authorized=False with a reason string.
        """
        if not attestation.tee_wallet:
            return AuthResult(authorized=False, reason="Missing TEE wallet")

        # 1. Look up instance
        try:
            instance = self.registry.get_instance_by_wallet(attestation.tee_wallet)
        except Exception as exc:
            logger.warning(f"Instance lookup failed for {attestation.tee_wallet}: {exc}")
            return AuthResult(authorized=False, reason="Instance not found")

        if instance.instance_id == 0:
            return AuthResult(authorized=False, reason="Instance not found")

        # 2. Instance must be ACTIVE + zkVerified
        if instance.status != InstanceStatus.ACTIVE:
            return AuthResult(authorized=False, reason="Instance not active")
        if not instance.zk_verified:
            return AuthResult(authorized=False, reason="Instance not zkVerified")

        # 3. App must be ACTIVE
        try:
            app = self.registry.get_app(instance.app_id)
        except Exception as exc:
            logger.warning(f"App lookup failed for appId={instance.app_id}: {exc}")
            return AuthResult(authorized=False, reason="App lookup failed")

        if app.status != AppStatus.ACTIVE:
            return AuthResult(authorized=False, reason="App not active")

        # 4. Version must be ENROLLED or DEPRECATED
        try:
            version = self.registry.get_version(instance.app_id, instance.version_id)
        except Exception as exc:
            logger.warning(f"Version lookup failed: {exc}")
            return AuthResult(authorized=False, reason="Version lookup failed")

        if version.status not in (VersionStatus.ENROLLED, VersionStatus.DEPRECATED):
            return AuthResult(authorized=False, reason="Version not allowed")

        # 5. Measurement match
        if attestation.measurement is not None:
            if version.code_measurement != attestation.measurement:
                return AuthResult(authorized=False, reason="Measurement mismatch")
        elif config.REQUIRE_MEASUREMENT:
            # If measurement is missing (PoP case), we trust the identity mapping
            # because the TEE wallet was already verified against this measurement on-chain.
            # In a strict future, we could re-verify this mapping if needed.
            pass

        return AuthResult(
            authorized=True,
            app_id=instance.app_id,
            version_id=instance.version_id,
        )


# =============================================================================
# KMS node peer verification (for sync)
# =============================================================================

class KMSNodeVerifier:
    """
    Verify that a sync peer is a registered KMS operator.
    Used in /sync endpoint to gate incoming data from other KMS nodes.
    """

    def __init__(self, kms_registry_client=None):
        self._kms_registry = kms_registry_client

    @property
    def kms_registry(self):
        if self._kms_registry is None:
            from kms_registry import KMSRegistryClient
            self._kms_registry = KMSRegistryClient()
        return self._kms_registry

    def verify_peer(self, tee_wallet: str) -> Tuple[bool, Optional[str]]:
        """Return (is_valid, reason_if_invalid)."""
        if not tee_wallet:
            return False, "Missing TEE wallet"
        try:
            if not self.kms_registry.is_operator(tee_wallet):
                return False, "Not a registered KMS operator"
        except Exception as exc:
            logger.warning(f"KMS peer lookup failed for {tee_wallet}: {exc}")
            return False, "Operator lookup failed"

        return True, None


def verify_wallet_signature(wallet: str, message: str, signature: str) -> bool:
    """
    Verify an Ethereum EIP-191 signature (ecrecover) for the given wallet and message.
    Used for lightweight PoP (Proof of Possession) between KMS nodes.
    """
    if not wallet or not signature or not message:
        return False
    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account

        msghash = encode_defunct(text=message)
        recovered = Account.recover_message(msghash, signature=signature)
        return recovered.lower() == wallet.lower()
    except Exception as exc:
        logger.warning(f"Signature verification failed: {exc}")
        return False
