"""enclave/auth.py

Authentication + authorization helpers.

This repository no longer uses RA-TLS / Nitro attestation documents for HTTP
request authentication.

Security modes:
    - Production (IN_ENCLAVE=True, SIMULATION_MODE=False): require lightweight
        Proof-of-Possession (PoP) signatures (EIP-191) for app requests.
    - Dev / Sim (IN_ENCLAVE=False or SIMULATION_MODE=True): allow convenience
        headers (x-tee-wallet / x-tee-measurement) to stand in for identity.

Authorization is always enforced via NovaAppRegistry lookups in AppAuthorizer.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional, Dict

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

def is_production_mode() -> bool:
    """Return True when running in an enclave (non-simulation)."""
    return bool(getattr(config, "IN_ENCLAVE", False)) and not bool(
        getattr(config, "SIMULATION_MODE", False)
    )


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


def issue_nonce() -> bytes:
    """Issue a fresh one-time nonce for PoP challenge-response."""
    return _nonce_store.issue()


def issue_attestation_challenge() -> bytes:
    """Backward-compatible alias for issue_nonce()."""
    return issue_nonce()


def attestation_from_headers(headers: dict) -> ClientAttestation:
    """
    Build a ClientAttestation from HTTP headers (dev / test mode).

    This helper provides a debugging shim for local development.

    In production mode (IN_ENCLAVE=True) this function raises an error to
    prevent header-based spoofing.
    """
    if is_production_mode():
        raise RuntimeError(
            "Header-based attestation is disabled in production. "
            "Use PoP (X-App-Signature / X-App-Nonce / X-App-Timestamp)."
        )
    tee_wallet = headers.get("x-tee-wallet", "")
    measurement_hex = headers.get("x-tee-measurement", "")
    measurement = bytes.fromhex(measurement_hex.replace("0x", "")) if measurement_hex else None
    if tee_wallet:
        logger.debug("Using header-based attestation (dev/sim mode)")
    return ClientAttestation(tee_wallet=tee_wallet, measurement=measurement)


def app_attestation_from_signature(request) -> Optional[ClientAttestation]:
    """
    Extract app identity from PoP signature headers.
    Headers: X-App-Signature, X-App-Timestamp, X-App-Nonce

    For backward compatibility, X-App-Wallet may be provided, but it is not
    required. When omitted, the wallet is recovered from the signature.
    """
    sig = request.headers.get("x-app-signature")
    ts = request.headers.get("x-app-timestamp")
    nonce_b64 = request.headers.get("x-app-nonce")

    wallet = request.headers.get("x-app-wallet")

    if not all([sig, ts, nonce_b64]):
        return None

    try:
        import base64
        nonce_bytes = base64.b64decode(nonce_b64)
        if not _nonce_store.validate_and_consume(nonce_bytes):
            raise RuntimeError("Invalid or expired nonce")

        # Enforce timestamp freshness to limit replay window.
        _require_fresh_timestamp(ts)

        # Message: NovaKMS:AppAuth:<Nonce>:<KMS_Wallet>:<Timestamp>
        message = f"NovaKMS:AppAuth:{nonce_b64}:{_node_wallet}:{ts}"

        recovered = recover_wallet_from_signature(message, sig)
        if not recovered:
            raise RuntimeError("Invalid app signature")

        # Optional explicit wallet header must match recovered signer.
        if wallet and recovered.lower() != wallet.lower():
            raise RuntimeError("App wallet header does not match signature")

        # Return attestation with None measurement; AppAuthorizer will trust
        # the on-chain measurement for this verified TEE wallet.
        return ClientAttestation(
            tee_wallet=recovered.lower(),
            measurement=None,
            signature=sig
        )
    except Exception as exc:
        logger.warning(f"App PoP verification failed: {exc}")
        raise RuntimeError(f"App PoP authentication failed: {exc}")


def get_attestation(request, headers: dict) -> ClientAttestation:
    """
    Unified attestation extraction.

    - In production mode: require PoP signature.
    - In dev/sim mode: allow header-based identity for convenience.
    """
    if is_production_mode():
        # Require lightweight PoP signature
        att = app_attestation_from_signature(request)
        if att is not None:
            return att

        raise RuntimeError(
            "Missing PoP authentication. "
            "Provide X-App-Signature / X-App-Nonce / X-App-Timestamp headers."
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
            # In production, measurement is required for full attestation paths.
            # For lightweight PoP, the wallet was already bound to a measured
            # version on-chain at enrollment time, so we allow missing measurement
            # ONLY when a PoP signature was presented.
            if not attestation.signature:
                return AuthResult(authorized=False, reason="Measurement required")

        return AuthResult(
            authorized=True,
            app_id=instance.app_id,
            version_id=instance.version_id,
        )

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


def recover_wallet_from_signature(message: str, signature: str) -> Optional[str]:
    """Recover the Ethereum wallet address from an EIP-191 signature."""
    if not signature or not message:
        return None
    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account

        msghash = encode_defunct(text=message)
        recovered = Account.recover_message(msghash, signature=signature)
        return recovered
    except Exception as exc:
        logger.warning(f"Signature recovery failed: {exc}")
        return None


def _require_fresh_timestamp(ts: str) -> None:
    """Raise RuntimeError if timestamp is missing/invalid/stale."""
    if not ts:
        raise RuntimeError("Missing timestamp")
    try:
        ts_int = int(ts)
    except Exception:
        raise RuntimeError("Invalid timestamp")

    max_age = getattr(config, "ATTESTATION_MAX_AGE_SECONDS", 120)
    now = int(time.time())
    if abs(now - ts_int) > max_age:
        raise RuntimeError("Stale timestamp")
