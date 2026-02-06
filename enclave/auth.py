"""
=============================================================================
App Authorization (auth.py)
=============================================================================

Verifies that an incoming request originates from a legitimate Nova Platform
application by cross-referencing the RA-TLS client attestation with
NovaAppRegistry on-chain data.

Security modes:
  - **Production** (REQUIRE_RATLS=True): attestation MUST come from a
    validated TLS channel (RA-TLS cert extensions).  Header-based fallback
    is disabled.  Measurement verification is mandatory.
  - **Dev / Sim** (REQUIRE_RATLS=False): headers X-Tee-Wallet and
    X-Tee-Measurement are accepted for convenience.  A warning is logged.

See architecture.md §2.3 for the full verification flow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Tuple

import config
from nova_registry import (
    AppStatus,
    InstanceStatus,
    NovaRegistry,
    VersionStatus,
)

logger = logging.getLogger("nova-kms.auth")


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
    Extract attestation from the mutual TLS client certificate.

    In a Nitro Enclave with RA-TLS, the client certificate contains custom
    X.509 extensions with the attestation document.  This function extracts
    the TEE wallet address and code measurement from those extensions.

    Parameters
    ----------
    request : fastapi.Request
        The incoming HTTP request.  The TLS layer must have already validated
        the client certificate and made it available.

    Returns
    -------
    ClientAttestation or None if no client cert is available.
    """
    # In production, the TLS terminator (e.g. Caddy with RA-TLS) validates
    # the attestation document and forwards verified fields as headers:
    #   X-Verified-Tee-Wallet, X-Verified-Tee-Measurement
    # These headers are ONLY trusted when set by the TLS terminator, never
    # by the external client.
    verified_wallet = request.headers.get("x-verified-tee-wallet", "")
    verified_measurement = request.headers.get("x-verified-tee-measurement", "")

    if not verified_wallet:
        return None

    measurement = None
    if verified_measurement:
        measurement = bytes.fromhex(verified_measurement.replace("0x", ""))

    return ClientAttestation(tee_wallet=verified_wallet, measurement=measurement)


def get_attestation(request, headers: dict) -> ClientAttestation:
    """
    Unified attestation extraction.

    - In production mode: try TLS-verified attestation first.
    - In dev/sim mode: fall back to header-based attestation.
    """
    if is_production_mode():
        att = attestation_from_tls(request)
        if att is not None:
            return att
        # In production, if TLS attestation is not available, reject
        raise RuntimeError(
            "No RA-TLS attestation found in request. "
            "Ensure the client presents a valid RA-TLS certificate."
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
            # In production, measurement is mandatory
            return AuthResult(authorized=False, reason="Measurement required but not provided")

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
