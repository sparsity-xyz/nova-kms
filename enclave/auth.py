"""enclave/auth.py

Authentication + authorization helpers.

This repository no longer uses RA-TLS / Nitro attestation documents for HTTP
request authentication.

Security modes:
    - Production (IN_ENCLAVE=True, SIMULATION_MODE=False): require lightweight
        Proof-of-Possession (PoP) signatures (EIP-191) for app requests.
    - Dev / Sim (IN_ENCLAVE=False or SIMULATION_MODE=True): allow convenience
        header (x-tee-wallet) to stand in for identity.

Authorization is always enforced via NovaAppRegistry lookups in AppAuthorizer.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Optional, Dict

import config
from config import (
    MAX_NONCES,
    POP_MAX_AGE_SECONDS,
)
from nova_registry import (
    AppStatus,
    InstanceStatus,
    NovaRegistry,
    VersionStatus,
)

logger = logging.getLogger("nova-kms.auth")
 
_node_wallet: Optional[str] = None

_ETH_WALLET_RE = re.compile(r"^(0x)?[0-9a-fA-F]{40}$")


def _canonical_eth_wallet(wallet: Optional[str]) -> str:
    """Return canonical wallet string: '0x' + 40 lowercase hex.

    Raises ValueError if wallet is missing or not a valid Ethereum address.
    """
    if wallet is None:
        raise ValueError("Wallet is not set")
    w = str(wallet).strip()
    if not w:
        raise ValueError("Wallet is empty")
    if not _ETH_WALLET_RE.match(w):
        raise ValueError(
            "Wallet must be an Ethereum address in the form 0x + 40 hex chars"
        )
    w = w.lower()
    if not w.startswith("0x"):
        w = "0x" + w
    return w

def set_node_wallet(wallet: str):
    """Set the local node wallet for PoP recipient binding."""
    global _node_wallet
    _node_wallet = _canonical_eth_wallet(wallet)


def is_production_mode() -> bool:
    """Return True when running in an enclave (non-simulation)."""
    return bool(config.IN_ENCLAVE) and not bool(config.SIMULATION_MODE)


# =============================================================================
# Client Identity
# =============================================================================

@dataclass
class ClientIdentity:
    """
    Represents the verified identity of a requesting app.

    In production, fields are recovered from PoP (EIP-191) signatures.
    In dev/sim mode, they can be injected via HTTP headers for testing.
    """

    tee_wallet: str                  # Ethereum address of the instance
    signature: Optional[str] = None  # Original PoP signature (if applicable)


class _NonceStore:
    """
    In-enclave nonce cache for PoP challenge-response.

    - KMS issues one-time nonces via ``GET /nonce``.
    - Clients include the nonce in their PoP signature message.
    - Nonces are single-use and expire after a short TTL to prevent replay.
    """

    def __init__(self, ttl_seconds: int = 120, max_nonces: int = 4096):
        from collections import OrderedDict

        self._ttl = ttl_seconds
        self._max_nonces = max(1, int(max_nonces))
        self._nonces: "OrderedDict[bytes, float]" = OrderedDict()

    def issue(self) -> bytes:
        import os
        import time

        # Best-effort cleanup first.
        nonce = os.urandom(16)
        now = time.time()

        if len(self._nonces) >= self._max_nonces:
            self._purge(now=now)
        # Still full: evict the oldest nonce (FIFO) to keep memory bounded.
        if len(self._nonces) >= self._max_nonces:
            self._nonces.popitem(last=False)

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
        # Periodic cleanup of expired entries to keep memory bounded.
        # Low fix: run cleanup on every validate call (not just on issuance)
        # to prevent unbounded growth from external replay attempts.
        if len(self._nonces) > 256:
            self._purge(now=now)
        return True

    def _purge(self, now: Optional[float] = None) -> None:
        import time

        if now is None:
            now = time.time()
        # Preserve insertion order for FIFO eviction.
        for n in list(self._nonces.keys()):
            if self._nonces.get(n, 0) < now:
                self._nonces.pop(n, None)


_nonce_store = _NonceStore(
    ttl_seconds=POP_MAX_AGE_SECONDS,
    max_nonces=MAX_NONCES,
)


def issue_nonce() -> bytes:
    """Issue a fresh one-time nonce for PoP challenge-response."""
    return _nonce_store.issue()


def identity_from_headers(headers: dict) -> ClientIdentity:
    """
    Build a ClientIdentity from HTTP headers (dev / sim mode).

    This helper provides a convenience shim for local development.

    In production mode (IN_ENCLAVE=True) this function raises an error to
    prevent header-based spoofing.
    """
    if is_production_mode():
        raise RuntimeError(
            "Header-based identity is disabled in production. "
            "Use PoP (X-App-Signature / X-App-Nonce / X-App-Timestamp)."
        )
    tee_wallet = headers.get("x-tee-wallet", "")
    if tee_wallet:
        logger.debug("Using header-based identity (dev/sim mode)")
    return ClientIdentity(tee_wallet=tee_wallet)


def app_identity_from_signature(request) -> Optional[ClientIdentity]:
    """
    Extract app identity from PoP signature headers.
    Headers: X-App-Signature, X-App-Timestamp, X-App-Nonce

    X-App-Wallet may be provided as an optional hint, but is not required.
    The wallet is always recovered from the signature.
    """
    sig = request.headers.get("x-app-signature")
    ts = request.headers.get("x-app-timestamp")
    nonce_b64 = request.headers.get("x-app-nonce")

    wallet = request.headers.get("x-app-wallet")

    if not all([sig, ts, nonce_b64]):
        return None

    recovered = None
    message = None

    try:
        import base64
        nonce_bytes = base64.b64decode(nonce_b64)
        if not _nonce_store.validate_and_consume(nonce_bytes):
            raise RuntimeError("Invalid or expired nonce")

        # Enforce timestamp freshness to limit replay window.
        _require_fresh_timestamp(ts)

        if not _node_wallet:
            raise RuntimeError("KMS node wallet is not configured")

        # Message: NovaKMS:AppAuth:<Nonce>:<KMS_Wallet>:<Timestamp>
        node_wallet = _canonical_eth_wallet(_node_wallet)
        message = f"NovaKMS:AppAuth:{nonce_b64}:{node_wallet}:{ts}"

        recovered = recover_wallet_from_signature(message, sig)
        if not recovered:
            raise RuntimeError("Invalid app signature")

        recovered_wallet = _canonical_eth_wallet(recovered)

        # Optional explicit wallet header must match recovered signer.
        if wallet:
            header_wallet = _canonical_eth_wallet(wallet)
            if recovered_wallet != header_wallet:
                raise RuntimeError("App wallet header does not match signature")

        return ClientIdentity(
            tee_wallet=recovered_wallet,
            signature=sig
        )
    except Exception as exc:
        logger.warning(
            f"App PoP verification failed: {exc} | "
            f"Message='{message}' | "
            f"Recovered='{recovered}' | "
            f"HeaderWallet='{wallet}' | "
            f"NodeWallet='{_node_wallet}'"
        )
        raise RuntimeError(f"App PoP authentication failed: {exc}")


def authenticate_app(request, headers: dict) -> ClientIdentity:
    """
    Unified app authentication.

    - In production mode: require PoP signature.
    - In dev/sim mode: try PoP first, then fall back to header-based identity.
    """
    # Try PoP signature first (works in both production and dev mode)
    try:
        identity = app_identity_from_signature(request)
        if identity is not None:
            return identity
    except RuntimeError:
        # PoP failed - in production mode, propagate the error
        if is_production_mode():
            raise
        # In dev mode, fall through to header-based fallback
        pass

    if is_production_mode():
        raise RuntimeError(
            "Missing PoP authentication. "
            "Provide X-App-Signature / X-App-Nonce / X-App-Timestamp headers."
        )
    # Dev/sim mode: headers are acceptable as fallback
    return identity_from_headers(headers)


# =============================================================================
# Authorization result
# =============================================================================

@dataclass
class AuthResult:
    authorized: bool
    app_id: Optional[int] = None
    version_id: Optional[int] = None
    tee_pubkey: Optional[bytes] = None  # App's P-384 teePubkey for E2E encryption
    reason: Optional[str] = None


# =============================================================================
# Verifier
# =============================================================================

class AppAuthorizer:
    """
    Verifies that a client identity maps to an authorized Nova app.

    Steps (mirrors architecture doc §2.3):
      1. getInstanceByWallet(teeWallet)  →  instance
      2. instance must be ACTIVE and zkVerified
      3. (if require_app_id != 0) instance.app_id must match require_app_id
      4. getApp(appId) → app must be ACTIVE
      5. getVersion(appId, versionId) → must be ENROLLED
    """

    def __init__(self, registry: Optional[NovaRegistry] = None, require_app_id: int = 0):
        """
        Parameters
        ----------
        registry : NovaRegistry, optional
            The registry client to use for lookups.
        require_app_id : int, optional
            If non-zero, the instance's app_id must match this value.
            Use this for KMS peer verification (require_app_id=KMS_APP_ID).
        """
        self.registry = registry or NovaRegistry()
        self._require_app_id = require_app_id

    def verify(self, identity: ClientIdentity) -> AuthResult:
        """
        Synchronous verification.  Returns AuthResult with authorized=True
        if all checks pass, or authorized=False with a reason string.
        """
        if not identity.tee_wallet:
            return AuthResult(authorized=False, reason="Missing TEE wallet")

        # 1. Look up instance
        try:
            instance = self.registry.get_instance_by_wallet(identity.tee_wallet)
        except Exception as exc:
            logger.warning(f"Instance lookup failed for {identity.tee_wallet}: {exc}")
            return AuthResult(authorized=False, reason="Instance not found")

        logger.debug(
            f"AppAuthorizer: instance for {identity.tee_wallet}: "
            f"id={instance.instance_id}, app_id={instance.app_id} "
            f"(require={self._require_app_id}), "
            f"status={instance.status}, zk_verified={instance.zk_verified}, "
            f"version_id={instance.version_id}"
        )

        if instance.instance_id == 0:
            return AuthResult(authorized=False, reason="Instance not found")

        # 2. Instance must be ACTIVE + zkVerified
        if instance.status != InstanceStatus.ACTIVE:
            return AuthResult(authorized=False, reason="Instance not active")
        if not instance.zk_verified:
            return AuthResult(authorized=False, reason="Instance not zkVerified")

        # 3. If require_app_id is set, instance.app_id must match
        if self._require_app_id != 0 and instance.app_id != self._require_app_id:
            return AuthResult(
                authorized=False,
                reason=f"Instance app_id {instance.app_id} != required {self._require_app_id}"
            )

        # 4. App must be ACTIVE
        try:
            app = self.registry.get_app(instance.app_id)
        except Exception as exc:
            logger.warning(f"App lookup failed for appId={instance.app_id}: {exc}")
            return AuthResult(authorized=False, reason="App lookup failed")

        if app.status != AppStatus.ACTIVE:
            return AuthResult(authorized=False, reason="App not active")

        # 5. Version must be ENROLLED
        try:
            version = self.registry.get_version(instance.app_id, instance.version_id)
        except Exception as exc:
            logger.warning(f"Version lookup failed: {exc}")
            return AuthResult(authorized=False, reason="Version lookup failed")

        if version.status != VersionStatus.ENROLLED:
            return AuthResult(authorized=False, reason="Version not enrolled")

        # Get app's teePubkey for E2E response encryption
        app_tee_pubkey = getattr(instance, "tee_pubkey", b"") or b""

        return AuthResult(
            authorized=True,
            app_id=instance.app_id,
            version_id=instance.version_id,
            tee_pubkey=app_tee_pubkey,
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

    max_age = POP_MAX_AGE_SECONDS
    now = int(time.time())
    if abs(now - ts_int) > max_age:
        raise RuntimeError("Stale timestamp")



