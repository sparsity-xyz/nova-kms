"""
=============================================================================
KMS API Routes (routes.py)
=============================================================================

Defines the HTTP API for the Nova KMS service.

Endpoints (see architecture.md §3):
    /health          GET   – health check (no auth)
    /status          GET   – node + cluster status (no auth)
    /nodes           GET   – list KMS operators (no auth)
    /kms/derive      POST  – derive application key (RA-TLS + App Registry)
    /kms/sign_cert   POST  – sign CSR with KMS CA  (RA-TLS + App Registry)
    /kms/data        GET   – read KV data           (RA-TLS + App Registry)
    /kms/data        PUT   – write KV data          (RA-TLS + App Registry)
    /kms/data        DELETE– delete KV data          (RA-TLS + App Registry)
    /sync            POST  – inter-node sync        (RA-TLS KMS peer)

Security:
    - In production: attestation is extracted from mutual TLS (RA-TLS).
    - In dev/sim: falls back to X-Tee-Wallet / X-Tee-Measurement headers.
    - Rate limiting and request body size limits enforced by middleware.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

if TYPE_CHECKING:
    from auth import AppAuthorizer, KMSNodeVerifier
    from data_store import DataStore
    from kdf import CertificateAuthority, MasterSecretManager
    from kms_registry import KMSRegistryClient
    from odyn import Odyn
    from sync_manager import SyncManager

logger = logging.getLogger("nova-kms.routes")

# =============================================================================
# Shared references (set by app.py at startup)
# =============================================================================

_odyn: Optional["Odyn"] = None
_data_store: Optional["DataStore"] = None
_master_secret_mgr: Optional["MasterSecretManager"] = None
_ca: Optional["CertificateAuthority"] = None
_authorizer: Optional["AppAuthorizer"] = None
_node_verifier: Optional["KMSNodeVerifier"] = None
_kms_registry: Optional["KMSRegistryClient"] = None
_sync_manager: Optional["SyncManager"] = None
_node_info: dict = {}


def init(
    *,
    odyn,
    data_store,
    master_secret_mgr,
    ca,
    authorizer,
    node_verifier,
    kms_registry,
    sync_manager,
    node_info: dict,
):
    global _odyn, _data_store, _master_secret_mgr, _ca
    global _authorizer, _node_verifier, _kms_registry, _sync_manager, _node_info
    _odyn = odyn
    _data_store = data_store
    _master_secret_mgr = master_secret_mgr
    _ca = ca
    _authorizer = authorizer
    _node_verifier = node_verifier
    _kms_registry = kms_registry
    _sync_manager = sync_manager
    _node_info = node_info
    logger.info("Routes module initialized")


# =============================================================================
# Routers
# =============================================================================

router = APIRouter(tags=["kms"])


# =============================================================================
# Request / Response Models
# =============================================================================

class DeriveRequest(BaseModel):
    path: str
    context: str = ""
    length: int = 32


class SignCertRequest(BaseModel):
    csr: str  # Base64-encoded PEM
    validity_days: int = 365


class DataPutRequest(BaseModel):
    key: str
    value: str  # Base64-encoded bytes
    ttl_ms: int = 0


class DataDeleteRequest(BaseModel):
    key: str


class SyncRequest(BaseModel):
    type: str
    sender_wallet: str = ""
    data: Optional[dict] = None
    master_secret: Optional[str] = None
    ecdh_pubkey: Optional[str] = None


# =============================================================================
# Auth helper
# =============================================================================

def _authorize_app(request: Request) -> int:
    """
    Verify the calling app via RA-TLS attestation and return app_id.
    Raises HTTPException(403) on failure.

    In production: attestation is extracted from the mutual TLS handshake.
    In development: falls back to X-Tee-Wallet / X-Tee-Measurement headers.
    """
    from auth import get_attestation

    try:
        attestation = get_attestation(request, dict(request.headers))
    except RuntimeError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    if not attestation.tee_wallet:
        raise HTTPException(status_code=403, detail="Missing TEE wallet in request")

    result = _authorizer.verify(attestation)
    if not result.authorized:
        raise HTTPException(status_code=403, detail=result.reason or "Unauthorized")

    return result.app_id


def _verify_kms_peer(request: Request) -> str:
    """Verify the sync caller is a registered KMS peer. Returns wallet."""
    from auth import get_attestation

    try:
        attestation = get_attestation(request, dict(request.headers))
    except RuntimeError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    ok, reason = _node_verifier.verify_peer(attestation.tee_wallet)
    if not ok:
        raise HTTPException(status_code=403, detail=reason or "Unauthorized peer")
    return attestation.tee_wallet


# =============================================================================
# /health
# =============================================================================

@router.get("/health")
def health_check():
    return {"status": "healthy"}


# =============================================================================
# /nonce  (Attestation challenge)
# =============================================================================

@router.get("/nonce")
def get_nonce():
    """
    Issue a one-time nonce for Nitro attestation challenge-response.

    The client must embed this nonce into the Nitro attestation document
    (payload['nonce']) and present the attestation in the next authenticated
    request. Nonces are single-use and expire after a short TTL.
    """
    from auth import issue_attestation_challenge

    nonce = issue_attestation_challenge()
    return {"nonce": base64.b64encode(nonce).decode()}


# =============================================================================
# /status
# =============================================================================

@router.get("/status")
def get_status():
    """Return node status and cluster overview."""
    cluster_info = {}
    try:
        cluster_info = {
            "kms_app_id": _node_info.get("kms_app_id"),
            "registry_address": _node_info.get("kms_registry_address"),
            "total_operators": _kms_registry.operator_count() if _kms_registry else 0,
        }
    except Exception as exc:
        cluster_info["error"] = str(exc)

    return {
        "node": {
            "tee_wallet": _node_info.get("tee_wallet"),
            "node_url": _node_info.get("node_url"),
            "is_operator": _node_info.get("is_operator", False),
            "master_secret_initialized": _master_secret_mgr.is_initialized if _master_secret_mgr else False,
        },
        "cluster": cluster_info,
        "data_store": _data_store.stats() if _data_store else {},
    }


# =============================================================================
# /nodes
# =============================================================================

@router.get("/nodes")
def list_operators():
    """List KMS operators from on-chain registry."""
    if not _kms_registry:
        raise HTTPException(status_code=503, detail="KMS registry not available")
    try:
        operators = _kms_registry.get_operators()
        return {
            "operators": operators,
            "count": len(operators),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# =============================================================================
# /kms/derive  (Key Derivation)
# =============================================================================

@router.post("/kms/derive")
def derive_key(body: DeriveRequest, request: Request):
    """Derive a deterministic key for the requesting app."""
    app_id = _authorize_app(request)

    if not _master_secret_mgr or not _master_secret_mgr.is_initialized:
        raise HTTPException(status_code=503, detail="Master secret not initialized")

    derived = _master_secret_mgr.derive(
        app_id, body.path, length=body.length, context=body.context
    )
    return {
        "app_id": app_id,
        "path": body.path,
        "key": base64.b64encode(derived).decode(),
        "length": len(derived),
    }


# =============================================================================
# /kms/sign_cert  (CA)
# =============================================================================

@router.post("/kms/sign_cert")
def sign_cert(body: SignCertRequest, request: Request):
    """Sign a CSR with the KMS CA."""
    _authorize_app(request)

    if not _ca:
        raise HTTPException(status_code=503, detail="CA not available")

    try:
        csr_pem = base64.b64decode(body.csr)
        cert_pem = _ca.sign_csr(csr_pem, validity_days=body.validity_days)
        ca_cert_pem = _ca.get_ca_cert_pem()
        return {
            "certificate": base64.b64encode(cert_pem).decode(),
            "ca_certificate": base64.b64encode(ca_cert_pem).decode(),
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        logger.error(f"CSR signing failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


# =============================================================================
# /kms/data  (KV Store)
# =============================================================================

@router.get("/kms/data/{key}")
def get_data(key: str, request: Request):
    """Read a key from the app's KV namespace."""
    app_id = _authorize_app(request)
    record = _data_store.get(app_id, key)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Key not found: {key}")
    return {
        "app_id": app_id,
        "key": record.key,
        "value": base64.b64encode(record.value).decode() if record.value else None,
        "updated_at_ms": record.updated_at_ms,
    }


@router.get("/kms/data")
def list_keys(request: Request):
    """List all keys in the app's KV namespace."""
    app_id = _authorize_app(request)
    keys = _data_store.keys(app_id)
    return {"app_id": app_id, "keys": keys, "count": len(keys)}


@router.put("/kms/data")
def put_data(body: DataPutRequest, request: Request):
    """Write a key-value pair to the app's KV namespace."""
    app_id = _authorize_app(request)
    try:
        value_bytes = base64.b64decode(body.value)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 value")

    try:
        record = _data_store.put(app_id, body.key, value_bytes, ttl_ms=body.ttl_ms)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    return {
        "app_id": app_id,
        "key": record.key,
        "updated_at_ms": record.updated_at_ms,
    }


@router.delete("/kms/data")
def delete_data(body: DataDeleteRequest, request: Request):
    """Delete a key from the app's KV namespace."""
    app_id = _authorize_app(request)
    record = _data_store.delete(app_id, body.key)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Key not found: {body.key}")
    return {"app_id": app_id, "key": body.key, "deleted": True}


# =============================================================================
# /sync  (Inter-node synchronization)
# =============================================================================

@router.post("/sync")
def sync_endpoint(body: SyncRequest, request: Request):
    """
    Handle incoming sync from a KMS peer.
    In production, the peer is verified via mutual RA-TLS.
    HMAC signature is validated when available.
    """
    _verify_kms_peer(request)

    if not _sync_manager:
        raise HTTPException(status_code=503, detail="Sync manager not available")

    # Pass HMAC signature from header for verification
    signature = request.headers.get("x-sync-signature")
    return _sync_manager.handle_incoming_sync(body.model_dump(), signature=signature)
