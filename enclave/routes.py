"""
=============================================================================
KMS API Routes (routes.py)
=============================================================================

Defines the HTTP API for the Nova KMS service.

Endpoints (see architecture.md §3):
    /health          GET   – health check (no auth)
    /status          GET   – node + cluster status (no auth)
    /nodes           GET   – list KMS operators (no auth)
    /kms/derive      POST  – derive application key (App PoP + App Registry)

    /kms/data        GET   – read KV data           (App PoP + App Registry)
    /kms/data        PUT   – write KV data          (App PoP + App Registry)
    /kms/data        DELETE– delete KV data          (App PoP + App Registry)
    /sync            POST  – inter-node sync        (KMS peer PoP)

Security:
    - In production: app calls authenticate via PoP signatures.
    - In dev/sim: can fall back to x-tee-wallet / x-tee-measurement headers.
    - Rate limiting and request body size limits enforced by middleware.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

import config
from rate_limiter import TokenBucket

if TYPE_CHECKING:
    from auth import AppAuthorizer
    from data_store import DataStore
    from kdf import MasterSecretManager
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

_authorizer: Optional["AppAuthorizer"] = None
_kms_registry: Optional["KMSRegistryClient"] = None
_sync_manager: Optional["SyncManager"] = None
_node_info: dict = {}


def init(
    *,
    odyn,
    data_store,
    master_secret_mgr,

    authorizer,
    kms_registry,
    sync_manager,
    node_info: dict,
):
    global _odyn, _data_store, _master_secret_mgr
    global _authorizer, _kms_registry, _sync_manager, _node_info
    _odyn = odyn
    _data_store = data_store
    _master_secret_mgr = master_secret_mgr
    _authorizer = authorizer
    _kms_registry = kms_registry
    _sync_manager = sync_manager
    _node_info = node_info
    logger.info("Routes module initialized")


# =============================================================================
# Routers
# =============================================================================

router = APIRouter(tags=["kms"])

_nonce_rate_limiter = TokenBucket(config.NONCE_RATE_LIMIT_PER_MINUTE)


# =============================================================================
# Request / Response Models
# =============================================================================

class DeriveRequest(BaseModel):
    path: str
    context: str = ""
    length: int = 32




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

def _authorize_app(request: Request) -> dict:
    """
    Verify the calling app via PoP / dev headers and return detailed auth info.
    Raises HTTPException(403) on failure.
    """
    from auth import authenticate_app

    try:
        identity = authenticate_app(request, dict(request.headers))
    except RuntimeError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    if not identity.tee_wallet:
        raise HTTPException(status_code=403, detail="Missing TEE wallet in request")

    result = _authorizer.verify(identity)
    if not result.authorized:
        raise HTTPException(status_code=403, detail=result.reason or "Unauthorized")

    return {
        "app_id": result.app_id,
        "client_sig": identity.signature
    }


def _add_mutual_signature(response: Response, client_sig: Optional[str]):
    """If client used PoP signature, add a mutual response signature header."""
    if client_sig and _odyn and _node_info.get("tee_wallet"):
        try:
            # Create Response Message: NovaKMS:Response:<Sig_A>:<KMS_Wallet>
            resp_msg = f"NovaKMS:Response:{client_sig}:{_node_info['tee_wallet']}"
            sig_res = _odyn.sign_message(resp_msg)
            response.headers["X-KMS-Response-Signature"] = sig_res["signature"]
        except Exception as exc:
            logger.warning(f"Failed to sign mutual response: {exc}")


# =============================================================================
# /health
# =============================================================================

@router.get("/health")
def health_check():
    return {"status": "healthy"}


# =============================================================================
# /nonce  (PoP challenge)
# =============================================================================

@router.get("/nonce")
def get_nonce(request: Request):
    """
    Issue a one-time nonce for Proof-of-Possession (PoP) challenge-response.

    Nonces are single-use and expire after a short TTL.
    """
    from auth import issue_nonce

    client_ip = request.client.host if request.client else "unknown"
    if not _nonce_rate_limiter.allow(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")

    nonce = issue_nonce()
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
def derive_key(body: DeriveRequest, request: Request, response: Response):
    """Derive a deterministic key for the requesting app."""
    auth_info = _authorize_app(request)
    app_id = auth_info["app_id"]
    _add_mutual_signature(response, auth_info.get("client_sig"))

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
# /kms/data  (KV Store)
# =============================================================================

@router.get("/kms/data/{key}")
def get_data(key: str, request: Request, response: Response):
    """Read a key from the app's KV namespace."""
    auth_info = _authorize_app(request)
    app_id = auth_info["app_id"]
    _add_mutual_signature(response, auth_info.get("client_sig"))
    from data_store import DataKeyUnavailableError

    try:
        record = _data_store.get(app_id, key)
    except DataKeyUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if record is None:
        raise HTTPException(status_code=404, detail=f"Key not found: {key}")
    return {
        "app_id": app_id,
        "key": record.key,
        "value": base64.b64encode(record.value).decode() if record.value else None,
        "updated_at_ms": record.updated_at_ms,
    }


@router.get("/kms/data")
def list_keys(request: Request, response: Response):
    """List all keys in the app's KV namespace."""
    auth_info = _authorize_app(request)
    app_id = auth_info["app_id"]
    _add_mutual_signature(response, auth_info.get("client_sig"))
    keys = _data_store.keys(app_id)
    return {"app_id": app_id, "keys": keys, "count": len(keys)}


@router.put("/kms/data")
def put_data(body: DataPutRequest, request: Request, response: Response):
    """Write a key-value pair to the app's KV namespace."""
    auth_info = _authorize_app(request)
    app_id = auth_info["app_id"]
    _add_mutual_signature(response, auth_info.get("client_sig"))
    try:
        value_bytes = base64.b64decode(body.value)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 value")

    try:
        record = _data_store.put(app_id, body.key, value_bytes, ttl_ms=body.ttl_ms)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        from data_store import DataKeyUnavailableError
        if isinstance(exc, DataKeyUnavailableError):
            raise HTTPException(status_code=503, detail=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "app_id": app_id,
        "key": record.key,
        "updated_at_ms": record.updated_at_ms,
    }


@router.delete("/kms/data")
def delete_data(body: DataDeleteRequest, request: Request, response: Response):
    """Delete a key from the app's KV namespace."""
    auth_info = _authorize_app(request)
    app_id = auth_info["app_id"]
    _add_mutual_signature(response, auth_info.get("client_sig"))
    record = _data_store.delete(app_id, body.key)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Key not found: {body.key}")
    return {"app_id": app_id, "key": body.key, "deleted": True}


# =============================================================================
# /sync  (Inter-node synchronization)
# =============================================================================

@router.post("/sync")
def sync_endpoint(body: SyncRequest, request: Request, response: Response):
    """
    Handle incoming sync from a KMS peer.
    Verified via lightweight Proof-of-Possession (PoP) signatures as described
    in docs/kms-core-workflows.md.
    """
    if not _sync_manager:
        raise HTTPException(status_code=503, detail="Sync manager not available")

    # Extract Lightweight PoP headers
    kms_pop = {
        "wallet": request.headers.get("x-kms-wallet"),
        "signature": request.headers.get("x-kms-signature"),
        "timestamp": request.headers.get("x-kms-timestamp"),
        "nonce": request.headers.get("x-kms-nonce"),
    }

    # Pass HMAC signature from header
    signature = request.headers.get("x-sync-signature")
    
    result = _sync_manager.handle_incoming_sync(
        body.model_dump(exclude_unset=True), 
        signature=signature,
        kms_pop=kms_pop
    )

    if result.get("status") == "error":
        raise HTTPException(status_code=403, detail=result.get("reason", "Sync denied"))

    # Return server signature if available for mutual auth
    resp_sig = result.pop("_kms_response_sig", None)
    if resp_sig:
        response.headers["X-KMS-Peer-Signature"] = resp_sig

    return result
