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
import threading
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Request, Response
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

_service_state_lock = threading.Lock()
_service_available: bool = False
_service_unavailable_reason: str = "initializing"


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


def set_service_availability(available: bool, *, reason: str = "") -> None:
    """Set whether this node should accept incoming HTTP requests.

    When unavailable, all incoming requests should return 503.
    """
    global _service_available, _service_unavailable_reason
    with _service_state_lock:
        _service_available = bool(available)
        _service_unavailable_reason = reason or ("" if available else "unavailable")


def get_service_availability() -> tuple[bool, str]:
    with _service_state_lock:
        return _service_available, _service_unavailable_reason


def _require_service_available(request: Request) -> None:
    # Allow CORS preflight to proceed so clients see a proper 503 on real requests.
    if request.method.upper() == "OPTIONS":
        return
    available, reason = get_service_availability()
    if not available:
        raise HTTPException(status_code=503, detail={"error": "Service unavailable", "reason": reason})


# =============================================================================
# Routers
# =============================================================================

router = APIRouter(tags=["kms"], dependencies=[Depends(_require_service_available)])

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

@router.get("/")
def api_overview():
    """Return a human-friendly API overview.

    This endpoint is meant as a lightweight, machine-readable landing page.
    """
    return {
        "service": "Nova KMS",
        "docs": {
            "openapi_json": "/openapi.json",
            "swagger_ui": "/docs",
            "redoc": "/redoc",
        },
        "auth": {
            "app_pop_headers": [
                "x-app-signature",
                "x-app-nonce",
                "x-app-timestamp",
                "x-app-wallet (optional)",
            ],
            "dev_identity_headers": ["x-tee-wallet"],
            "mutual_response_header": "X-KMS-Response-Signature (optional)",
        },
        "endpoints": [
            {"method": "GET", "path": "/health", "auth": "none", "description": "Health check"},
            {"method": "GET", "path": "/status", "auth": "none", "description": "Node + cluster status"},
            {"method": "GET", "path": "/nonce", "auth": "none", "description": "Issue one-time PoP nonce"},
            {"method": "GET", "path": "/nodes", "auth": "none", "description": "List KMS operators"},
            {"method": "POST", "path": "/kms/derive", "auth": "app PoP", "description": "Derive per-app key"},
            {"method": "GET", "path": "/kms/data/{key}", "auth": "app PoP", "description": "Read app-scoped KV"},
            {"method": "PUT", "path": "/kms/data", "auth": "app PoP", "description": "Write app-scoped KV"},
            {"method": "DELETE", "path": "/kms/data", "auth": "app PoP", "description": "Delete app-scoped KV"},
            {"method": "POST", "path": "/sync", "auth": "peer PoP + HMAC", "description": "Inter-node sync"},
        ],
    }

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
        # Use PeerCache (NovaAppRegistry-sourced) for instance count
        peer_count = 0
        if _sync_manager and getattr(_sync_manager, "peer_cache", None):
            peer_count = len(_sync_manager.peer_cache.get_peers())
        cluster_info = {
            "kms_app_id": _node_info.get("kms_app_id"),
            "registry_address": _node_info.get("kms_registry_address"),
            "total_instances": peer_count,
        }
    except Exception as exc:
        cluster_info["error"] = str(exc)

    return {
        "node": {
            "tee_wallet": _node_info.get("tee_wallet"),
            "node_url": _node_info.get("node_url"),
            "is_operator": _node_info.get("is_operator", False),
            "service_available": get_service_availability()[0],
            "master_secret": (
                {
                    "state": getattr(_master_secret_mgr, "init_state", "uninitialized")
                    if _master_secret_mgr and _master_secret_mgr.is_initialized
                    else "uninitialized",
                    "synced_from": getattr(_master_secret_mgr, "synced_from", None) if _master_secret_mgr else None,
                }
            ),
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
    """List KMS instances from NovaAppRegistry (PeerCache).

    Node list is sourced exclusively from NovaAppRegistry via PeerCache
    (KMS_APP_ID → ENROLLED versions → ACTIVE instances).
    The KMSRegistry operator list is NOT used.

    M2 fix: no longer performs synchronous outbound HTTP probes to every
    peer inside this request handler.  Connectivity data comes from the
    PeerCache which is refreshed asynchronously by ``node_tick``.
    """
    peer_cache = None
    nova_registry = None
    if _sync_manager and getattr(_sync_manager, "peer_cache", None):
        peer_cache = _sync_manager.peer_cache
        nova_registry = _sync_manager.peer_cache.nova_registry

    if not peer_cache:
        raise HTTPException(status_code=503, detail="Peer discovery not available")

    try:
        peers = peer_cache.get_peers()
        enriched = []
        for p in peers:
            wallet = p.get("tee_wallet_address", "")
            instance_info: dict = {}
            if nova_registry:
                try:
                    inst = nova_registry.get_instance_by_wallet(wallet)
                    status_val = getattr(inst.status, "value", inst.status)
                    status_name = getattr(inst.status, "name", str(inst.status))
                    instance_info = {
                        "instance_id": inst.instance_id,
                        "app_id": inst.app_id,
                        "version_id": inst.version_id,
                        "operator": inst.operator,
                        "instance_url": inst.instance_url,
                        "tee_wallet": inst.tee_wallet_address,
                        "zk_verified": inst.zk_verified,
                        "instance_status": {"value": status_val, "name": status_name},
                        "registered_at": inst.registered_at,
                    }
                except Exception as exc:
                    instance_info = {"error": str(exc)}

            connection_info = {
                "in_peer_cache": True,
                "cached_status": (
                    getattr(p.get("status"), "name", str(p.get("status")))
                    if p.get("status") is not None else None
                ),
            }

            enriched.append({
                "operator": wallet,
                "instance": instance_info,
                "connection": connection_info,
            })

        return {
            "operators": enriched,
            "count": len(enriched),
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
    from data_store import DataKeyUnavailableError, DecryptionError

    try:
        record = _data_store.get(app_id, key)
    except DataKeyUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except DecryptionError as exc:
        raise HTTPException(status_code=503, detail=f"Data decryption failed: {exc}")
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
