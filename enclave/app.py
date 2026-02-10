"""
=============================================================================
Nova KMS - Main Application (app.py)
=============================================================================

Entry point for the distributed Key Management Service running in
a TEE (Nitro Enclave on Nova Platform).  Follows the Nova app-template
pattern (FastAPI + Uvicorn).

Supports two modes:

**Production** (default):
  1. Wait for Helios light-client RPC
  2. Initialize Odyn SDK → get TEE wallet address
  3. Discover peers via KMSRegistry operators + NovaAppRegistry instance lookup
  4. Initialize or receive master secret (via sealed ECDH key exchange)
  5. Start background sync scheduler
  6. Mount API routes with rate limiting and body size limits

**Simulation** (``SIMULATION_MODE=1``):
  Skips Helios/Odyn, uses in-memory fake registries and a deterministic
  master secret.  Suitable for local development and multi-node testing.
  **Cannot be activated when running inside an enclave** (IN_ENCLAVE=true).

KMS nodes do NOT submit any on-chain transactions.  Operator registration
is managed entirely through NovaAppRegistry → KMSRegistry callbacks.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from web3 import Web3

import config
import routes
from auth import AppAuthorizer
from data_store import DataStore
from kdf import MasterSecretManager
from probe import find_healthy_peer
from rate_limiter import RateLimitMiddleware
from sync_manager import PeerCache, SyncManager

# =============================================================================
# Logging
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("nova-kms")

# =============================================================================
# Module-level singletons (accessible from sync_manager for master secret)
# =============================================================================

master_secret_mgr = MasterSecretManager()

# =============================================================================
# Lifespan — Simulation Mode
# =============================================================================


def _startup_simulation() -> dict:
    """
    Build all components from simulation fakes.  Returns a dict with
    everything the lifespan needs to wire up.
    """
    from simulation import build_sim_components, get_sim_port

    def data_key_callback(app_id: int) -> bytes:
        return master_secret_mgr.derive(app_id, "data_key")

    sim = build_sim_components()

    tee_wallet = sim["tee_wallet"]
    node_url = sim["node_url"]
    kms_registry = sim["kms_registry"]
    nova_registry = sim["nova_registry"]
    authorizer = sim["authorizer"]
    odyn = sim["odyn"]
    from auth import set_node_wallet
    set_node_wallet(tee_wallet)

    node_info = {
        "tee_wallet": tee_wallet,
        "node_url": node_url,
        "is_operator": True,
        "kms_app_id": config.KMS_APP_ID or 9999,
        "kms_registry_address": "simulation",
        "simulation_mode": True,
    }

    data_store = DataStore(node_id=tee_wallet, key_callback=data_key_callback)
    peer_cache = PeerCache(kms_registry_client=kms_registry, nova_registry=nova_registry)
    sync_manager = SyncManager(data_store, tee_wallet, peer_cache, odyn=odyn)

    # Master secret: try peers first, fall back to deterministic sim secret
    peers = peer_cache.get_peers(exclude_wallet=tee_wallet)
    healthy_peer = find_healthy_peer(
        [{"node_url": p["node_url"], "tee_wallet_address": p["tee_wallet_address"]} for p in peers],
        exclude_wallet=tee_wallet,
        timeout=2,
    )
    if healthy_peer:
        logger.info(f"[SIM] Requesting master secret from peer {healthy_peer['node_url']}")
        secret = sync_manager.request_master_secret(healthy_peer["node_url"])
        if secret:
            master_secret_mgr.initialize_from_peer(secret)
            sync_manager.request_snapshot(healthy_peer["node_url"])

    if not master_secret_mgr.is_initialized:
        master_secret_mgr.initialize_from_peer(sim["master_secret"])
        logger.info("[SIM] Master secret initialized from simulation config")



    return {
        "odyn": odyn,
        "data_store": data_store,
        "authorizer": authorizer,
        "kms_registry": kms_registry,
        "sync_manager": sync_manager,
        "node_info": node_info,
    }


# =============================================================================
# Lifespan — Production Mode
# =============================================================================


def _startup_production() -> dict:
    """
    Standard production startup using Helios, Odyn, and on-chain contracts.
    """
    from chain import wait_for_helios
    from kms_registry import KMSRegistryClient
    from nova_registry import NovaRegistry
    from odyn import Odyn

    odyn = Odyn()

    def data_key_callback(app_id: int) -> bytes:
        return master_secret_mgr.derive(app_id, "data_key")

    # 1. Wait for Helios RPC
    try:
        wait_for_helios(timeout=60)
    except Exception as exc:
        logger.warning(f"Helios sync wait skipped/failed: {exc}")

    # 2. Get TEE identity
    tee_wallet = "0x0000000000000000000000000000000000000000"
    try:
        tee_wallet = Web3.to_checksum_address(odyn.eth_address())
        logger.info(f"TEE wallet: {tee_wallet}")
    except Exception as exc:
        logger.error(f"Failed to get TEE wallet: {exc}")

    # 3. Initialize on-chain clients
    kms_registry: KMSRegistryClient | None = None
    nova_registry: NovaRegistry | None = None
    node_info: dict = {
        "tee_wallet": tee_wallet,
        "node_url": os.getenv("NODE_URL", ""),
        "kms_app_id": config.KMS_APP_ID,
        "kms_registry_address": config.KMS_REGISTRY_ADDRESS,
    }

    try:
        if config.KMS_REGISTRY_ADDRESS:
            kms_registry = KMSRegistryClient()
        if config.NOVA_APP_REGISTRY_ADDRESS:
            nova_registry = NovaRegistry()
    except Exception as exc:
        logger.warning(f"Contract client init failed: {exc}")

    # 4. Check if this node is a registered operator
    is_operator = False
    if kms_registry:
        try:
            is_operator = kms_registry.is_operator(tee_wallet)
            if is_operator:
                logger.info("This node is a registered KMS operator")
            else:
                logger.warning("This node is NOT a registered KMS operator")
        except Exception as exc:
            logger.warning(f"Operator check failed: {exc}")
    node_info["is_operator"] = is_operator

    # 5. Initialize data store & sync
    data_store = DataStore(node_id=tee_wallet, key_callback=data_key_callback)
    peer_cache = PeerCache(kms_registry_client=kms_registry, nova_registry=nova_registry)
    sync_manager = SyncManager(data_store, tee_wallet, peer_cache, odyn=odyn)

    # 6. Master secret: verify peers and sync (workflow steps 4.1–4.5)
    # Uses strict initialization logic with mutual PoP auth to prevent split-brain.
    sync_manager.wait_for_master_secret(
        kms_registry=kms_registry if kms_registry else None,
        master_secret_mgr=master_secret_mgr,
    )

    # 7. CA & auth

    authorizer = AppAuthorizer(registry=nova_registry)
    from auth import set_node_wallet
    set_node_wallet(tee_wallet)
    return {
        "odyn": odyn,
        "data_store": data_store,
        "authorizer": authorizer,
        "kms_registry": kms_registry,
        "sync_manager": sync_manager,
        "node_info": node_info,
    }


# =============================================================================
# Lifespan
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown lifecycle."""

    from simulation import is_simulation_mode

    sim_mode = is_simulation_mode()
    mode_label = "SIMULATION" if sim_mode else "PRODUCTION"

    # Safety guard: refuse simulation mode inside a real enclave
    if sim_mode and config.IN_ENCLAVE:
        logger.critical(
            "SECURITY: SIMULATION_MODE=1 is forbidden when IN_ENCLAVE=true. "
            "Refusing to start.  Disable SIMULATION_MODE or run outside the enclave."
        )
        raise RuntimeError("Simulation mode cannot be used inside an enclave")

    logger.info(f"=== Nova KMS starting ({mode_label}) ===")

    if sim_mode:
        components = _startup_simulation()
    else:
        components = _startup_production()

    # 8. Initialize routes
    routes.init(
        odyn=components.get("odyn"),
        data_store=components["data_store"],
        master_secret_mgr=master_secret_mgr,

        authorizer=components["authorizer"],
        kms_registry=components["kms_registry"],
        sync_manager=components["sync_manager"],
        node_info=components["node_info"],
    )
    app.include_router(routes.router)

    # 9. Set sync HMAC key if master secret is available
    if master_secret_mgr.is_initialized:
        components["sync_manager"].set_sync_key(master_secret_mgr.get_sync_key())

    # 10. Background scheduler
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        components["sync_manager"].push_deltas,
        "interval",
        seconds=config.SYNC_INTERVAL_SECONDS,
    )
    # Periodically refresh the operator list from the KMS registry
    # (workflow step: "Periodically repeat step 1 to refresh the operator list")
    scheduler.add_job(
        components["sync_manager"].peer_cache.refresh,
        "interval",
        seconds=config.PEER_CACHE_TTL_SECONDS,
    )
    scheduler.start()
    logger.info(f"=== Nova KMS started successfully ({mode_label}) ===")

    yield

    # Shutdown
    scheduler.shutdown(wait=False)
    logger.info("=== Nova KMS shutdown ===")


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Nova KMS",
    description="Distributed Key Management Service for Nova Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
cors_origins_env = os.getenv("CORS_ORIGINS", "*")
cors_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()] or ["*"]
allow_all = "*" in cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[] if allow_all else cors_origins,
    allow_origin_regex=".*" if allow_all else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting & body size enforcement
app.add_middleware(RateLimitMiddleware)

# =============================================================================
# Development Entry Point
# =============================================================================

if __name__ == "__main__":
    from simulation import is_simulation_mode, get_sim_port

    port = get_sim_port() if is_simulation_mode() else 8000
    uvicorn.run(app, host="0.0.0.0", port=port)
