"""
Centralized configuration for the Nova KMS enclave application.

Edit these constants directly. Environment variables are only used for
IN_ENCLAVE detection (handled in odyn.py and chain.py) and SIMULATION_MODE.
"""

from __future__ import annotations

import os

# =============================================================================
# Environment Detection
# =============================================================================

IN_ENCLAVE: bool = os.getenv("IN_ENCLAVE", "False").lower() == "true"

# =============================================================================
# Chain / RPC
# =============================================================================

CHAIN_ID: int = 84532  # Base Sepolia

# Minimum number of block confirmations before trusting eth_call results.
# Protects against reorgs that could change on-chain operator sets.
CONFIRMATION_DEPTH: int = int(os.getenv("CONFIRMATION_DEPTH", "6"))

# =============================================================================
# On-chain Contract Addresses
# =============================================================================

# NovaAppRegistry proxy address (UUPS upgradeable)
NOVA_APP_REGISTRY_ADDRESS: str = os.getenv("NOVA_APP_REGISTRY_ADDRESS", "")

# KMSRegistry contract address
KMS_REGISTRY_ADDRESS: str = os.getenv("KMS_REGISTRY_ADDRESS", "")

# KMS application ID assigned by NovaAppRegistry
KMS_APP_ID: int = int(os.getenv("KMS_APP_ID", "0"))

# =============================================================================
# Simulation Mode
# =============================================================================
# Toggle via env var (SIMULATION_MODE=1) or set here.  When True, the node
# skips Helios/Odyn and uses in-memory fake registries configured below.

SIMULATION_MODE: bool = os.getenv("SIMULATION_MODE", "").strip().lower() in ("1", "true", "yes")

# Preconfigured peer list for simulation.  Each entry is a SimPeer-like dict.
# If empty, the defaults in simulation.py are used.
# Format: [SimPeer(tee_wallet="0x...", node_url="http://localhost:8001"), ...]
SIM_PEERS: list = []

# Deterministic master secret hex for reproducible dev runs (optional).
# If empty, a default deterministic value is used.
SIM_MASTER_SECRET_HEX: str = ""

# =============================================================================
# Security — Authentication
# =============================================================================

# In production (IN_ENCLAVE=True), AppAuthorizer can require code measurement
# for non-PoP identity paths. For PoP, wallet→measurement binding is enforced
# at enrollment time on-chain.
REQUIRE_MEASUREMENT: bool = IN_ENCLAVE

# Max age (seconds) for PoP timestamps and the nonce TTL.
POP_MAX_AGE_SECONDS: int = int(os.getenv("POP_MAX_AGE_SECONDS",
                                          os.getenv("ATTESTATION_MAX_AGE_SECONDS", "120")))

# In production (IN_ENCLAVE=True), never fall back to plaintext storage when
# per-app encryption keys are unavailable.
ALLOW_PLAINTEXT_FALLBACK: bool = os.getenv(
    "ALLOW_PLAINTEXT_FALLBACK",
    "true" if not IN_ENCLAVE else "false",
).strip().lower() in ("1", "true", "yes")

# =============================================================================
# Security — Sync Integrity
# =============================================================================

# Maximum clock skew (in ms) tolerated for LWW merge from sync peers.
# Records with updated_at_ms more than this far from local time are rejected.
MAX_CLOCK_SKEW_MS: int = int(os.getenv("MAX_CLOCK_SKEW_MS", "30000"))  # 30 seconds

# Maximum payload size (bytes) accepted on /sync endpoint.
MAX_SYNC_PAYLOAD_BYTES: int = int(os.getenv("MAX_SYNC_PAYLOAD_BYTES", str(50 * 1024 * 1024)))  # 50 MB

# =============================================================================
# Security — Rate Limiting
# =============================================================================

# Global rate limit: max requests per minute across all endpoints
RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "120"))

# Dedicated /nonce rate limit (per-IP). Lower than the global limit to reduce
# nonce-store churn under abuse.
NONCE_RATE_LIMIT_PER_MINUTE: int = int(os.getenv("NONCE_RATE_LIMIT_PER_MINUTE", "30"))

# Hard cap on active nonces held in memory.
MAX_NONCES: int = int(os.getenv("MAX_NONCES", "4096"))

# Maximum request body size in bytes for non-sync endpoints
MAX_REQUEST_BODY_BYTES: int = int(os.getenv("MAX_REQUEST_BODY_BYTES", str(2 * 1024 * 1024)))  # 2 MB

# =============================================================================
# Security — Peer URL Validation
# =============================================================================

# Only these URL schemes are allowed for outbound peer communication.
ALLOWED_PEER_URL_SCHEMES: list = ["https"]

# In dev/sim mode, also allow plain http.
if not IN_ENCLAVE:
    ALLOWED_PEER_URL_SCHEMES = ["http", "https"]

# =============================================================================
# KMS Behaviour
# =============================================================================

# =============================================================================
# Data Store Limits
# =============================================================================

# Maximum size of a single value in bytes (1 MB)
MAX_VALUE_SIZE: int = 1_048_576

# Per-app maximum total storage in bytes (10 MB)
MAX_APP_STORAGE: int = 10_485_760

# Default TTL for records (0 = no expiry)
DEFAULT_TTL_MS: int = 0

# =============================================================================
# Sync
# =============================================================================

# Interval in seconds for periodic anti-entropy sync
SYNC_INTERVAL_SECONDS: int = 60

# Maximum number of delta records per sync push
SYNC_BATCH_SIZE: int = 500

# Peer cache TTL in seconds
PEER_CACHE_TTL_SECONDS: int = 120

# =============================================================================
# Nova Registry Cache
# =============================================================================

# TTL in seconds for caching NovaAppRegistry authorization results.
# Reduces on-chain calls during high-frequency API requests.
REGISTRY_CACHE_TTL_SECONDS: int = int(os.getenv("REGISTRY_CACHE_TTL_SECONDS", "60"))
