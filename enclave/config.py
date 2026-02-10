"""enclave/config.py

Centralized configuration for the Nova KMS enclave application.

Production deployments typically bake these values into the enclave image.

For local development and simulation, a small set of values (notably
`IN_ENCLAVE`) may be overridden via environment variables by the helper
scripts under `scripts/`.
"""

from __future__ import annotations

import os

# =============================================================================
# Environment Detection
# =============================================================================

# Treat Nitro Enclave as the safe default.
#
# Local simulation scripts override this with `IN_ENCLAVE=false` so that
# simulation mode can be enabled (see simulation.is_simulation_mode()).
_in_enclave_env = os.getenv("IN_ENCLAVE", "").strip().lower()
if _in_enclave_env in ("1", "true", "yes"):
    IN_ENCLAVE: bool = True
elif _in_enclave_env in ("0", "false", "no"):
    IN_ENCLAVE = False
else:
    IN_ENCLAVE = True

# =============================================================================
# Chain / RPC
# =============================================================================

CHAIN_ID: int = 84532  # Base Sepolia

# Minimum number of block confirmations before trusting eth_call results.
# Protects against reorgs that could change on-chain operator sets.
CONFIRMATION_DEPTH: int = 6

# =============================================================================
# On-chain Contract Addresses
# =============================================================================

# NovaAppRegistry proxy address (UUPS upgradeable)
NOVA_APP_REGISTRY_ADDRESS: str = "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"

# KMSRegistry contract address
KMS_REGISTRY_ADDRESS: str = "0x934744f9D931eF72d7fa10b07CD46BCFA54e8d88"

# KMS application ID assigned by NovaAppRegistry
KMS_APP_ID: int = 43

# =============================================================================
# Simulation Mode
# =============================================================================
# Hardcoded to False for production Enclave
SIMULATION_MODE: bool = False

# Preconfigured peer list for simulation.
SIM_PEERS: list = []

# Deterministic master secret hex for reproducible dev runs (optional).
SIM_MASTER_SECRET_HEX: str = ""

# =============================================================================
# Security — Authentication
# =============================================================================

# In production (IN_ENCLAVE=True), AppAuthorizer can require code measurement
# for non-PoP identity paths. For PoP, wallet→measurement binding is enforced
# at enrollment time on-chain.
REQUIRE_MEASUREMENT: bool = IN_ENCLAVE

# Max age (seconds) for PoP timestamps and the nonce TTL.
POP_MAX_AGE_SECONDS: int = 120

# In production (IN_ENCLAVE=True), never fall back to plaintext storage when
# per-app encryption keys are unavailable.
ALLOW_PLAINTEXT_FALLBACK: bool = False

# =============================================================================
# Security — Sync Integrity
# =============================================================================

# Maximum clock skew (in ms) tolerated for LWW merge from sync peers.
# Records with updated_at_ms more than this far from local time are rejected.
MAX_CLOCK_SKEW_MS: int = 30000  # 30 seconds

# Maximum payload size (bytes) accepted on /sync endpoint.
MAX_SYNC_PAYLOAD_BYTES: int = 50 * 1024 * 1024  # 50 MB

# =============================================================================
# Security — Rate Limiting
# =============================================================================

# Global rate limit: max requests per minute across all endpoints
RATE_LIMIT_PER_MINUTE: int = 120

# Dedicated /nonce rate limit (per-IP). Lower than the global limit to reduce
# nonce-store churn under abuse.
NONCE_RATE_LIMIT_PER_MINUTE: int = 30

# Hard cap on active nonces held in memory.
MAX_NONCES: int = 4096

# Maximum request body size in bytes for non-sync endpoints
MAX_REQUEST_BODY_BYTES: int = 2 * 1024 * 1024  # 2 MB

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
REGISTRY_CACHE_TTL_SECONDS: int = 60
