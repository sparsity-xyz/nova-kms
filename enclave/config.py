"""enclave/config.py

Centralized configuration for the Nova KMS enclave application.

This file defines the runtime configuration. In production (Nitro Enclave), these values
are typically "baked in" to the enclave image to ensure security and immutability.
Environment variables are sparingly used, primarily for local debugging and overrides.

Key Design Principles:
  1. Security by Default: Defaults are set for the hardened Enclave environment.
  2. Immutability: Critical addresses (Contracts) are hardcoded to act as trust roots.
  3. Environment Support: `IN_ENCLAVE` flag switches strictly between Enclave and Local behavior.
"""

from __future__ import annotations

import os

# =============================================================================
# Environment Detection
# =============================================================================

# LOG_LEVEL:
# Controls the verbosity of application logging.
# - DEBUG: Output detailed internal state transitions (e.g. peer scanning, sync logic).
# - INFO:  Standard production level, logs major events (startup, shutdown, errors).
# - WARNING/ERROR: Only log abnormal operational events.
#
# Used in: app.py (logging.basicConfig)
LOG_LEVEL = "DEBUG"

# IN_ENCLAVE:
# The master switch for security modes, determined by the `IN_ENCLAVE` env var.
# - True (Production / Enclave):
#     - Enforces PoP (Proof of Possession) authentication.
#     - Disables text/plain master secret exchange (requires sealed ECDH).
#     - Enforces HTTPS for peer communication.
#     - Uses real Odyn SDK for TEE interactions.
#
# - False (Local Development):
#     - Allows HTTP for peers.
#     - Allows plaintext master secret (for debugging).
#     - Enables header-based identity injection (X-Tee-Wallet).
#     - Uses Mock Odyn SDK.
#
# Used in: config.py, auth.py, odyn.py, kms_registry.py
_in_enclave_env = os.getenv("IN_ENCLAVE", "").strip().lower()
if _in_enclave_env in ("1", "true", "yes"):
    IN_ENCLAVE: bool = True
elif _in_enclave_env in ("0", "false", "no"):
    IN_ENCLAVE = False
else:
    IN_ENCLAVE = True  # Safe default

# =============================================================================
# Chain & Trust Roots
# =============================================================================

# CHAIN_ID:
# The Ethereum Chain ID where the Nova contracts reside.
# 84532 = Base Sepolia Testnet.
# Used in: chain.py (to validate transaction signatures or network matching)
CHAIN_ID: int = 84532


# =============================================================================
# Contract Addresses (Trust Roots)
# =============================================================================
# These addresses are hardcoded to establish a Root of Trust.
# Changing them requires rebuilding the enclave image, which ensures that a running
# enclave cannot be tricked into using a malicious registry via simplistic env var manipulation.

# NOVA_APP_REGISTRY_ADDRESS:
# The storage contract that maintains the list of:
# 1. Registered Apps (including KMS itself).
# 2. Approved Versions (code measurements).
# 3. Active Instances (TEE nodes and their attestations).
#
# Used in: nova_registry.py (to instantiate the contract wrapper)
NOVA_APP_REGISTRY_ADDRESS: str = "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"

# KMS_REGISTRY_ADDRESS:
# The governance contract specifically for the KMS network.
# 1. Manages the Allowlist of KMS Operators (who can run nodes).
# 2. Stores the Master Secret Hash (commit on chain for consistency).
#
# Used in: kms_registry.py (client), app.py (bootstrap checks)
KMS_REGISTRY_ADDRESS: str = "0x934744f9D931eF72d7fa10b07CD46BCFA54e8d88"

# KMS_APP_ID:
# The unique Integer ID assigned to the KMS application within the Nova ecosystem.
# Used to identify "us" (KMS peers) versus "clients" (other apps).
#
# Used in: app.py (identity check), sync_manager.py (peer discovery)
KMS_APP_ID: int = 43

# =============================================================================
# Security & Authentication
# =============================================================================

# POP_MAX_AGE_SECONDS:
# Defines the validity window for a PoP (Proof of Possession) signature.
# Clients sign a timestamp; if the timestamp is older than this (or in the future),
# the request is rejected. This mitigates replay attacks.
#
# Used in: auth.py (verify_wallet_signature / _require_fresh_timestamp)
POP_MAX_AGE_SECONDS: int = 120



# =============================================================================
# Sync & Integrity
# =============================================================================

# MAX_CLOCK_SKEW_MS:
# The maximum allowed difference between a peer's timestamp and local time during sync.
# If a record's `updated_at_ms` implies it is > 15 minutes in the future, it is rejected.
# This prevents a misconfigured or malicious peer from writing "future" data that
# can never be overwritten by correct updates (Last-Write-Wins).
#
# Used in: data_store.py (merge_record conflict resolution)
MAX_CLOCK_SKEW_MS: int = 5000  # 5 seconds

# MAX_SYNC_PAYLOAD_BYTES:
# The maximum allowed body size for the specific `/sync` endpoint.
# Sync payloads can be large (many records), so this limit is higher than normal.
#
# Used in: rate_limiter.py (RateLimitMiddleware custom check for /sync path)
MAX_SYNC_PAYLOAD_BYTES: int = 50 * 1024 * 1024  # 50 MB

# =============================================================================
# Rate Limiting (DDoS Protection)
# =============================================================================

# RATE_LIMIT_PER_MINUTE:
# The default number of requests allowed per minute per IP address.
# A basic protection against flooding.
#
# Used in: rate_limiter.py (TokenBucket initialization)
RATE_LIMIT_PER_MINUTE: int = 120

# NONCE_RATE_LIMIT_PER_MINUTE:
# A stricter rate limit specifically for the `/nonce` endpoint.
# Generating nonces consumes memory (NonceStore), so we limit it more aggressively.
#
# Used in: routes.py (/nonce endpoint decorator)
NONCE_RATE_LIMIT_PER_MINUTE: int = 30

# MAX_NONCES:
# The maximum capacity of the in-memory NonceStore.
# If exceeded, oldest nonces are evicted. Limits memory usage for auth tracking.
#
# Used in: auth.py (NonceStore initialization)
MAX_NONCES: int = 4096

# MAX_REQUEST_BODY_BYTES:
# The default maximum size for HTTP request bodies (e.g. key setting, misc posts).
# Prevents memory exhaustion attacks via large payloads.
#
# Used in: rate_limiter.py (RateLimitMiddleware default check)
MAX_REQUEST_BODY_BYTES: int = 2 * 1024 * 1024  # 2 MB

# =============================================================================
# Networking
# =============================================================================

# ALLOWED_PEER_URL_SCHEMES:
# Defines which protocols are valid for peer node URLs.
# - Production: ["https"] only.
# - Dev: ["http", "https"] (determined by IN_ENCLAVE flag).
#
# Used in: url_validator.py (validate_peer_url)
ALLOWED_PEER_URL_SCHEMES: list = ["https"]
if not IN_ENCLAVE:
    ALLOWED_PEER_URL_SCHEMES = ["http", "https"]

# =============================================================================
# Storage Limits
# =============================================================================

# MAX_VALUE_SIZE:
# The maximum size allowed for a SINGLE value (encrypted bytes) in the key-value store.
#
# Used in: data_store.py (DataStore.put)
MAX_VALUE_SIZE: int = 1_048_576       # 1 MB per value

# MAX_APP_STORAGE:
# The total storage quota allocated for a SINGLE App ID.
# If exceeded, LRU eviction is triggered for that app's namespace.
#
# Used in: data_store.py (DataStore.put / eviction logic)
MAX_APP_STORAGE: int = 10_485_760     # 10 MB total per app

# DEFAULT_TTL_MS:
# The default Time-To-Live for a key-value record if none is specified.
# 0 means "no expiration" (infinite).
#
# Used in: data_store.py (DataRecord creation in put)
DEFAULT_TTL_MS: int = 0

# =============================================================================
# Periodic Tasks (Scheduling)
# =============================================================================

# KMS_NODE_TICK_SECONDS:
# The core heartbeat interval of the KMS node.
# The background scheduler triggers `node_tick` at this frequency.
# It drives: master secret checks, operator status checks, and sync initiation.
#
# Used in: app.py (BackgroundScheduler interval)
KMS_NODE_TICK_SECONDS: int = 30


# SYNC_INTERVAL_SECONDS:
# Defines how frequently the background sync process (pushing deltas to peers) runs.
# This throttles network traffic; we don't need to sync on every single tick.
#
# Used in: sync_manager.py (SyncManager.node_tick logic)
SYNC_INTERVAL_SECONDS: int = 60

# SYNC_BATCH_SIZE:
# The maximum number of records to include in a single sync push request.
# limits the payload size and processing time per request.
#
# Used in: sync_manager.py (SyncManager._push_deltas)
SYNC_BATCH_SIZE: int = 500

# PEER_CACHE_TTL_SECONDS:
# The Time-To-Live for the cached list of peer KMS nodes.
# Used by `PeerCache` (sync level) regarding peer discovery.
# Even if the cache is stale, sync logic might use it; but this controls when
# a proactive refresh from chain is considered "due".
# Set to 180s (3x tick interval) to rely primarily on `node_tick` background refreshes
# while providing a failsafe expiration.
#
# Used in: sync_manager.py (PeerCache._is_stale)
PEER_CACHE_TTL_SECONDS: int = 180

# REGISTRY_CACHE_TTL_SECONDS:
# The Time-To-Live for cached responses from the NovaAppRegistry.
# Used by `CachedNovaRegistry` to reduce expensive on-chain RPC calls when
# verifying client identities (App/Version status) during high-frequency API requests.
#
# Used in: nova_registry.py (CachedNovaRegistry default TTL)
REGISTRY_CACHE_TTL_SECONDS: int = 180


# PEER_BLACKLIST_DURATION_SECONDS:
# The duration for which a peer is temporarily ignored if it fails verification
# (e.g. invalid teePubkey). Prevents continuous probing of known-bad hosts.
#
# Used in: sync_manager.py (PeerCache.blacklist_peer)
PEER_BLACKLIST_DURATION_SECONDS: int = 600

