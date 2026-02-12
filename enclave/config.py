"""enclave/config.py

# Centralized configuration for the Nova KMS enclave application.
#
# This file defines the runtime configuration. In production (Nitro Enclave), these values
# are typically "baked in" to the enclave image to ensure security and immutability.
# Environment variables are sparingly used, primarily for local debugging and overrides.
#
# Key Design Principles:
# 1. **Security by Default**: Defaults are set for the hardened Enclave environment.
# 2. **Immutability**: Critical addresses (Contracts) are hardcoded to act as trust roots.
# 3. **Environment Support**: `IN_ENCLAVE` flag switches strictly between Enclave and Local behavior.
"""

from __future__ import annotations

import os

# =============================================================================
# Environment Detection
# =============================================================================

# Logging
# Logging
# Hardcoded to DEBUG to expose internal state transitions as requested.
# To reduce verbosity, change this to "INFO".
LOG_LEVEL = "DEBUG"

# IN_ENCLAVE: The master switch for security modes.
# - True (Production / Enclave):
#     - Enforces PoP (Proof of Possession) authentication.
#     - Disables text/plain master secret exchange (requires sealed ECDH).
#     - Enforces HTTPS for peer communication.
#
# - False (Local Development):
#     - Allows HTTP.
#     - Allows plaintext master secret (for debugging).
#     - Enables header-based identity injection (X-Tee-Wallet).
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

CHAIN_ID: int = 84532  # Base Sepolia



# =============================================================================
# Contract Addresses (Trust Roots)
# =============================================================================
# These addresses are hardcoded to establish a Root of Trust.
# Changing them requires rebuilding the enclave image, which ensures that a running
# enclave cannot be tricked into using a malicious registry via simplistic env var manipulation.

# NovaAppRegistry: Source of truth for App, Version, and Instance status.
NOVA_APP_REGISTRY_ADDRESS: str = "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"

# KMSRegistry: Manages the KMS Operator set and the Master Secret Hash.
KMS_REGISTRY_ADDRESS: str = "0x934744f9D931eF72d7fa10b07CD46BCFA54e8d88"

# The App ID for the KMS itself within the Nova ecosystem.
KMS_APP_ID: int = 43

# =============================================================================
# Security & Authentication
# =============================================================================

# POP_MAX_AGE_SECONDS:
# Defines the specific validity window for a PoP (Proof of Possession) signature.
# Prevents replay attacks where an old signature is intercepted and reused.
# Clients must include a timestamp within this window.
POP_MAX_AGE_SECONDS: int = 120

# ALLOW_PLAINTEXT_FALLBACK:
# Data security safety fuse.
# If False (Production Default), the System halts if it cannot derive encryption keys
# for an app. It will NEVER store data in plaintext.
ALLOW_PLAINTEXT_FALLBACK: bool = False

# =============================================================================
# Sync & integrity
# =============================================================================

# MAX_CLOCK_SKEW_MS:
# Tolerance for Last-Write-Wins conflict resolution.
# Peer updates claiming a timestamp too far in the future are rejected to prevent
# clock-skewed nodes from permanently overwriting data.
MAX_CLOCK_SKEW_MS: int = 30000  # 30 seconds

# MAX_SYNC_PAYLOAD_BYTES:
# DDoS protection for the /sync endpoint.
MAX_SYNC_PAYLOAD_BYTES: int = 50 * 1024 * 1024  # 50 MB

# =============================================================================
# Rate Limiting (DDoS Protection)
# =============================================================================

RATE_LIMIT_PER_MINUTE: int = 120
NONCE_RATE_LIMIT_PER_MINUTE: int = 30
MAX_NONCES: int = 4096
MAX_REQUEST_BODY_BYTES: int = 2 * 1024 * 1024  # 2 MB

# =============================================================================
# Networking
# =============================================================================

ALLOWED_PEER_URL_SCHEMES: list = ["https"]
if not IN_ENCLAVE:
    ALLOWED_PEER_URL_SCHEMES = ["http", "https"]

# =============================================================================
# Storage Limits
# =============================================================================

MAX_VALUE_SIZE: int = 1_048_576       # 1 MB per value
MAX_APP_STORAGE: int = 10_485_760     # 10 MB total per app
DEFAULT_TTL_MS: int = 0               # 0 = No expiration by default

# =============================================================================
# Periodic Tasks (Scheduling)
# =============================================================================

# SYNC_INTERVAL_SECONDS:
# Rate limiter for the Data Sync operation (`push_deltas`).
# While the node "ticks" every `KMS_NODE_TICK_SECONDS` (15s) to maintain availability status,
# the heavy operation of pushing data to peers is restricted to run only this often.
# Must be >= KMS_NODE_TICK_SECONDS.
SYNC_INTERVAL_SECONDS: int = 60

# SYNC_BATCH_SIZE:
# Max records to push in one batch.
SYNC_BATCH_SIZE: int = 500

# KMS_NODE_TICK_SECONDS:
# The HEARTBEAT of the KMS node.
# This single interval controls the entire lifecycle loop:
# 1. Refreshing Operator status (Am I still active?).
# 2. Checking Master Secret integrity (Is my secret correct? Do I need to sync?).
# 3. Triggering Data Sync.
KMS_NODE_TICK_SECONDS: int = 60

# REGISTRY_CACHE_TTL_SECONDS:
# Caching for App/Version/Instance lookups during *high-frequency* API authorization.
# Unlike KMS node ticks (which happen every ~15s), API requests can happen hundreds
# of times per second. This cache protects the chain RPC from being overwhelmed.
REGISTRY_CACHE_TTL_SECONDS: int = 180
