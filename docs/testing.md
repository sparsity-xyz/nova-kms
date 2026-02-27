# Nova KMS — Testing Guide (Rust)

## Overview

`nova-kms` now uses Rust as the primary node implementation. Testing is split into:

- Rust unit tests (`cargo test`) for auth/crypto/store/sync/server primitives.
- Python parity test (`tests/compare_behavior.py`) to verify HKDF + AES-GCM compatibility against the Python reference algorithm.
- Solidity tests (`contracts/`, Foundry) for `KMSRegistry`.

## Quick Start

```bash
cd nova-kms

# 1) Rust unit tests
cargo test

# 2) Cross-language crypto behavior parity
python3 tests/compare_behavior.py

# 3) Contract tests
cd contracts && forge test -vvv
```

## Rust Test Coverage

Current Rust tests cover:

- `auth.rs`
  - nonce issue/consume replay protection
  - wallet canonicalization
  - nonce base64 encoding validation
  - KMS peer PoP checks (stale timestamp, replay nonce, wallet-header mismatch)
  - EIP-191 signature round-trip verification
- `crypto.rs`
  - HKDF derivation (path/context separation)
  - AES-GCM encrypt/decrypt
  - HMAC generation/verification
  - sealed master-secret exchange (P-384 ECDH + AES-GCM)
  - master-secret lifecycle state
- `store.rs`
  - delete semantics for missing keys
  - tombstone retention behavior
  - deterministic conflict resolution on concurrent updates
- `sync.rs`
  - canonical JSON for HMAC signing
  - HMAC round-trip
  - sync delta serialization shape
  - `node_tick` self-membership availability gate
  - `sync_tick` availability gate behavior
  - peer blacklist cache eviction
  - peer `/status` probe metadata capture
  - incoming sync record validation (oversize payload, future timestamp, invalid ciphertext)
- `server.rs`
  - `/health`, `/nodes`, `/nonce` behavior
  - `/nonce` token-bucket rate limiting
  - `/kms/*` service availability gate
  - `/sync` readiness gate (master secret required)
- `rate_limiter.rs`
  - token bucket allow/deny and refill behavior
- `registry.rs`
  - `setMasterSecretHash` calldata encoding
  - Odyn signed-tx payload extraction variants
  - `CachedNovaRegistry` wallet cache hit path
- `models.rs`
  - vector clock comparison
  - sync record serialization/deserialization

## Cross-Language Parity Test

`tests/compare_behavior.py` validates:

- `derive_data_key(master_secret, app_id)` compatibility
- `derive_sync_key(master_secret)` compatibility
- AES-GCM ciphertext produced by Rust can be decrypted by Python reference implementation

Run:

```bash
cd nova-kms
python3 tests/compare_behavior.py
```

Expected: script prints all checks as `True` and ends with success.

## Notes

- The parity script intentionally does not depend on legacy `enclave/` source files; it embeds the Python reference HKDF/AES logic directly.
- For full end-to-end cluster sync validation, run at least two nodes and execute sync flows (`/sync` delta + snapshot + master-secret request) under the same registry/network configuration.
- For coverage details, run:

```bash
cd nova-kms
cargo llvm-cov --workspace --all-features --summary-only
```
