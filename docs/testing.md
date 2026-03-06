# Nova KMS Testing Guide

This guide covers the test entry points that exist in the repository today.

## 1. Main Commands

From the repository root:

```bash
# Rust unit tests
cargo test

# contract tests
cd contracts && forge test -vvv
```

## 2. Rust Unit Tests

`cargo test` covers the main Rust modules under `src/`.

### 2.1 `auth.rs`

Current tests cover:

- nonce issue and consumption
- wallet canonicalization
- stale timestamp rejection
- nonce replay rejection
- wallet header mismatch rejection
- signature recovery helpers

### 2.2 `crypto.rs`

Current tests cover:

- master-secret lifecycle state
- HKDF derivation behavior
- AES-GCM encrypt/decrypt
- HMAC generation and verification
- sealed master-secret exchange

### 2.3 `models.rs`

Current tests cover:

- vector clock increment
- vector clock comparison
- sync record serialization and parsing

### 2.4 `store.rs`

Current tests cover:

- delete on missing keys
- tombstone cleanup behavior
- concurrent update tie-breaks

### 2.5 `registry.rs`

Current tests cover:

- `setMasterSecretHash` calldata encoding
- raw transaction extraction from Odyn responses
- `CachedNovaRegistry` wallet-cache hit behavior

### 2.6 `sync.rs`

Current tests cover:

- canonical JSON generation
- HMAC round-trip
- delta serialization shape
- peer blacklist primitive
- readiness behavior when peer refresh fails
- `sync_tick` availability gate
- peer `/status` probe metadata capture
- inbound sync record validation

### 2.7 `server.rs`

Current tests cover:

- `/health`
- `/nonce`
- `/nodes`
- nonce rate limiting
- `/kms/*` service-availability gate
- `/sync` requirement that the master secret already exists

## 3. Contract Tests

The Foundry suite in `contracts/` validates `KMSRegistry` behavior, including:

- operator callback handling
- `setKmsAppId`
- `setMasterSecretHash`
- `resetMasterSecretHash`
- owner and registry guards

Run:

```bash
cd contracts
forge test -vvv
```

## 4. What Is Not Covered Automatically

The repository does not contain a current end-to-end cluster test that spins up multiple live Rust nodes and exercises:

- encrypted app writes
- delta propagation across peers
- full bootstrap from `master_secret_request` plus snapshot

For those flows, use a real environment and validate with:

- `/status`
- `/nodes`
- application logs

## 5. Recommended Validation Before Shipping

1. run `cargo test`
2. run `cd contracts && forge test -vvv`
3. in a real deployment, verify:
   - `/status.node.service_available`
   - peer visibility in `/nodes`
   - successful delta push logs
