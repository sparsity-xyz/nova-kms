# Nova KMS Development Guide

This guide covers local development against the current Rust codebase.

## 1. Tooling

Required:

- Rust and Cargo
- Python 3 for `tests/compare_behavior.py`
- Foundry for `contracts/`
- Docker for image builds

Runtime dependencies for a real local node:

- an RPC endpoint that can serve `NovaAppRegistry` and `KMSRegistry`
- an Odyn API endpoint
  - local dev code path uses `http://odyn.sparsity.cloud:18000`
  - enclave code path uses `http://127.0.0.1:18000`

## 2. Repository Layout

Relevant paths:

- `src/main.rs`: process startup and background tasks
- `src/server.rs`: routes and response shapes
- `src/auth.rs`: nonce store, PoP verification, wallet recovery
- `src/sync.rs`: peer cache, readiness, delta push, snapshot and secret sync
- `src/store.rs`: namespaced in-memory KV store
- `src/crypto.rs`: HKDF, AES-GCM, HMAC, sealed master-secret exchange
- `src/registry.rs`: contract clients and caches
- `src/bin/compare_rust.rs`: helper for the reference crypto check
- `docs/`: code-aligned documentation
- `contracts/`: `KMSRegistry` contract and Foundry scripts

## 3. Common Commands

```bash
# format
cargo fmt

# lint
cargo clippy

# unit tests
cargo test

# reference crypto check
python3 tests/compare_behavior.py

# image build
make build-docker
```

The root `Makefile` currently exposes:

- `build-docker`
- `test`
- `lint`
- `fmt`

## 4. Configuration Sources

The service loads configuration in this order:

1. defaults in `src/config.rs`
2. `NovaKms.toml`
3. environment variables

Use lower snake case in `NovaKms.toml`, for example:

```toml
in_enclave = false
bind_addr = "0.0.0.0:8000"
log_level = "INFO"

node_url = "http://127.0.0.1:18545"
node_instance_url = "http://localhost:8000"
node_wallet = "0x0a00000000000000000000000000000000000000"
node_private_key = "0x..."

nova_app_registry_address = "0x..."
kms_registry_address = "0x..."
kms_app_id = 49

master_secret_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

Environment variables use upper snake case equivalents, for example `NODE_URL` and `KMS_APP_ID`.

## 5. Active Runtime Settings

These fields have active effect in the current code path:

| Setting | Default | Effect |
| --- | --- | --- |
| `IN_ENCLAVE` | `true` | choose Odyn endpoint, peer URL policy, startup wallet behavior |
| `LOG_LEVEL` | `INFO` | tracing filter |
| `BIND_ADDR` | `0.0.0.0:8000` | Axum listen address |
| `NOVA_APP_REGISTRY_ADDRESS` | configured default | NovaAppRegistry client |
| `KMS_REGISTRY_ADDRESS` | configured default | KMSRegistry client |
| `KMS_APP_ID` | `49` | KMS peer membership scope |
| `NODE_URL` | `http://127.0.0.1:18545` | chain RPC |
| `NODE_INSTANCE_URL` | empty | reported node URL; backfilled from registry if empty |
| `NODE_WALLET` | fixed placeholder | dev wallet or enclave fallback before Odyn refresh |
| `NODE_PRIVATE_KEY` | unset | required for local message signing when the node must sign in dev mode |
| `KMS_NODE_TICK_SECONDS` | `60` | heartbeat and readiness loop |
| `DATA_SYNC_INTERVAL_SECONDS` | `10` | outbound delta loop |
| `PEER_CACHE_TTL_SECONDS` | `180` | stale threshold for on-demand peer refresh |
| `REGISTRY_CACHE_TTL_SECONDS` | `180` | app auth cache TTL |
| `MAX_APP_STORAGE_BYTES` | `10485760` | per-app namespace budget |
| `MAX_KV_VALUE_SIZE_BYTES` | `1048576` | app `PUT /kms/data` plaintext size limit |
| `TOMBSTONE_RETENTION_MS` | `86400000` | tombstone cleanup window |
| `MAX_TOMBSTONES_PER_APP` | `10000` | namespace tombstone cap |
| `POP_TIMEOUT_SECONDS` | `120` | nonce and PoP timestamp freshness |
| `MAX_NONCES` | `4096` | nonce LRU capacity |
| `MAX_CLOCK_SKEW_MS` | `15000` | future timestamp rejection for incoming sync |
| `MASTER_SECRET_HEX` | unset | optional local master-secret seed |
| `NONCE_RATE_LIMIT_PER_MINUTE` | `30` | `/nonce` token bucket |

## 6. Declared But Currently Inactive Settings

These fields exist in `Config`, but the current request path does not enforce them:

- `RATE_LIMIT_PER_MINUTE`
- `ALLOW_PLAINTEXT_DEV`
- `MAX_REQUEST_BODY_BYTES`
- `MAX_SYNC_PAYLOAD_BYTES`
- `PEER_BLACKLIST_DURATION_SECONDS`

Do not rely on them for security or traffic control unless the code path is wired first.

## 7. Local Run Modes

### 7.1 Minimal Single-Node Bring-Up

For a single local node where you want deterministic startup:

```bash
export IN_ENCLAVE=false
export NODE_URL=http://127.0.0.1:18545
export NOVA_APP_REGISTRY_ADDRESS=0x...
export KMS_REGISTRY_ADDRESS=0x...
export KMS_APP_ID=49
export NODE_WALLET=0x0a00000000000000000000000000000000000000
export NODE_INSTANCE_URL=http://localhost:8000
export MASTER_SECRET_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

cargo run
```

### 7.2 Local PoP Or Peer Sync Exercises

If the node must sign messages in dev mode, also set:

```bash
export NODE_PRIVATE_KEY=0x...
```

You need this when:

- the node returns app mutual signatures after PoP-authenticated requests
- the node initiates peer sync in dev mode

## 8. What You Can Probe With Plain HTTP

These routes do not require encrypted request bodies:

- `GET /health`
- `GET /status`
- `GET /nodes`
- `GET /nonce`
- `GET /`

Routes under `/kms/*` and `/sync` still require encrypted envelopes even in local development.

## 9. Local Authentication Notes

For app routes only:

- normal mode is app PoP with `x-app-*` headers
- when `IN_ENCLAVE=false`, the node also accepts `x-tee-wallet`

For peer routes:

- `/sync` always requires peer PoP
- once a sync key exists, it also requires `x-sync-signature` except for `type=master_secret_request`

## 10. Useful Checks During Bring-Up

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/status
curl http://127.0.0.1:8000/nodes
curl http://127.0.0.1:8000/nonce
```

Interpretation:

- `/health=200` means the process is alive
- `/status.node.service_available=true` means `/kms/*` is ready
- `/nodes` shows what the current `PeerCache` believes
