# Nova KMS

Nova KMS is the Rust KMS node for the Nova platform. It runs as an Axum service, uses Odyn for enclave signing/encryption primitives, authorizes callers from `NovaAppRegistry`, and coordinates cluster master-secret state through `KMSRegistry`.

The node provides two application-facing capabilities:

- Key derivation from a cluster-wide master secret
- An encrypted, in-memory KV store partitioned by caller `app_id`

## What The Current Node Does

- Derives per-app keys with HKDF-SHA256
- Encrypts stored values with AES-256-GCM before they enter the KV store
- Replicates KV records across KMS peers with delta push and snapshot sync
- Uses Proof of Possession (PoP) signatures for app and peer authentication
- Uses `teePubkey`-based end-to-end envelopes for request and response bodies
- Uses `KMSRegistry.masterSecretHash` to converge on one cluster master secret

## Runtime Dependencies

- Odyn API
  - `IN_ENCLAVE=true`: `http://127.0.0.1:18000`
  - `IN_ENCLAVE=false`: `http://odyn.sparsity.cloud:18000`
- Chain RPC for `NovaAppRegistry` and `KMSRegistry`
- `NovaAppRegistry` as the source of truth for:
  - app authorization
  - KMS peer membership
  - `teePubkey` and `instanceUrl` metadata
- `KMSRegistry` for:
  - operator callbacks
  - `kmsAppId`
  - `masterSecretHash`

## Availability Model

- `GET /health` is process liveness only.
- `GET /status` is the readiness source.
- `node.service_available=true` only after:
  - this node appears in current KMS membership
  - the local `teePubkey` matches `NovaAppRegistry`
  - the local master secret matches `KMSRegistry.masterSecretHash`
- `/kms/*` routes require `service_available=true`.
- `/sync` requires the local master secret to be initialized.

## API Surface

| Route | Method | Purpose | Auth |
| --- | --- | --- | --- |
| `/` | `GET` | JSON overview of the service | none |
| `/health` | `GET` | liveness probe | none |
| `/status` | `GET` | node, cluster, and store status | none |
| `/nonce` | `GET` | issue single-use base64 nonce | none |
| `/nodes` | `GET` | dump current `PeerCache` view | none |
| `/kms/derive` | `POST` | derive an app-scoped key | app PoP or dev fallback |
| `/kms/data` | `GET` | list keys, or fetch one key with `?key=` | app PoP or dev fallback |
| `/kms/data/*key` | `GET` | fetch one key, path form | app PoP or dev fallback |
| `/kms/data` | `PUT` | write one key | app PoP or dev fallback |
| `/kms/data` | `DELETE` | delete one key | app PoP or dev fallback |
| `/sync` | `POST` | peer delta, snapshot, or master-secret sync | peer PoP |

Notes:

- Sensitive request and response bodies are always carried in an encrypted envelope.
- Plaintext request bodies are rejected in the current server implementation.
- The router does not register OpenAPI, Swagger UI, or ReDoc endpoints.

## Authentication And Encryption

### App -> KMS

- PoP message:
  - `NovaKMS:AppAuth:<nonce_b64>:<kms_wallet>:<timestamp>`
- Required headers when using PoP:
  - `x-app-signature`
  - `x-app-nonce`
  - `x-app-timestamp`
  - `x-app-wallet` (optional hint, must match recovered signer if present)
- In local development only (`IN_ENCLAVE=false`), app routes can fall back to:
  - `x-tee-wallet`

### KMS -> KMS

- PoP message:
  - `NovaKMS:Auth:<nonce_b64>:<recipient_wallet>:<timestamp>`
- Required headers:
  - `x-kms-signature`
  - `x-kms-nonce`
  - `x-kms-timestamp`
  - `x-kms-wallet` (optional hint, must match recovered signer if present)
- Once a sync key exists, `/sync` also expects:
  - `x-sync-signature`
  - exception: `type=master_secret_request`

### Encrypted Envelope

All sensitive payloads use this JSON shape:

```json
{
  "sender_tee_pubkey": "<hex DER/SPKI>",
  "nonce": "<hex>",
  "encrypted_data": "<hex>"
}
```

The receiver checks that `sender_tee_pubkey` matches the authenticated caller's on-chain `teePubkey` before decrypting.

## Configuration

Configuration is loaded from:

1. built-in defaults
2. `NovaKms.toml`
3. environment variables

Canonical runtime variables that matter for normal operation:

- `IN_ENCLAVE`
- `LOG_LEVEL`
- `BIND_ADDR`
- `NOVA_APP_REGISTRY_ADDRESS`
- `KMS_REGISTRY_ADDRESS`
- `KMS_APP_ID`
- `NODE_URL`
- `NODE_INSTANCE_URL`
- `NODE_WALLET`
- `NODE_PRIVATE_KEY`
- `KMS_NODE_TICK_SECONDS`
- `DATA_SYNC_INTERVAL_SECONDS`
- `PEER_CACHE_TTL_SECONDS`
- `REGISTRY_CACHE_TTL_SECONDS`
- `MAX_APP_STORAGE_BYTES`
- `MAX_KV_VALUE_SIZE_BYTES`
- `TOMBSTONE_RETENTION_MS`
- `MAX_TOMBSTONES_PER_APP`
- `POP_TIMEOUT_SECONDS`
- `MAX_NONCES`
- `MAX_CLOCK_SKEW_MS`
- `MASTER_SECRET_HEX`
- `NONCE_RATE_LIMIT_PER_MINUTE`

Some fields exist in `Config` but are not enforced on the current request path:

- `RATE_LIMIT_PER_MINUTE`
- `ALLOW_PLAINTEXT_DEV`
- `MAX_REQUEST_BODY_BYTES`
- `MAX_SYNC_PAYLOAD_BYTES`
- `PEER_BLACKLIST_DURATION_SECONDS`

## Startup And Master Secret Convergence

On startup the process:

1. creates shared state and background tasks
2. runs `node_tick` immediately
3. refreshes `PeerCache` from `NovaAppRegistry`
4. confirms that this node is an active KMS instance and that its local `teePubkey` matches the registry
5. reads `KMSRegistry.masterSecretHash`
6. if the on-chain hash is zero:
   - uses `MASTER_SECRET_HEX` if supplied, otherwise generates 32 random bytes
   - computes `keccak256(master_secret)`
   - submits `setMasterSecretHash`
   - remains unavailable until the chain reflects the hash
7. if the on-chain hash is non-zero and local state does not match:
   - requests the master secret from a verified peer
   - immediately requests a full snapshot from that peer
8. derives the sync HMAC key and marks the service available

Important detail:

- `sync_tick` does not run immediately at boot. It starts after the first `DATA_SYNC_INTERVAL_SECONDS` sleep.

## Repository Map

- `src/main.rs`: process bootstrap and background tasks
- `src/server.rs`: HTTP routes and response shapes
- `src/auth.rs`: nonce handling, PoP verification, wallet recovery
- `src/sync.rs`: peer discovery, master-secret convergence, delta push
- `src/store.rs`: in-memory namespaced store and merge logic
- `src/crypto.rs`: HKDF, AES-GCM, HMAC, sealed master-secret exchange
- `src/registry.rs`: on-chain clients and caches
- `docs/`: code-aligned documentation
- `contracts/`: `KMSRegistry` contract and Foundry scripts

## Development Commands

```bash
cargo test
python3 tests/compare_behavior.py
make build-docker
```

For local setup and deployment details, see:

- `docs/development.md`
- `docs/deployment.md`
- `docs/app-to-kms-connection.md`
- `docs/architecture.md`
