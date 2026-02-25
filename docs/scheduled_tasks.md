# KMS Scheduled Tasks

The Nova KMS uses **two periodic scheduler jobs**:

- `node_tick` (cluster state / readiness / master secret alignment)
- `sync_tick` (delta push for KV convergence)

This matches `enclave/app.py`, which registers both jobs via APScheduler.

## Task 1: `node_tick`

`node_tick` is the core heartbeat:

- **Function**: `sync_manager.node_tick(master_secret_mgr)`
- **Configuration**: `KMS_NODE_TICK_SECONDS`

### What `node_tick` does

1. Refresh peer cache from `NovaAppRegistry` and update local membership view.
   - `PeerCache` is the KMS peer authorization source for `/sync`.
   - In enclave mode, refresh also probes peer `/status` (3s timeout) and caches connectivity metadata.
2. If this node is not currently an eligible KMS instance, keep service unavailable (`503`).
3. Read `masterSecretHash` from `KMSRegistry`:
   - If hash is zero and this node is eligible, attempt bootstrap hash claim.
   - If hash is non-zero, ensure local master secret matches chain.
4. If needed, sync master secret from verified peers.
5. Derive and install sync HMAC key when master secret is ready.
6. Set service availability (`200` when ready, otherwise `503` with reason).

`node_tick` itself does not perform periodic delta pushes anymore.

Note:
- The service-availability gate applies to app-facing `/kms/*` endpoints.
- Incoming `/sync` has a dedicated readiness gate: it is available only after the local master secret is initialized (PoP/HMAC checks still enforced).
- Outbound sync/bootstrap requests are still allowed before full service availability.

## Task 2: `sync_tick`

`sync_tick` is the lightweight data convergence task:

- **Function**: `sync_manager.sync_tick()`
- **Configuration**: `DATA_SYNC_INTERVAL_SECONDS`

### What `sync_tick` does

1. Returns early when sync key is not initialized.
2. Returns early when service availability is currently `False`.
3. Calls `push_deltas()` to propagate recent changes to peers.

## Configuration Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `KMS_NODE_TICK_SECONDS` | `60` | core heartbeat interval |
| `DATA_SYNC_INTERVAL_SECONDS` | `10` | interval for pushing data deltas to peers |
| `PEER_CACHE_TTL_SECONDS` | `180` | (internal) max age of peer cache before forced refresh |
| `REGISTRY_CACHE_TTL_SECONDS` | `180` | TTL for app authorization read-through cache (`CachedNovaRegistry`) |
