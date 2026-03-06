# KMS Scheduled Tasks

The process starts two background loops from `src/main.rs`.

## 1. `node_tick`

- function: `sync::node_tick(&SharedState)`
- first run: immediately at startup
- steady-state interval: `KMS_NODE_TICK_SECONDS`

### Responsibilities

1. If running in enclave mode, refresh the local wallet from Odyn and canonicalize it.
2. Refresh `PeerCache` from `NovaAppRegistry`.
3. Fail closed if peer refresh failed and no cached peers remain.
4. Confirm that this node wallet is still part of current KMS membership.
5. If available, compare the local Odyn `teePubkey` with the registry entry for this node.
6. Read `KMSRegistry.masterSecretHash`.
7. If the hash is zero:
   - initialize a local master secret if needed
   - submit `setMasterSecretHash`
   - keep the node unavailable until the chain reflects the hash
8. If the hash is non-zero and local state does not match:
   - sync the master secret from a verified peer
   - immediately request a full snapshot from that peer
9. Derive the sync HMAC key from the reconciled master secret.
10. Set `service_available` and `service_unavailable_reason`.

### Availability Effects

`node_tick` is the only place that flips the main readiness gate for `/kms/*`.

Common unavailable reasons written by the current code include:

- `peer cache refresh failed`
- `self not in KMS node list`
- `cannot read local teePubkey`
- `local teePubkey mismatch with registry`
- `cannot read master secret hash`
- `failed to set master secret hash`
- `master secret sync failed`
- `synced master secret hash mismatch`

## 2. `sync_tick`

- function: `sync::sync_tick(&SharedState)`
- first run: after one sleep interval
- steady-state interval: `DATA_SYNC_INTERVAL_SECONDS`

### Responsibilities

1. return early if no sync key exists
2. return early if `service_available` is false
3. call `push_deltas()`

`sync_tick` only handles outbound delta replication. It does not perform peer discovery, readiness decisions, snapshot pull, or master-secret exchange.

## 3. Related On-Demand Work

Not all sync work waits for the scheduler:

- `attempt_master_secret_sync()` can run inside `node_tick`
- `refresh_peers_if_needed()` can refresh `PeerCache` just before outbound sync if the cache is stale

## 4. Configuration

| Variable | Default | Used by |
| --- | --- | --- |
| `KMS_NODE_TICK_SECONDS` | `60` | scheduled `node_tick` |
| `DATA_SYNC_INTERVAL_SECONDS` | `10` | scheduled `sync_tick` |
| `PEER_CACHE_TTL_SECONDS` | `180` | on-demand refresh staleness check |
| `REGISTRY_CACHE_TTL_SECONDS` | `180` | app auth cache |

Other timing knobs that affect these flows:

- `POP_TIMEOUT_SECONDS`
- `MAX_CLOCK_SKEW_MS`
- `NONCE_RATE_LIMIT_PER_MINUTE`
