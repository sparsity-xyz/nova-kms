# Registry And Cache Model

Nova KMS reads from `NovaAppRegistry` in two distinct ways. The split matters because app authorization and peer authorization have different freshness and latency goals.

## 1. Source Of Truth

`NovaAppRegistry` is the only runtime source of truth for:

- app status
- version status
- instance status
- `zkVerified`
- `teeWalletAddress`
- `teePubkey`
- `instanceUrl`

`KMSRegistry` is only used for:

- operator callbacks
- `kmsAppId`
- `masterSecretHash`

Runtime peer membership does not come from `KMSRegistry`.

## 2. App Authorization Path

App routes use `CachedNovaRegistry` from `src/registry.rs`.

Call path:

1. recover the app wallet from PoP, or accept `x-tee-wallet` when `IN_ENCLAVE=false`
2. `getInstanceByWallet(wallet)`
3. `getApp(app_id)`
4. `getVersion(app_id, version_id)`

Acceptance rules:

- instance ACTIVE
- instance `zkVerified`
- app ACTIVE
- version status is not REVOKED

Cache behavior:

- normal TTL: `REGISTRY_CACHE_TTL_SECONDS`
- not-found instance entries use a shorter TTL:
  - `min(REGISTRY_CACHE_TTL_SECONDS, 10s)`

This cache is read-through. A miss performs an on-chain read.

## 3. Peer Authorization Path

Peer sync uses `PeerCache` from `src/sync.rs`.

Refresh logic:

1. `getActiveInstances(KMS_APP_ID)`
2. for each wallet, `getInstanceByWallet(wallet)`
3. `getVersion(app_id, version_id)`
4. keep only peers where:
   - instance is ACTIVE
   - `zkVerified=true`
   - version status is ENROLLED or DEPRECATED
   - URL passes local validation

Cached peer fields:

- `tee_wallet_address`
- `node_url`
- `tee_pubkey`
- `app_id`
- `operator`
- `status`
- `zk_verified`
- `version_id`
- `instance_id`
- `registered_at`

## 4. URL Validation

Before a peer enters `PeerCache`, its `instanceUrl` must satisfy:

- valid URL
- host present
- no embedded credentials
- scheme:
  - `https` only when `IN_ENCLAVE=true`
  - `http` or `https` when `IN_ENCLAVE=false`

This is the same URL that outbound sync and nonce requests use later.

## 5. Probe Metadata

When `IN_ENCLAVE=true`, a peer refresh also probes `GET <peer>/status` with a 3-second timeout.

Cached probe fields:

- `status_reachable`
- `status_http_code`
- `status_probe_ms`
- `status_checked_at_ms`

`/nodes` exposes this metadata directly from `PeerCache`.

When `IN_ENCLAVE=false`, those fields remain unset.

## 6. Refresh Timing

There are two refresh triggers:

### 6.1 Scheduled Refresh

`node_tick` runs every `KMS_NODE_TICK_SECONDS` and refreshes `PeerCache` unconditionally.

### 6.2 On-Demand Refresh

`refresh_peers_if_needed()` runs before outbound sync operations. It refreshes only when the cache is older than `PEER_CACHE_TTL_SECONDS`.

## 7. Runtime Consequences

### 7.1 App Routes

App-route authorization can recover from cache misses immediately because `CachedNovaRegistry` is read-through.

### 7.2 Peer Routes

`/sync` is cache-first:

- if a peer is absent from `PeerCache`, the request is rejected
- the request handler does not hit `NovaAppRegistry` directly

This makes `PeerCache` freshness part of sync availability.

### 7.3 Self Membership Gate

`node_tick` also uses `PeerCache` to decide whether this node is a current KMS member.

If this node wallet is not found in the cached peer set:

- `is_operator=false`
- `service_available=false`
- reason becomes `self not in KMS node list`

### 7.4 Node URL Backfill

If `NODE_INSTANCE_URL` is empty and the node finds its own entry in `PeerCache`, it copies the registry `instanceUrl` into `config.node_instance_url`.

## 8. Revocation And Propagation Windows

Two different windows exist:

- app-route auth can be stale until `REGISTRY_CACHE_TTL_SECONDS`
- peer auth can be stale until the next successful `PeerCache` refresh

Operationally, if you revoke a KMS instance or rotate its `teePubkey`, readiness and peer acceptance follow the cache and tick windows, not the exact block where the change was mined.

## 9. Declared But Inactive Peer Controls

`PeerCache` has a `blacklist_peer()` primitive, and `Config` includes `PEER_BLACKLIST_DURATION_SECONDS`, but the current runtime does not invoke automatic peer blacklisting.
