# Registry and Cache Model

This document defines how Nova KMS separates **App authorization** and **KMS peer authorization**.

## 1. Source of Truth

Both flows ultimately derive from `NovaAppRegistry` on-chain data, but use different local caches:

| Flow | Primary cache | On-chain source | Runtime endpoint family |
| :--- | :--- | :--- | :--- |
| App -> KMS authorization | `CachedNovaRegistry` | `NovaAppRegistry` (instance/app/version) | `/kms/*` |
| KMS <-> KMS peer authorization | `PeerCache` | `NovaAppRegistry` (`KMS_APP_ID` membership + metadata) | `/sync` |

`KMSRegistry` is used for cluster coordination (`masterSecretHash`), not for runtime peer membership.

## 2. Startup Wiring

In `enclave/app.py`:

1. Build one canonical registry client: `app_registry_client = NovaRegistry()`.
2. Inject it into `PeerCache` for KMS peer discovery/verification.
3. Wrap it in `CachedNovaRegistry` and inject into `AppAuthorizer` for app auth hot paths.

This keeps registration wiring explicit:

- `PeerCache` = KMS peer membership/auth path.
- `CachedNovaRegistry` = app auth path.

## 3. App Authorization Path (`/kms/*`)

For app requests:

1. Authenticate PoP (`X-App-*` headers).
2. `AppAuthorizer.verify()` reads via `CachedNovaRegistry`:
   - `get_instance_by_wallet`
   - `get_app`
   - `get_version`
3. Cache miss triggers an on-chain read and stores result with TTL.

Default TTL:

- `REGISTRY_CACHE_TTL_SECONDS = 180`
- Not-found instance entries use shorter TTL (`10s` by default).

## 4. KMS Peer Path (`/sync`)

For inter-node sync:

1. `node_tick` refreshes `PeerCache` from `NovaAppRegistry` at `KMS_NODE_TICK_SECONDS`.
2. `PeerCache` stores peer fields used for sync authorization:
   - wallet, app_id, status, zk_verified, tee_pubkey, instance_url, version_id
3. Incoming `/sync` checks PoP + nonce/timestamp, then authorizes peer via `PeerCache.verify_kms_peer()`.
4. E2E `sender_tee_pubkey` verification in `/sync` also uses cached peer teePubkey.

Current behavior is intentionally **cache-first for `/sync`**:

- If peer is not present in `PeerCache`, `/sync` is rejected.
- `/sync` does not directly read `NovaAppRegistry` in request path.

## 5. Peer Connectivity Metadata

During `PeerCache.refresh()` in enclave mode:

- each peer's `/status` endpoint is probed (timeout: `3s`)
- metadata is cached:
  - `status_reachable`
  - `status_http_code`
  - `status_probe_ms`
  - `status_checked_at_ms`

This metadata is exposed by `/nodes` for diagnostics.

## 6. Refresh and Staleness

- `node_tick` interval: `KMS_NODE_TICK_SECONDS` (default `60s`)
- `PeerCache` staleness TTL: `PEER_CACHE_TTL_SECONDS` (default `180s`)
- App auth cache TTL: `REGISTRY_CACHE_TTL_SECONDS` (default `180s`)

Operational implication:

- App auth can still read-through on cache miss.
- KMS peer sync depends on `PeerCache` freshness for acceptance.
