# Nova KMS Data Store

This document describes the actual in-memory data-store implementation in `src/store.rs`, `src/models.rs`, and the surrounding route and sync logic.

## 1. Data Shape

The store is organized as:

- `DataStore`
  - `HashMap<u64, Namespace>`
- `Namespace`
  - keyed by `app_id`
  - stores `DataRecord` values in an `LruCache<String, DataRecord>`

Each `DataRecord` contains:

- `key`
- `encrypted_value`
- `version` as a vector clock
- `updated_at_ms`
- `tombstone`
- `ttl_ms`

## 2. Namespace Isolation

Each authorized app instance operates only inside its own `app_id` namespace.

That isolation is enforced by the route layer:

- the app identity is resolved from auth
- the handler always uses `auth.app_id`
- callers never choose an arbitrary namespace directly

## 3. Encryption At Rest In The Store

The store does not keep application values in plaintext.

Write path:

1. app sends plaintext value as base64 inside the encrypted request envelope
2. handler decodes the base64 plaintext
3. handler derives `derive_data_key(master_secret, app_id)`
4. handler encrypts with AES-256-GCM
5. store keeps only the ciphertext bytes

Read path:

1. handler fetches the ciphertext record
2. handler derives the same per-app data key
3. handler decrypts to plaintext
4. handler returns base64 plaintext inside the encrypted response envelope

Operational nuance:

- route handlers still hold plaintext temporarily while processing requests
- the persisted in-memory store content is ciphertext only

## 4. Record Lifetime

### 4.1 TTL

`ttl_ms == 0` means the record does not expire.

For `ttl_ms > 0`, a record is considered expired when:

```text
current_time_ms > updated_at_ms + ttl_ms
```

Expired records are removed during namespace access.

### 4.2 Tombstones

Delete does not remove a key immediately.

Instead it stores a tombstone record:

- `tombstone=true`
- `encrypted_value=[]`
- vector clock incremented from the previous record version
- `updated_at_ms` set to delete time

Tombstones are removed later when either:

- they outlive `TOMBSTONE_RETENTION_MS`
- tombstone count exceeds `MAX_TOMBSTONES_PER_APP`

## 5. Size Limits

### 5.1 Per-Value Input Limit

`PUT /kms/data` rejects plaintext values larger than `MAX_KV_VALUE_SIZE_BYTES`.

### 5.2 Namespace Budget

Each namespace is bounded by `MAX_APP_STORAGE_BYTES`.

When the budget is exceeded, the namespace evicts non-tombstone records until it falls back under the limit.

### 5.3 Incoming Sync Validation

Inbound sync records are rejected when:

- ciphertext length exceeds `MAX_KV_VALUE_SIZE_BYTES + 128`
- timestamp is too far in the future relative to `MAX_CLOCK_SKEW_MS`
- in enclave mode, ciphertext cannot be decrypted with the local per-app data key

## 6. Concurrency And Locking

Locking is split by namespace:

- `DataStore` guards namespace lookup with one `RwLock`
- each `Namespace` has its own `RwLock`

That means different `app_id` namespaces can proceed independently after lookup.

## 7. Local Write Semantics

### 7.1 Put

On a local write:

- the handler creates a fresh vector clock
- increments it once with `config.node_wallet`
- stamps `updated_at_ms=now_ms()`
- stores the encrypted record

### 7.2 Delete

On delete:

- the existing record version is cloned
- the vector clock is incremented with `config.node_wallet`
- a tombstone replaces the live record

## 8. Merge Semantics

Merge logic lives in `Namespace::merge_record_with_outcome()`.

Rules:

- if the incoming version happened after the current version:
  - replace
- if the incoming version happened before the current version:
  - ignore
- if versions are equal:
  - ignore
- if versions are concurrent:
  - compare `updated_at_ms`
  - larger timestamp wins
  - if timestamps tie, lexicographically larger ciphertext wins
  - when a concurrent record wins, the stored vector clock becomes the merge of both clocks

This produces deterministic convergence across nodes.

## 9. Snapshot And Delta Shapes

Replication serializes records like this:

```json
{
  "key": "path/to/key",
  "value": "<hex ciphertext or null for tombstone>",
  "version": {
    "0xnodewallet": 1
  },
  "updated_at_ms": 1730000000000,
  "tombstone": false,
  "ttl_ms": 60000
}
```

Outbound deltas are grouped by `app_id`:

```json
{
  "49": [
    {
      "key": "a",
      "value": "001122...",
      "version": {
        "0xnodewallet": 1
      },
      "updated_at_ms": 1730000000000,
      "tombstone": false,
      "ttl_ms": 0
    }
  ]
}
```

## 10. Store Statistics

`/status` reports store-level metrics under `data_store`:

- `namespaces`
- `total_keys`
- `total_bytes`

`total_keys` counts currently live keys after cleanup.

## 11. Durability Model

The current store is memory-only.

Consequences:

- process restart clears local KV state
- a restarted node needs peer-assisted recovery
- `attempt_master_secret_sync()` immediately requests a snapshot after syncing the master secret

There is no disk persistence layer in the current code.
