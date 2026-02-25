# Nova KMS DataStore Implementation Report

This report provides a detailed technical review of the `DataStore` architecture in Nova KMS, focusing on security, consistency, and scalability within a distributed Trusted Execution Environment (TEE).

## 1. Security & Encryption
The DataStore implements a "defense-in-depth" approach where data is never stored in plaintext within the enclave's memory.

- **Algorithm**: `AES-256-GCM` (Galois/Counter Mode) via `cryptography.hazmat`. GCM provides both confidentiality and authenticity.
- **Key Management**: 
    - Keys are derived per-app using `HKDF-SHA256` from the global master secret.
    - Context-binding ensures that `app_A` cannot decrypt data belonging to `app_B`.
- **Ciphertext Integrity**:
    - Format: `nonce (12b) || ciphertext || tag (16b)`.
    - **Probe Decryption**: During synchronization, incoming records are probe-decrypted in production mode to verify they were authored by a legitimate KMS node before being admitted to the store.

## 2. Read/Write Logic
The implementation follows a thread-safe, partitioned namespace design.

- **Isolation**: Each `app_id` has its own `_Namespace` object, preventing cross-tenant interference.
- **Granular Locking**: Locking is performed at the namespace level (`_Namespace._lock`), allowing concurrent read/write operations for different apps.
- **Read Path**: Performs expiry checks and tombstone filtering before attempting decryption.
- **Write Path**: Increments vector clocks and potentially triggers LRU eviction before committing the encrypted record.

## 3. Storage Limits & Resource Management
To prevent memory exhaustion attacks, strict limits are enforced within each namespace.

| Limit | Value | Description |
|-------|-------|-------------|
| `MAX_VALUE_SIZE` | 1 MB | Maximum size of a single encrypted record. |
| `MAX_APP_STORAGE` | 10 MB | Total encrypted payload quota per app namespace. |
| `MAX_CLOCK_SKEW_MS`| 5 sec | Tolerance window for future-dated writes. |

- **Eviction policy**: When a namespace exceeds `MAX_APP_STORAGE`, it evicts records in least-recently-updated order based on `updated_at_ms` while preserving tombstone semantics.

## 4. Distributed Synchronization
Synchronization between KMS nodes is a multi-layered process ensuring state convergence across the cluster.

- **Peer Discovery**: Nodes dynamically discover each other via the `NovaAppRegistry` on-chain (filtering for `ACTIVE` instances under `KMS_APP_ID` and excluding `REVOKED` versions).
- **Communication Security**:
    - **PoP Handshake**: Mutual Proof-of-Possession based on `tee_wallet` signatures.
    - **HMAC Signing**: All sync payloads are signed with a transient sync key derived from the shared master secret.
- **Sync Modes**:
    1. **Delta Push**: Periodic push (default 10s) of recent changes since the last sync.
    2. **Full Snapshot**: Performed during startup or after prolonged network isolation to ensure full state parity.

## 5. Conflict Resolution (Vector Clocks + LWW)
The system uses a hybrid consistency model to handle network partitions and concurrent writes.

- **Causality Tracking**: Every record carries a `VectorClock`. 
    - If `Incoming > Local` (causally): Accept the update.
    - If `Incoming < Local`: Discard the update.
- **Concurrent Conflict**: If updates are concurrent (no clear causal ancestor), the system falls back to **Last-Writer-Wins (LWW)** using the `updated_at_ms` millisecond timestamp.
- **Safety**: Conflicts are resolved deterministically across all nodes, ensuring "eventual consistency."

## 6. Recommendations & Observations
- **Observation**: The current implementation is non-persistent (In-Memory Only). While this maximizes speed and security (no disk IO), it requires a full snapshot sync upon every node restart.
- **Metric**: The `stats()` endpoint provides visibility into namespace count, total keys, and memory utilization, which is critical for monitoring cluster health.
