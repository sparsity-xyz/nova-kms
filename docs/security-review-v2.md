# Nova KMS — Independent Security Review Report

**Reviewer**: Senior Security Engineer / Distributed Systems Architect  
**Date**: 2026-02-11  
**Scope**: Full codebase — Solidity contracts, Python enclave application, configuration, docs  
**Codebase**: ~15 Python modules, 1 Solidity contract + interface, 6 doc files, 14 test files

---

## Executive Summary

### High-Level Security Posture

The Nova KMS architecture is **well-designed at the conceptual level**. Trust is anchored on-chain via UUPS-upgradeable contracts, the enclave isolation model is coherent, PoP-based mutual authentication is correctly specified, and the anti-split-brain initialization logic is robust. The system correctly avoids persisting secrets to disk and enforces encrypted-at-rest semantics for KV data.

However, this review identified multiple findings across severity levels that **must be addressed before production deployment**. Several are in critical paths (master secret lifecycle, sync authentication, transport security).

### Major Strengths
- On-chain trust anchoring via `KMSRegistry` + `NovaAppRegistry` callback pattern
- Strong anti-split-brain initialization logic (`node_tick` is stricter than documented — good)
- Sealed ECDH key exchange for master secret transport
- Per-app namespace isolation with AES-GCM encryption at rest
- Simulation mode correctly guarded against enclave activation (`IN_ENCLAVE` + `SIMULATION_MODE` double-check)
- `Ownable2StepUpgradeable` for ownership safety
- `eth_call_finalized` with confirmation depth to guard against reorgs

### Major Risks
- Master secret generation in `node_tick` lacks the full anti-split-brain rigor of `wait_for_master_secret`
- Derived key cache is not invalidated on master secret re-sync
- Client side accepts legacy plaintext master secret even in production
- `/kms/derive` returns raw key material without application-layer transport protection
- DNS rebinding TOCTOU in SSRF validation
- Rate limiter body size check is `Content-Length` only (bypassable)

### Finding Summary

| Severity | Count |
| :--- | :--- |
| 🔴 Critical | 3 |
| 🟠 High | 6 |
| 🟡 Medium | 8 |
| 🔵 Low / Info | 10 |

---

## Severity Legend

| Severity | Description |
| :--- | :--- |
| 🔴 **Critical** | Could lead to key compromise, data loss, or complete bypass of security controls |
| 🟠 **High** | Significant risk to integrity, availability, or confidentiality |
| 🟡 **Medium** | Defense-in-depth weakness or correctness issue |
| 🔵 **Low / Info** | Hygiene, documentation mismatch, or dead code |

---

## 1. Overall Architecture & Threat Model

### Reconstructed Architecture

```
Nova Apps (TEE instances) —[PoP+HTTPS]→ KMS Nodes (Nitro Enclave)
KMS Nodes —[PoP+HMAC Sync]→ KMS Nodes
KMS Nodes —[read-only eth_call]→ NovaAppRegistry (proxy)
KMS Nodes —[read-only eth_call]→ KMSRegistry (proxy)
NovaAppRegistry —[addOperator/removeOperator callbacks]→ KMSRegistry
```

### Trust Assumptions (Explicit & Implicit)

1. **NovaAppRegistry is trusted**: It's the root of identity for apps and KMS nodes
2. **KMSRegistry proxy owner key is trustworthy**: Single EOA controls upgrades + `resetMasterSecretHash`
3. **Odyn SDK is trusted**: Provides TEE wallet, signing, and randomness — marked "DO NOT MODIFY"
4. **Helios light client provides honest RPC**: `eth_call_finalized` assumes Helios isn't compromised
5. **DNS resolution is honest** (implicit — violated by TOCTOU in `url_validator.py`)
6. **Network between enclave and LB is secure** (undocumented — see C-APP-1 below)

### Security Boundaries

| Boundary | Trust Level | Notes |
| :--- | :--- | :--- |
| Inside Nitro Enclave | Fully trusted | All Python code, master secret, derived keys |
| Enclave ↔ Helios | Trusted (vsock) | Light client runs inside enclave process |
| Enclave ↔ Load Balancer | **Undocumented** | If plaintext HTTP, key material exposed |
| Enclave ↔ Peer KMS | Authenticated via PoP+HMAC | Mutual verification against on-chain state |
| On-chain contracts | Trusted root | UUPS upgradeable by single owner key |

### Missing / Undocumented Assumptions

- **No documented threat model for the enclave-to-LB hop** — Nitro enclaves typically use vsock with a proxy, which may or may not provide TLS
- **No threat model for Odyn SDK compromise** — if Odyn returns wrong randomness or signs incorrectly, entire KMS fails
- **No consideration of chain reorganization deeper than 6 blocks** for `eth_call_finalized`

---

## 2. Smart Contract Review: KMSRegistry

### Contract Role

`KMSRegistry` is a UUPS-upgradeable contract that:

1. Stores an operator set (TEE wallet addresses) managed via `addOperator`/`removeOperator` callbacks from `NovaAppRegistry`
2. Stores a `masterSecretHash` (keccak256 of the cluster master secret) for cluster integrity verification
3. Provides `getOperators()` for peer discovery

### Findings

#### C-SOL-1: `_authorizeUpgrade` performs no validation on `newImplementation` (Medium)

**File**: `contracts/src/KMSRegistry.sol` — Line 108

```solidity
function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
```

While `onlyOwner` is enforced, the function body is empty. A compromised owner key can upgrade to any arbitrary contract, including one that drains the operator set or returns false data. There is **no timelock, no multi-sig requirement, and no implementation validation**.

**Impact**: If owner key is compromised, attacker can silently replace all contract logic.  
**Recommendation**: Add a timelock or require that `newImplementation` has matching code hash.

---

#### C-SOL-2: `__UUPSUpgradeable_init()` not called in `initialize()` (Low)

**File**: `contracts/src/KMSRegistry.sol` — Lines 99–104

```solidity
function initialize(address initialOwner, address appRegistry_) public initializer {
    __Ownable_init(initialOwner);
    // __UUPSUpgradeable_init() is not called
```

Currently a no-op in OpenZeppelin, but breaks initialization convention. Future OZ upgrades could add logic here.

---

#### C-SOL-3: `setMasterSecretHash` front-running race (Medium-High)

**File**: `contracts/src/KMSRegistry.sol` — Lines 147–155

`setMasterSecretHash` accepts the **first** call when `masterSecretHash == 0`. While `_isEligibleHashSetter` validates the caller is a legitimate ACTIVE KMS instance, a malicious validator/MEV bot could observe a pending `setMasterSecretHash` transaction and front-run it with a different hash from another legitimate KMS node that has been compromised.

The hash value itself is chosen by the `msg.sender` — the contract has no way to verify the hash corresponds to the *correct* master secret vs. a rogue one.

**Mitigations**: The `_isEligibleHashSetter` check significantly narrows the attack surface. However, if any single KMS node's TEE is compromised, it could set a malicious hash.

---

#### C-SOL-4: `kmsAppId` can be changed after deployment by owner (Low)

**File**: `contracts/src/KMSRegistry.sol` — Lines 125–128

`setKmsAppId` has no guard against being called repeatedly. An owner could change the app ID, causing `addOperator`/`removeOperator` to silently reject legitimate callbacks or accept callbacks from the wrong app.

**Recommendation**: Consider making `kmsAppId` immutable after initial set (or add a flag).

---

#### C-SOL-5: No storage gap documentation (Info)

The `masterSecretHash` state variable was added above the `_gap`. The `uint256[44] private _gap` provides 44 slots, which is adequate. However, the gap calculation should be documented to show it accounts for all state variables.

---

#### Authorization Correctness: **PASS**

- `addOperator`/`removeOperator` correctly gated by `onlyNovaAppRegistryMod`
- `setNovaAppRegistry`/`setKmsAppId`/`resetMasterSecretHash` correctly gated by `onlyOwner`
- `appId` mismatch check prevents cross-app operator injection
- Operator set uses correct O(1) swap-and-pop removal
- Idempotent add/remove (returns silently if already added/removed)

#### Event Correctness: **PASS**

All state-changing functions emit appropriate events with indexed parameters.

#### Test Coverage: **Adequate for core paths**, but missing:

- Test for `setMasterSecretHash` (success, revert on double-set, revert on non-eligible sender)
- Test for `resetMasterSecretHash`
- Test for `_isEligibleHashSetter` logic
- Fuzz test for operator add/remove ordering

---

## 3. Enclave Code Review

### Boot Sequence

**File**: `enclave/app.py`

1. Detect mode (simulation vs production)
2. Safety guard: refuse simulation in enclave
3. Production: wait for Helios → get TEE wallet from Odyn → init chain clients → check operator status → init DataStore/PeerCache/SyncManager
4. **Master secret NOT initialized at startup** — deferred to `node_tick`
5. Mount routes, start background scheduler

#### Finding: Production startup does not block on master secret

**File**: `enclave/app.py` — Lines 193–194

Comment: "Master secret and sync are handled by the single periodic node tick. Startup should not block on initialization." This is **correct by design** — the first `node_tick` runs immediately after startup (line 261), and the service stays `503 Unavailable` until the master secret is verified. This is sound.

### Attestation Usage

The KMS does **not** use attestation documents for HTTP authentication. Instead, it relies on:

1. NovaAppRegistry registers instances only after ZKP verification
2. PoP signatures from the TEE wallet (provided by Odyn) are sufficient since the wallet is bound to the attested enclave

This is a reasonable tradeoff for performance. However:

#### Finding: No runtime attestation re-verification (Info)

Once an instance is registered on-chain as `ACTIVE`, the KMS trusts it indefinitely (subject to cache TTL). There is no periodic re-attestation. If an enclave is compromised after registration, it continues to be trusted.

### Key Isolation

- Master secret stored in `MasterSecretManager._secret` (Python object in memory — no disk persistence)
- Derived keys computed on-demand via HKDF
- Per-app data keys cached in `_Namespace._cached_key`
- **No explicit memory protection (mlock/mprotect)** — expected in a Nitro Enclave where the entire memory is protected

### Boundary Between Trusted / Untrusted Code

- `odyn.py` is marked "DO NOT MODIFY" — trusted SDK
- All incoming HTTP requests validated via middleware → PoP → registry verification
- `simulation.py` has proper guards against activation in production
- `chain.py` removed transaction helpers and documents the "read-only" invariant

### Error Handling & Panic Paths

Generally good — extensive `try/except` with logging. No unhandled exceptions that would crash the process. `DataKeyUnavailableError` is properly fail-closed (refuses to serve rather than falling back to plaintext in production).

### Logging of Sensitive Material

#### C-ENC-1: PoP signature logged on verification failure (Low)

**File**: `enclave/auth.py` — Lines 175–183

```python
logger.warning(
    f"App PoP verification failed: {exc} | "
    f"Message='{message}' | "
    f"Recovered='{recovered}' | "
    f"HeaderWallet='{wallet}' | "
    f"NodeWallet='{_node_wallet}'"
)
```

The PoP message includes the nonce, which has already been consumed. The signature itself is not a secret (it's in headers). This is acceptable for debugging but could be reduced in production.

#### C-ENC-2: Master secret epoch and state exposed via `/status` (Medium)

**File**: `enclave/routes.py` — Lines 245–260

The `/status` endpoint exposes `master_secret.state` (`uninitialized`/`generated`/`synced`), `master_secret.epoch`, and `synced_from` — all unauthenticated. This leaks:

- Whether the node has initialized its master secret
- Whether it was a seed node or synced from a peer
- The epoch counter (useful for timing attacks around rotation)

**Recommendation**: Restrict `/status` to authenticated operators in production or remove master secret fields.

---

## 4. KMS Node Logic

### Node Identity

- TEE wallet address obtained from `Odyn.eth_address()` at startup
- Set globally via `auth.set_node_wallet()`
- Used as node ID for vector clocks, sync, and PoP binding

### Node Lifecycle

1. Start → Helios sync → TEE wallet → check `isOperator` → init components
2. `node_tick` (every 15s): refresh peers → check master secret hash → sync data
3. Service goes online only when: self is in operator list AND master secret hash matches on-chain

### Registration & Validation

- KMS nodes do NOT self-register; `NovaAppRegistry` handles registration via attestation/ZKP
- `KMSRegistry.addOperator()` called by `NovaAppRegistry` callback
- Off-chain, nodes check `kms_registry.is_operator(self.node_wallet)` and `_isEligibleHashSetter`

### Implicit Trust Issues

#### C-NODE-1: `node_tick` generates master secret without full split-brain protection (🔴 Critical)

**File**: `enclave/sync_manager.py` — Lines 530–540

In `node_tick`, when `chain_hash_is_zero` and master secret is not initialized:

```python
if not master_secret_mgr.is_initialized:
    if not self.odyn:
        _set_unavailable(...)
        return
    try:
        master_secret_mgr.initialize_from_random(self.odyn)
```

This generates a master secret **without checking** whether other ACTIVE operators exist. The `wait_for_master_secret` method has elaborate split-brain prevention (checking operator count, verifying self is the sole ACTIVE instance), but `node_tick` **does not call it** — it generates immediately if `chain_hash == 0`.

**Impact**: If two nodes start simultaneously and both see `chain_hash == 0`, both generate different master secrets. The first to get `setMasterSecretHash` confirmed wins; the other is permanently locked out until manual intervention.

The architecture doc's anti-split-brain logic (Section 3) says "If all other operators are INACTIVE or FAILED, the current node acts as the seed" — **this check is missing from `node_tick`**.

**Mitigations**: The on-chain `setMasterSecretHash` is first-write-wins, so only one secret can win. The losing node will detect the mismatch on the next tick and attempt to sync. However, during the race window, the losing node may have served derived keys to apps from its ephemeral secret.

**Recommendation**: Add the same `wait_for_master_secret`-style checks into `node_tick` before generating.

---

## 5. Master Secret Generation & Synchronization

### Generation

- **Generated from**: `odyn.get_random_bytes()` (hardware RNG), padded to 32 bytes
- **Generated when**: `chain_hash == 0` and local secret uninitialized (in `node_tick`)
- **Deterministic or random**: Random (hardware RNG in production), deterministic SHA-256 in simulation

### Persistence

- **None** — master secret lives only in Python memory (`MasterSecretManager._secret`)
- On restart, must sync from peer or regenerate (if no peers)

### Rotation

#### C-MS-1: `rotate()` has no callers outside tests (Medium)

**File**: `enclave/kdf.py` — Lines 131–140

The `rotate()` method increments the epoch counter but does not:

- Clear the derived key cache
- Update the on-chain `masterSecretHash`
- Propagate the new epoch to peers

No production caller was found. This is dead code for now, but when rotation is implemented, the cache and on-chain hash must be updated atomically.

#### C-MS-2: Per-app data key cache never invalidated (🔴 Critical)

**File**: `enclave/data_store.py` — Lines 155–162

`_Namespace._cached_key` caches the per-app data encryption key and is **never invalidated**:

```python
def _get_key(self) -> Optional[bytes]:
    if self._cached_key:
        return self._cached_key
    if self._key_callback:
        try:
            self._cached_key = self._key_callback(self.app_id)
            return self._cached_key
```

If the master secret is re-synced (e.g., `node_tick` detects hash mismatch and syncs from peer), the `_cached_key` in every `_Namespace` still holds the old derived key. Reads/writes after sync will use stale keys.

**Impact**: After master secret re-sync, the node uses old data keys for encryption/decryption, causing silent data corruption.

**Recommendation**: Add a method to `DataStore` that clears all namespace key caches, and call it whenever `master_secret_mgr` is re-initialized.

### Synchronization Across Nodes

- Master secret exchanged via sealed ECDH (AES-GCM) — **well implemented**
- On-chain hash provides consistency anchor
- If local hash mismatches on-chain hash, node attempts sync from peers

### Failure Scenarios

| Scenario | Behavior | Adequacy |
| :--- | :--- | :--- |
| Node crash | Restart → `node_tick` → sync from peers | Good |
| Node replacement | New node sees `chain_hash != 0` → sync | Good |
| Partial cluster failure | Surviving nodes continue; failed nodes resync | Good |
| Total cluster loss | `chain_hash != 0` but no peers → stuck at 503 | **No recovery without `resetMasterSecretHash`** |
| Simultaneous start | Both generate; first tx wins; loser resyncs | Race window exists (C-NODE-1) |

### Single Points of Failure

1. **KMSRegistry owner key**: Can `resetMasterSecretHash()`, forcing all nodes offline
2. **NovaAppRegistry**: If compromised, can add/remove arbitrary operators
3. **First seed node**: Generates the master secret for the entire cluster's lifetime

---

## 6. Inter-KMS Node Sync

### Peer Discovery

- `PeerCache._refresh()` queries `NovaAppRegistry` for KMS app versions and instances
- Filters for `VersionStatus.ENROLLED` + `InstanceStatus.ACTIVE`
- URL validated via `validate_peer_url()` before adding to cache

### State Sync Protocol

- **Delta sync**: Push recent records (by `updated_at_ms`) to all peers every `SYNC_INTERVAL_SECONDS` (60s)
- **Snapshot sync**: Full state pull on startup or when far behind
- **Master secret sync**: Sealed ECDH exchange via `/sync` with type `master_secret_request`

### Sync Correctness

#### C-SYNC-1: `PEER_CACHE_TTL_SECONDS` NameError in `_start_scheduler` (Low — dead code)

**File**: `enclave/sync_manager.py` — Line 260

```python
self.scheduler.add_job(
    self.peer_cache.refresh,
    "interval",
    seconds=PEER_CACHE_TTL_SECONDS,  # Not imported!
```

`PEER_CACHE_TTL_SECONDS` is referenced but not imported at the top of the file. Only `SYNC_INTERVAL_SECONDS`, `SYNC_BATCH_SIZE`, and `MAX_SYNC_PAYLOAD_BYTES` are imported from `config`.

**However**, this code path is **only reached** when `SyncManager` is constructed with `scheduler=True` (or `scheduler=None`). In the current codebase, `app.py` always passes `scheduler=False` and manages the scheduler externally via `node_tick`. So this is **dead code but still should be fixed**.

---

#### C-SYNC-2: `master_secret_request` exempt from HMAC (🟡 Medium — by design, but risky)

**File**: `enclave/sync_manager.py` — Line 946

```python
if self._sync_key and sync_type != "master_secret_request":
```

`master_secret_request` is deliberately exempted from HMAC verification to allow bootstrap. This means any registered KMS operator can request the master secret **at any time**, not just during initial setup.

**Impact**: A compromised KMS node can repeatedly extract the master secret.

**Mitigation**: PoP authentication is still required, so the requester must be a registered operator.

**Recommendation**: Add a flag or rate limit: only service `master_secret_request` when the requesting node can demonstrate it lacks the secret.

---

#### C-SYNC-3: Client-side accepts plaintext master secret in production (🔴 Critical)

**File**: `enclave/sync_manager.py` — Lines 636–641

```python
elif result and isinstance(result, bytes):
    # Legacy plaintext fallback (dev/sim only)
    master_secret_mgr.initialize_from_peer(result, peer_url=peer_url)
```

The **server side** correctly rejects plaintext in production (`IN_ENCLAVE` check at line 995). But the **client side** at line 636 has no such guard. If a malicious peer returns a plaintext secret, a production node will accept it.

**Recommendation**: Add `if not config.IN_ENCLAVE:` guard around the plaintext fallback branch on the client side.

### Replay / Rollback Risks

- Nonces are single-use and TTL-bounded — replay protected
- Timestamps enforce freshness window (`POP_MAX_AGE_SECONDS = 120s`)
- HMAC on payload prevents tampering
- Vector clocks prevent rollback of individual data records
- **No epoch binding** in HMAC: if the sync key changes (due to epoch rotation), old HMAC signatures become invalid. This is correct.

### Ordering Assumptions

- LWW (Last-Writer-Wins) with millisecond timestamps for concurrent writes
- At same millisecond, existing record wins (could silently drop writes — see M-DATA-1 below)

---

## 7. Scheduled / Background Tasks

### `node_tick` — The Single Heartbeat

**Config**: `KMS_NODE_TICK_SECONDS = 15`

| Step | Action | Failure Handling |
| :--- | :--- | :--- |
| 1 | Refresh peer cache from NovaAppRegistry | Warning logged, continues |
| 2 | Check self in operator list | → 503 |
| 3 | Read `masterSecretHash` from chain | → 503 |
| 4a | Hash == 0: generate + attempt `setMasterSecretHash` | → 503 on failure |
| 4b | Hash != 0: verify local matches, sync if mismatch | → 503 on failure |
| 5 | Set sync key, go online | → 200 |
| 6 | Push deltas (paced by `SYNC_INTERVAL_SECONDS`) | Exception caught, logged |

**Assessment**: Well-structured single-task design avoids race conditions. Idempotent per tick.

### Obsolete `_start_scheduler` tasks

**File**: `enclave/sync_manager.py` — Lines 247–263

Two jobs are registered:

1. `push_deltas` every `SYNC_INTERVAL_SECONDS` — **redundant** with `node_tick` which also calls `push_deltas`
2. `refresh_peers` every `PEER_CACHE_TTL_SECONDS` — **crashes** due to import error

Since `scheduler=False` is always passed, these are dead code. **Recommend removing `_start_scheduler` entirely**.

### `wait_for_master_secret` — Dead code in production

**File**: `enclave/sync_manager.py` — Lines 318–421

This elaborate method implements the full anti-split-brain logic documented in `kms-core-workflows.md`. However, **it is never called** in the current codebase. `app.py` and `node_tick` do not call it.

**Impact**: The documented anti-split-brain protection is **not actually enforced** in the production path. `node_tick` has a simpler (and less safe) approach.

**Recommendation**: Either integrate `wait_for_master_secret` into the startup path or port its checks into `node_tick`.

---

## 8. Nova App Serving Logic

### Authentication Flow

1. App calls `GET /nonce` (rate limited by `_nonce_rate_limiter`)
2. App signs `NovaKMS:AppAuth:<Nonce>:<KMS_Wallet>:<Timestamp>` with its TEE key
3. App sends request with `X-App-Signature`, `X-App-Nonce`, `X-App-Timestamp` headers
4. KMS recovers wallet from signature → queries `NovaAppRegistry.getInstanceByWallet` → verifies ACTIVE + zkVerified + App ACTIVE + Version ENROLLED/DEPRECATED

### App Identity Binding: **Correct**

- App ID derived from on-chain registry, not client-provided
- `auth.py`: "the KMS does not trust client-provided App IDs"
- PoP signature binds to specific KMS node wallet (prevents reflection attacks)

### Replay Protection: **Correct**

- Nonces are single-use (`validate_and_consume` pops from store)
- Timestamps within `POP_MAX_AGE_SECONDS` window
- Nonce TTL prevents stale nonce accumulation

### Request Scoping: **Correct**

- All KV operations scoped by `app_id` (from registry, not client)
- Namespace isolation enforced by `DataStore._ns(app_id)` dispatch

### Leakage Risks

#### C-APP-1: `/kms/derive` returns raw key material without transport envelope (🟠 High)

**File**: `enclave/routes.py` — Lines 311–320

Derived key bytes are Base64-encoded in the HTTP response body. If the enclave-to-LB hop is plaintext (common in Nitro setups), key material traverses the wire unencrypted.

**Recommendation**: Wrap key material in an ECDH+AES-GCM sealed envelope (the infrastructure already exists in `kdf.py`), or enforce that the connection is over TLS.

#### C-APP-2: `/nodes` makes synchronous outbound probes on every call (🟡 Medium)

**File**: `enclave/routes.py` — Lines 272–310

Each `GET /nodes` triggers health probes to all peers. A DDoS attacker sends 1 request, node sends N outbound requests. This is an amplification vector.

**Recommendation**: Cache probe results or make probes async.

---

## 9. Configuration Review

### Full Config Item Analysis

| Config Item | Value | Where Used | Effect | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `IN_ENCLAVE` | auto-detected | Everywhere | Master security switch | Defaults to `True` — safe |
| `CHAIN_ID` | 84532 | `chain.py` | Base Sepolia | Hardcoded — good |
| `NOVA_APP_REGISTRY_ADDRESS` | `0x0f68...` | `nova_registry.py` | Trust root | Hardcoded — good |
| `KMS_REGISTRY_ADDRESS` | `0x9347...` | `kms_registry.py` | Trust root | Hardcoded — good |
| `KMS_APP_ID` | 43 | peer discovery, sync | KMS app identifier | Hardcoded — good |
| `SIMULATION_MODE` | False | `simulation.py` | Dev toggle | Correctly guarded |
| `SIM_PEERS` | [] | `simulation.py` | Sim peer list | Dev only |
| `SIM_MASTER_SECRET_HEX` | "" | `simulation.py` | Dev secret | Dev only |
| `POP_MAX_AGE_SECONDS` | 120 | `auth.py` | Replay window | Reasonable |
| `ALLOW_PLAINTEXT_FALLBACK` | False | `data_store.py` | Encryption bypass | **Correctly False** |
| `MAX_CLOCK_SKEW_MS` | 30000 | `data_store.py` | Sync clock skew tolerance | 30s — reasonable |
| `MAX_SYNC_PAYLOAD_BYTES` | 50MB | `rate_limiter.py`, `sync` | Payload limit | Large but acceptable for snapshots |
| `RATE_LIMIT_PER_MINUTE` | 120 | `rate_limiter.py` | Global rate limit | Per-IP |
| `NONCE_RATE_LIMIT_PER_MINUTE` | 30 | `routes.py` | Nonce endpoint limit | Per-IP |
| `MAX_NONCES` | 4096 | `auth.py` | Nonce store cap | With FIFO eviction — bounded |
| `MAX_REQUEST_BODY_BYTES` | 2MB | `rate_limiter.py` | Non-sync body limit | Via Content-Length only (bypassable) |
| `MAX_VALUE_SIZE` | 1MB | `data_store.py` | KV value cap | Enforced |
| `MAX_APP_STORAGE` | 10MB | `data_store.py` | Per-app total cap | With LRU eviction |
| `DEFAULT_TTL_MS` | 0 | `data_store.py` | No default expiration | Growth bounded by 10MB cap |
| `SYNC_INTERVAL_SECONDS` | 60 | `sync_manager.py` | Delta push pace | Reasonable |
| `SYNC_BATCH_SIZE` | 500 | `sync_manager.py` | Max records per push | **Never referenced — dead config** |
| `KMS_NODE_TICK_SECONDS` | 15 | `app.py` | Heartbeat interval | Reasonable |
| `REGISTRY_CACHE_TTL_SECONDS` | 60 | `nova_registry.py` | Auth cache duration | Revocation delay |
| `ALLOWED_PEER_URL_SCHEMES` | `["https"]` prod / `["http","https"]` dev | `url_validator.py` | SSRF protection | Correct |

### Dead Config Values

- **`SYNC_BATCH_SIZE`** (500): Imported in `sync_manager.py` but **never referenced** in any function. `push_deltas` sends all deltas without batching.
- **`SIM_PEERS`** and **`SIM_MASTER_SECRET_HEX`**: Always empty in config; overridden by env vars or defaults in `simulation.py`. Could be removed from config.

### Security-Dangerous Defaults

- **`CORS_ORIGINS = "*"`** (env var default in `app.py` line 322): In production, `CORS_ORIGINS` should not default to `*`. While CORS is not a security boundary for API-to-API communication, it weakens defense-in-depth.

### Missing `PEER_CACHE_TTL_SECONDS` in `config.py`

Referenced in `scheduled_tasks.md` as a config variable (default 60) and used in `sync_manager.py` line 260, but **not defined in `config.py`**. It should be added (even though the code path using it is currently dead).

---

## 10. kms-core-workflow Compliance

### Documented Workflow vs. Implementation

| Workflow Step | Document | Implementation | Match? |
| :--- | :--- | :--- | :--- |
| 1. Deploy KMSRegistry + Platform Registration | §1 | `DeployKMSRegistry.s.sol` + `setKmsAppId` | ✅ Match |
| 2. Node Join & Enrollment | §2 | NovaAppRegistry callbacks → `addOperator` | ✅ Match |
| 3. Anti-Split-Brain Init | §3 | `wait_for_master_secret` (method exists but **never called**) | ❌ **Not enforced** |
| 3. Anti-Split-Brain Init | §3 | `node_tick` generates immediately when hash==0 | ❌ **Weaker than documented** |
| 4. Inter-Node Mutual Auth | §4 | `_make_request` + `handle_incoming_sync` | ✅ Match |
| 5. App Access (Mutual PoP) | §5 | `_authorize_app` + `_add_mutual_signature` | ✅ Match |
| 6. Key Derivation | §6 | `derive_app_key` via HKDF | ✅ Match |
| Master Secret Hash on-chain | `scheduled_tasks.md` | `node_tick` → `set_master_secret_hash` | ✅ Match |

### Explicit Deviations

1. **Anti-split-brain not enforced in `node_tick`**: The documented loop (fetch operators → check active set → only generate if sole ACTIVE) is implemented in `wait_for_master_secret` but that function is **never called**. `node_tick` immediately generates when `chain_hash == 0`. This is **not intentional** (the docs describe it as a requirement) and **weakens security** by allowing race conditions during simultaneous boot.

2. **`wait_for_master_secret` is dead code**: Despite being the core of the anti-split-brain design, it's unreachable in the current startup flow.

3. **`_start_scheduler` is dead code**: The dual-scheduler model (internal + external) described in early code has been replaced by external-only scheduler in `app.py`, but the internal scheduler code remains.

---

## 11. Documentation & Comments Audit

### Outdated Statements

| Location | Statement | Reality |
| :--- | :--- | :--- |
| `enclave/chain.py` lines 167–175 | "KMS nodes do NOT submit on-chain transactions" | `kms_registry.py` has `set_master_secret_hash` and `reset_master_secret_hash` which **do submit transactions** |
| `enclave/kms_registry.py` docstring | "Read-only helpers for querying the KMSRegistry" | Contains `set_master_secret_hash` and `reset_master_secret_hash` (write operations) |
| `docs/deployment.md` line 152 | "KMS nodes do NOT submit any on-chain transactions" | False — `node_tick` calls `set_master_secret_hash` |
| `enclave/app.py` line 31 | "KMS nodes do NOT submit any on-chain transactions" | False — `node_tick` calls `set_master_secret_hash` |
| `docs/scheduled_tasks.md` | Describes `PEER_CACHE_TTL_SECONDS` as a config variable | **Not defined in `config.py`**, referenced in dead code |

### Inaccurate Descriptions

- Architecture doc §2.3 shows code checking `version.code_measurement != measurement` in auth flow, but actual `auth.py` `AppAuthorizer.verify()` **does not check code measurement** at all — it only checks instance status, app status, and version status.

### Missing Documentation

- No documentation for `resetMasterSecretHash` operational runbook
- No documentation for what happens when all nodes lose their master secret simultaneously
- No documentation for the gap between `wait_for_master_secret` (documented but dead) and `node_tick` (implemented but different logic)
- No documentation for key rotation procedure (`rotate()` exists but unused)

---

## Critical Findings Summary

### 🔴 Critical

| # | Finding | File | Impact |
| :--- | :--- | :--- | :--- |
| C1 | `node_tick` generates master secret without anti-split-brain checks | `enclave/sync_manager.py` line 530 | Race condition: two nodes can generate different secrets |
| C2 | Per-app data key cache never invalidated after master secret re-sync | `enclave/data_store.py` line 155 | Silent data corruption after re-sync |
| C3 | Client-side accepts plaintext master secret in production | `enclave/sync_manager.py` line 636 | Rogue peer can inject known secret |

### 🟠 High

| # | Finding | File | Impact |
| :--- | :--- | :--- | :--- |
| H1 | `/kms/derive` returns raw key material without transport envelope | `enclave/routes.py` line 311 | Key exposure on plaintext enclave-to-LB hop |
| H2 | DNS rebinding TOCTOU in SSRF validation | `enclave/url_validator.py` line 107 | SSRF via DNS rebinding |
| H3 | Rate limiter body size check uses Content-Length only | `enclave/rate_limiter.py` line 106 | Bypass via chunked encoding |
| H4 | `wait_for_master_secret` (anti-split-brain) is dead code | `enclave/sync_manager.py` line 318 | Documented safety not enforced |
| H5 | `setMasterSecretHash` front-running window | `contracts/src/KMSRegistry.sol` line 147 | Compromised node can lock cluster to rogue hash |
| H6 | CachedNovaRegistry serves stale authorization for up to 60s | `enclave/nova_registry.py` line 457 | Revoked apps served for up to TTL |

### 🟡 Medium

| # | Finding | File | Impact |
| :--- | :--- | :--- | :--- |
| M1 | `/status` exposes master secret metadata unauthenticated | `enclave/routes.py` line 245 | Information leakage |
| M2 | `master_secret_request` exempt from HMAC (any operator can extract) | `enclave/sync_manager.py` line 946 | No rate-limiting on secret extraction |
| M3 | LWW tie-break on equal timestamps keeps existing (silent write loss) | `enclave/data_store.py` line 329 | Concurrent writes may be lost |
| M4 | `/nodes` makes synchronous outbound probes (DDoS amplification) | `enclave/routes.py` line 272 | 1 inbound → N outbound |
| M5 | Auth does not check `code_measurement` despite documentation claiming it | `enclave/auth.py` line 258 | App with wrong code can authenticate |
| M6 | `_authorizeUpgrade` has empty body in Solidity | `contracts/src/KMSRegistry.sol` line 108 | Compromised owner = full contract takeover |
| M7 | CORS defaults to `*` in production | `enclave/app.py` line 322 | Defense-in-depth weakness |
| M8 | `probe_node` does not validate URLs via `validate_peer_url` | `enclave/probe.py` line 26 | SSRF via cached malicious URL |

### 🔵 Low / Info

| # | Finding | File |
| :--- | :--- | :--- |
| L1 | `SYNC_BATCH_SIZE` imported but never used | `enclave/config.py`, `enclave/sync_manager.py` |
| L2 | `PEER_CACHE_TTL_SECONDS` not defined in config, referenced in dead code | `enclave/sync_manager.py` line 260 |
| L3 | `_start_scheduler` method is dead code | `enclave/sync_manager.py` line 247 |
| L4 | Duplicate `_abi_type_to_eth_abi_str` / `_decode_outputs` across files | `enclave/kms_registry.py` + `enclave/nova_registry.py` |
| L5 | `kdf.py` has duplicate `get_sync_key` method definition | `enclave/kdf.py` lines 114 and 153 |
| L6 | `__UUPSUpgradeable_init()` not called | `contracts/src/KMSRegistry.sol` line 99 |
| L7 | Nonce store cleanup only runs on `issue()` path | `enclave/auth.py` line 94 |
| L8 | Sequential probing in `probe_nodes` — O(N×timeout) | `enclave/probe.py` line 34 |
| L9 | `_cleanup_counter` global unsynchronized (benign on CPython) | `enclave/rate_limiter.py` line 78 |
| L10 | "Read-only" comments/docstrings contradicted by `set_master_secret_hash` tx methods | Multiple files |

---

## Dead / Redundant Code & Config to Remove

1. **`SyncManager._start_scheduler()`** — Never reached, contains NameError
2. **`SyncManager.wait_for_master_secret()`** — Never called; elaborate dead code (or should be integrated)
3. **`SyncManager.verify_and_sync_peers()`** — Never called in production path
4. **`SYNC_BATCH_SIZE`** config constant and its import — Never used
5. **`SIM_PEERS`** and **`SIM_MASTER_SECRET_HEX`** in `config.py` — Always overridden by `simulation.py` defaults
6. **Duplicate `get_sync_key`** in `kdf.py` — Two identical methods (lines ~114 and ~153)
7. **Duplicate `_abi_type_to_eth_abi_str`** / **`_decode_outputs`** — Identical functions in `kms_registry.py` and `nova_registry.py`, should be in shared utility
8. **Transaction comment block in `chain.py`** (lines 167–175) — References removed functionality but contradicts actual behavior

---

## Security Recommendations (Prioritized)

### P0 — Before Production

1. **Port anti-split-brain checks from `wait_for_master_secret` into `node_tick`** — Prevent dual-generation race
2. **Add `config.IN_ENCLAVE` guard to client-side plaintext master secret fallback** in `_sync_master_secret_from_peer`
3. **Add per-app data key cache invalidation** when master secret changes
4. **Fix body size enforcement** to read actual body bytes, not trust `Content-Length`
5. **Pin DNS resolution** in `validate_peer_url` and pass resolved IP to `requests`

### P1 — Before Mainnet

6. **Add transport-layer envelope for `/kms/derive` responses** (sealed ECDH or require TLS verification)
7. **Restrict `/status` master secret fields** to authenticated operators
8. **Add `code_measurement` verification in `AppAuthorizer.verify()`** as documented
9. **Add timelock or multi-sig to `_authorizeUpgrade`** in KMSRegistry
10. **Rate-limit `master_secret_request`** sync type

### P2 — Defense-in-Depth

11. Remove dead code (`_start_scheduler`, `wait_for_master_secret`, `verify_and_sync_peers`, `SYNC_BATCH_SIZE`)
12. Fix documentation mismatches (read-only claims vs. transaction methods)
13. Cache `/nodes` probe results
14. Add `validate_peer_url` call inside `probe_node`
15. Set CORS to non-`*` default in production config

---

## Open Questions for Maintainers

1. **Why is `wait_for_master_secret` dead code?** Was this intentional? The `node_tick` approach is less safe. Should this be integrated?

2. **What is the enclave-to-LB transport?** Is it vsock with TLS termination inside the enclave, or plaintext HTTP? This determines severity of returned key material exposure.

3. **What is the key rotation plan?** `rotate()` exists but has no callers, no on-chain hash update, no peer propagation. How will epoch transitions work in production?

4. **Is `code_measurement` verification intentionally omitted from `AppAuthorizer`?** The architecture doc shows it as a step, but the implementation skips it.

5. **What is the `resetMasterSecretHash` operational runbook?** Calling it makes all nodes go offline. What recovery procedure follows?

6. **Is the owner of KMSRegistry a multi-sig?** Documentation says "hardware wallet recommended" but does not require multi-sig for the contract that controls the entire KMS cluster.

7. **Solidity test coverage for `masterSecretHash`**: The foundry test file has no tests for `setMasterSecretHash`, `resetMasterSecretHash`, or `_isEligibleHashSetter`. Are these tested elsewhere?
