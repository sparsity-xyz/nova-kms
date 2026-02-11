# Nova KMS — Security Review Report

## Executive Summary

A thorough adversarial review of the `nova-kms` codebase (15 Python modules, 1 Solidity contract, 6 docs) was conducted. The overall architecture is well-designed: trust is anchored on-chain, production mode enforces strong defaults (PoP auth, HTTPS, sealed ECDH), and the anti-split-brain initialization logic is robust. However, the review identified **4 Critical**, **5 High**, and **10 Medium** findings that should be addressed before production deployment.

---

## Severity Legend

| Severity | Description |
| :--- | :--- |
| 🔴 **Critical** | Could lead to key compromise, data loss, or complete bypass of security controls |
| 🟠 **High** | Significant risk to integrity, availability, or confidentiality |
| 🟡 **Medium** | Defense-in-depth weakness or correctness issue |
| 🔵 **Low / Info** | Hygiene, documentation mismatch, or dead code |

---

## 🔴 Critical Findings

### C1. `PEER_CACHE_TTL_SECONDS` NameError crashes scheduler

**File**: [sync_manager.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/sync_manager.py#L260)

`PEER_CACHE_TTL_SECONDS` is used at line 260 inside `_start_scheduler()` but is **never imported**. Only `SYNC_INTERVAL_SECONDS`, `SYNC_BATCH_SIZE`, and `MAX_SYNC_PAYLOAD_BYTES` are imported at the top. This will cause a `NameError` at startup when the scheduler tries to register the peer-refresh job, **preventing the node from discovering or refreshing peers**.

```python
# Line 260 — NameError at runtime
seconds=PEER_CACHE_TTL_SECONDS,  # not imported
```

> [!CAUTION]
> **Impact**: Peer cache never refreshes after initial population. Nodes added/removed after startup are invisible. Service degradation escalates to cluster-wide failure over time.

**Fix**: Add `PEER_CACHE_TTL_SECONDS` to the import from `config`.

---

### C2. Derived key cache not invalidated on master secret rotation

**File**: [kdf.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/kdf.py) — `MasterSecretManager`

`MasterSecretManager` caches derived keys (via `derive()` / `_cache`), but when `initialize_from_peer()` or `rotate()` replaces the master secret, **the cache is not cleared**. Old derived keys from a previous epoch continue to be served until process restart.

> [!CAUTION]
> **Impact**: After a master secret rotation, apps receive stale keys derived from the old epoch. Encryption/decryption breaks silently — data encrypted with a new-epoch key cannot be decrypted by a node serving old-epoch cached keys.

**Fix**: Clear `self._cache` in `initialize_from_peer()`, `initialize_from_random()`, and `rotate()`.

---

### C3. `/kms/derive` returns raw key material — no transport encryption guarantee

**File**: [routes.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/routes.py) — `handle_derive()`

The `/kms/derive` endpoint returns **plaintext derived key bytes** (Base64-encoded) in the HTTP response body. While production mode enforces HTTPS for *outbound* sync, there is **no application-level enforcement** that the *inbound* client connection is over TLS. If a load balancer or reverse proxy terminates TLS and forwards plaintext HTTP to the enclave, key material travels in the clear inside the internal network.

> [!IMPORTANT]
> **Impact**: Key material exposure on the wire. The enclave-to-LB hop is typically plaintext in AWS Nitro setups.

**Recommendations**:
1. Wrap returned key material in a sealed envelope (ECDH) similar to master secret exchange.
2. Or at minimum, reject requests arriving over HTTP in production (check `request.url.scheme`).

---

### C4. `setMasterSecretHash` on-chain tx front-running race

**Files**: [KMSRegistry.sol:L147-155](file:///home/ubuntu/sparsity-nova-platform/nova-kms/contracts/src/KMSRegistry.sol#L147-L155), [sync_manager.py:L544-556](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/sync_manager.py#L544-L556)

`setMasterSecretHash` accepts the **first** call when `masterSecretHash == 0`, then reverts all subsequent calls with `MasterSecretHashAlreadySet`. If two nodes start simultaneously and both pass the `node_tick` gating, a mempool observer can see the pending tx and front-run it with a malicious hash, permanently locking the cluster to a compromised secret until `resetMasterSecretHash` is called.

> [!WARNING]
> **Impact**: A front-running attacker can set an arbitrary `masterSecretHash`, forcing all joining nodes to sync from a rogue peer or remain offline. Recovery requires owner intervention.

**Mitigations**:
- Add a commit-reveal scheme, or require that `msg.sender` also match the local node's wallet.
- The existing `_isEligibleHashSetter()` check reduces risk, but the hash value itself is attacker-chosen.

---

## 🟠 High Findings

### H1. DNS resolution TOCTOU in SSRF validation

**File**: [url_validator.py:L107-113](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/url_validator.py#L107-L113)

URL validation resolves the hostname to IPs and checks them against blocked ranges. However, the actual `requests.post()` in `_make_request()` performs a second DNS lookup. A DNS rebinding attack (the hostname resolves to a public IP during validation, then to `127.0.0.1` during the actual request) can bypass SSRF protections.

**Fix**: Resolve once, pin the IP, and pass it directly to `requests` via a custom `HTTPAdapter` or by rewriting the URL.

---

### H2. Rate limiter uses `Content-Length` header (bypassable)

**File**: [rate_limiter.py:L106-120](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/rate_limiter.py#L106-L120)

Body size enforcement relies solely on the `Content-Length` header. An attacker can:
- Omit `Content-Length` entirely and stream an arbitrarily large body.
- Use `Transfer-Encoding: chunked` to bypass the check.

**Fix**: Read the body with a capped reader (e.g., `request.body()` with a max-size wrapper) or use Uvicorn's `--limit-request-body` setting.

---

### H3. CachedNovaRegistry serves stale authorization decisions

**File**: [nova_registry.py:L357-437](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/nova_registry.py#L357-L437)

The `CachedNovaRegistry` caches `get_instance_by_wallet` results for `REGISTRY_CACHE_TTL_SECONDS` (default 60s). If an app's status changes from `ACTIVE` to `REVOKED` on-chain, the KMS continues to serve key material to the revoked app for up to 60 seconds. There is **no event-driven invalidation**.

**Impact**: A revoked app can exfiltrate keys for up to one TTL window after revocation.

**Mitigation**: Reduce cache TTL for authorization-sensitive lookups, or add a cache-bust mechanism on status transitions.

---

### H4. Legacy plaintext master secret fallback path

**File**: [sync_manager.py:L636-641](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/sync_manager.py#L636-L641)

`_sync_master_secret_from_peer()` has a fallback path that accepts raw bytes (line 636-641) when the peer returns `master_secret` instead of `sealed`. While the server side rejects this in production (`IN_ENCLAVE` check at line 996), the **client side** does not, meaning a malicious peer could inject a rogue secret via a plaintext response even in production mode.

**Fix**: Add an `IN_ENCLAVE` guard on the client side at line 636.

---

### H5. `_cleanup_counter` is unsynchronized global state

**File**: [rate_limiter.py:L78,L123-125](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/rate_limiter.py#L78)

`_cleanup_counter` is a global integer incremented in the async `dispatch` method without any lock. Under concurrent requests, this is a harmless race on CPython (GIL), but is technically a data race and could cause counter undercount on alternative Python runtimes.

---

## 🟡 Medium Findings

### M1. `/nodes` endpoint makes blocking outbound probes on every call

**File**: [routes.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/routes.py) — `list_nodes()`

Each call to `GET /nodes` triggers health probes to **all peers** synchronously (via `probe_nodes`). This:
- Amplifies DDoS (attacker sends 1 request, node sends N outbound requests).
- Blocks the response for `N × timeout` seconds.

**Fix**: Cache probe results or run probes asynchronously.

---

### M2. `/status` exposes master secret metadata

**File**: [routes.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/routes.py) — `get_status()`

The `/status` endpoint returns `master_secret_epoch`, `master_secret_initialized`, and `peer_count`. This aids an attacker in fingerprinting cluster state and timing attacks around secret rotation.

**Fix**: Restrict `/status` to authenticated operators or remove sensitive fields.

---

### M3. Last-Writer-Wins can silently drop concurrent writes

**File**: [data_store.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/data_store.py) — `merge_record()`

When two records have identical `updated_at_ms`, LWW falls through to a tie-break that keeps the existing record. If two nodes write to the same key within the same millisecond, one write is silently lost.

**Fix**: Add a secondary tie-breaker (e.g., node ID comparison, or merge vector clocks).

---

### M4. No HMAC on `master_secret_request` sync type

**File**: [sync_manager.py:L946](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/sync_manager.py#L946)

`master_secret_request` is deliberately exempted from HMAC verification (line 946) to allow bootstrap. However, this means any node passing PoP (which only requires KMS operator status) can request the master secret at any time, not just during bootstrap.

**Fix**: Add rate limiting or a one-time flag so that `master_secret_request` is only serviced when the requester genuinely lacks the secret.

---

### M5. `KMSRegistryClient` retains tx submission methods

**File**: [kms_registry.py:L334-374](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/kms_registry.py#L334-L374)

The docstrings and `chain.py` claim "KMS nodes do NOT submit on-chain transactions." However, `KMSRegistryClient` contains `_build_eip1559_tx`, `_send_signed_tx`, `set_master_secret_hash`, and `reset_master_secret_hash` — all of which **do** submit on-chain transactions. This is a design-vs-documentation mismatch (and both `node_tick` at line 547 and `wait_for_master_secret` use it).

> [!NOTE]
> Not a vulnerability per se, but the documentation is misleading and should be corrected.

---

### M6. Duplicate `get_sync_key` in `kdf.py`

**File**: [kdf.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/kdf.py)

`MasterSecretManager` has a `get_sync_key()` method and a standalone `get_sync_key()` function. The standalone function uses a hardcoded context; the method delegates to `derive()` with a different context. Only one should exist.

---

### M7. Nonce store memory growth unbounded

**File**: [auth.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/auth.py) — `NonceStore`

Nonces are stored in-memory with a TTL-based cleanup that only runs when `issue_nonce()` is called (not on `validate_and_consume`). An attacker issuing rapid nonce requests without consuming them can grow the store indefinitely.

**Fix**: Cap nonce store size or run periodic cleanup independently.

---

### M8. `probe_node()` used without SSRF validation

**File**: [probe.py:L26-31](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/probe.py#L26-L31)

`probe_node()` calls `requests.get(url)` without passing the URL through `validate_peer_url()`. If the peer cache contains a malicious URL that bypassed initial validation (e.g., via DNS rebinding), the probe becomes an SSRF vector.

---

### M9. `_authorizeUpgrade` has empty body

**File**: [KMSRegistry.sol:L108](file:///home/ubuntu/sparsity-nova-platform/nova-kms/contracts/src/KMSRegistry.sol#L108)

```solidity
function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
```

While this is protected by `onlyOwner`, it performs **no validation** on `newImplementation`. A compromised owner key can upgrade to a malicious implementation. Consider adding a timelock or multi-sig requirement.

---

### M10. `__UUPSUpgradeable_init()` not called in initializer

**File**: [KMSRegistry.sol:L99-104](file:///home/ubuntu/sparsity-nova-platform/nova-kms/contracts/src/KMSRegistry.sol#L99-L104)

The `initialize` function calls `__Ownable_init` but does **not** call `__UUPSUpgradeable_init()`. While this doesn't cause a functional issue in the current OpenZeppelin version (the UUPS init is a no-op), it breaks the initialization convention and could cause issues with future OZ upgrades.

---

## 🔵 Low / Informational

| # | Finding | File | Notes |
| :--- | :--- | :--- | :--- |
| L1 | `simulation.py` derives private keys from SHA-256 of predictable seeds | [simulation.py:L46](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/simulation.py#L46) | Acceptable for dev-only code, but ensure `is_simulation_mode()` safety guard works |
| L2 | `_decode_outputs` / `_abi_type_to_eth_abi_str` duplicated across `kms_registry.py` + `nova_registry.py` | Both files | Refactor into shared utility |
| L3 | `config.py` imports CORS origins from env but doesn't validate them | [config.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/config.py) | Could allow `*` in production |
| L4 | `DataStore.get()` returns `None` silently on decryption failure | [data_store.py](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/data_store.py) | Consider returning an explicit error to the caller |
| L5 | `probe_nodes()` is sequential — O(N × timeout) | [probe.py:L34-49](file:///home/ubuntu/sparsity-nova-platform/nova-kms/enclave/probe.py#L34) | Use `concurrent.futures` for parallel probing |

---

## Design vs. Implementation Gaps

| Documented Claim | Reality | Impact |
| :--- | :--- | :--- |
| "KMS nodes do NOT submit on-chain transactions" (`kms_registry.py` docstring, `chain.py` comments) | `node_tick()` calls `kms_reg.set_master_secret_hash()` which submits a signed tx | Documentation is misleading; the actual behavior is correct per `kms-core-workflows.md` |
| "Peer cache refreshed every `PEER_CACHE_TTL_SECONDS`" (`scheduled_tasks.md`) | `PEER_CACHE_TTL_SECONDS` is not imported in `sync_manager.py` — job registration crashes | Peer cache never refreshes on schedule |
| Anti-split-brain doc says "If all other operators are INACTIVE or FAILED, generate" | Implementation only generates when `len(active_set) == 1` and it's self | Implementation is **stricter** than docs (good) |

---

## Open Questions for Team

1. **Key rotation trigger**: What initiates a master secret epoch rotation in production? The `rotate()` method exists but no caller was found outside of tests. Is this manual-only?

2. **Upgrade governance**: The UUPS proxy owner is a single EOA. Is there a plan for multi-sig or timelock before mainnet?

3. **Enclave-to-LB transport**: Is the connection between the Nitro Enclave and the internet-facing load balancer encrypted (vsock TLS proxy), or is it plaintext? This determines the severity of C3.

4. **`resetMasterSecretHash` ceremony**: What is the operational procedure when the owner calls `resetMasterSecretHash()`? All nodes will go offline until a new secret is seeded. Is there a documented runbook?

5. **`RATE_LIMIT_PER_MINUTE` value**: What is the current production value? If set too high, the rate limiter is ineffective; if too low, legitimate apps are throttled.
