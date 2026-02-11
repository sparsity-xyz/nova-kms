# Nova KMS — Consolidated Security Audit Report

**Date**: 2026-02-11
**Scope**: Full codebase (Python enclave application, Solidity contracts, documentation)
**Status**: Consolidated from two independent reviews and verified against the current codebase.

---

## Executive Summary

A comprehensive security review of the `nova-kms` codebase was conducted, consolidating findings from two independent audits. The architecture is conceptually sound, leveraging on-chain trust anchoring, robust enclave isolation, and a strong anti-split-brain design. However, several **critical** and **high-severity** issues were identified that pose significant risks to key security, data integrity, and system availability.

These findings must be addressed before production deployment. The most critical issues involve the master secret generation lifecycle, potential for race conditions during startup, and transport layer security gaps.

### Summary of Findings

| Severity | Count | Description |
| :--- | :--- | :--- |
| 🔴 **Critical** | 2 | Issues leading to key compromise or service failure. |
| 🟠 **High** | 2 | Significant risks to integrity, availability, or confidentiality. |
| 🟡 **Medium** | 3 | Defense-in-depth weaknesses or logical errors. |
| 🔵 **Low/Info** | 10+ | Code hygiene, documentation mismatches, or minor observations. |

---

## 🔴 Critical Findings

### C1. Client-Side Accepts Plaintext Master Secret in Production
**File**: `enclave/sync_manager.py` (Lines 636–641)
**Source**: Report 1 (H4), Report 2 (C-SYNC-3).

While the server-side `handle_incoming_sync` correctly enforces `IN_ENCLAVE` checks to prevent sending plaintext master secrets, the **client-side** `_sync_master_secret_from_peer` method accepts a plaintext response (`isinstance(result, bytes)`) without any environment check.

**Impact**: A malicious or compromised peer could downgrade the sync process and inject a known/malicious master secret by sending it in plaintext, which the victim node would accept and use.

**Recommendation**: Wrap the plaintext fallback block in `if not config.IN_ENCLAVE:` to ensure production nodes only accept sealed (ECDH) master secrets.

### C2. `PEER_CACHE_TTL_SECONDS` NameError / Redundant Scheduler
**File**: `enclave/sync_manager.py` (Line 260)
**Source**: Report 1 (C1), Report 2 (C-SYNC-1).

The `_start_scheduler` method tries to register a job using `seconds=PEER_CACHE_TTL_SECONDS` (which is not imported). More importantly, this background task is **redundant** because the main `node_tick` loop already calls `self.peer_cache.refresh()` on every tick.

**Impact**: If `scheduler=True` were passed to `SyncManager`, the application would crash. As it stands, it is dead, broken code that creates confusion.

**Recommendation**: Remove the `_start_scheduler` method and the `scheduler` argument from `SyncManager.__init__` entirely. Rely solely on `node_tick` for peer discovery.

---

## 🟠 High Findings

### H1. Missing Enclave-to-Enclave TLS with `teePubkey` Verification
**File**: `enclave/routes.py`, `enclave/sync_manager.py`
**Source**: User Feedback / Verified Codebase.

The current implementation relies on standard HTTP(S) via `requests` and `FastAPI` without enforcing a custom trust root based on the `teePubkey` registered in the `NovaAppRegistry`. This applies to **both**:
1.  **KMS-to-KMS Sync:** Synchronization of master secrets and data between nodes.
2.  **App-to-KMS Operations:** Key derivation (`/kms/derive`) and data access (`/kms/data`) by Nova Apps.

**Vulnerability**: KMS nodes and Nova Apps run in Nitro Enclaves where the intermediate network is untrusted. Standard CA-based TLS is valid only for the external domain, not the internal enclave identity. Without verifying the server's identity against the on-chain `teePubkey`, the connection is vulnerable to Man-in-the-Middle (MitM) attacks by the host or network provider.

**Impact**: Total breach of confidentiality. An attacker could intercept the master secret during sync or the derived app keys during `/kms/derive` by terminating the TLS connection at the host level.

**Recommendation**:
1.  **Mutual Authentication (mTLS/ECDH)**: Establish the secure channel using the **`teePubkey` of both parties**.
2.  **Handshake**: The client and server must perform an ECDH key exchange (or TLS handshake) where:
    *   The **Server** proves possession of the private key corresponding to its `teePubkey`.
    *   The **Client** proves possession of the private key corresponding to its `teePubkey`.
    *   The resulting session keys (ECDH shared secret) are secure and mutually authenticated.
3.  **Verification**: Both sides must validate the counterparty's `teePubkey` against the on-chain registry before establishing the connection.

### H2. Rate Limiter Relies on `Content-Length` Header
**File**: `enclave/rate_limiter.py` (Lines 106–120)
**Source**: Report 1 (H2), Report 2 (H3).

The middleware checks `Content-Length` to enforce `MAX_REQUEST_BODY_BYTES`. It does not verify the actual body size read from the stream.

**Impact**: An attacker can bypass the limit by using `Transfer-Encoding: chunked` or by lying about the content length, potentially causing DoS via memory exhaustion.

**Recommendation**: Use a streaming reader that counts bytes and aborts if the limit is exceeded, regardless of headers.


---

## 🟡 Medium Findings

### M1. Unused `epoch` Complexity
**File**: `enclave/kdf.py`
**Source**: Report 1 (M2), Report 2 (M1).

The codebase includes logic for an `epoch` counter in key derivation and master secret management, intended for key rotation. However, there is no mechanism to rotate the master secret or increment the epoch in the current design. This adds unnecessary complexity and potential confusion.

**Recommendation**: Remove `epoch` from `MasterSecretManager`, `derive_app_key`, and the sync protocol to simplify the design.



### M2. Synchronous Outbound Probes in `/nodes`
**File**: `enclave/routes.py`
**Source**: Report 1 (M1), Report 2 (M4).

The `/nodes` endpoint probes all peers sequentially and synchronously. This makes the endpoint slow and potentially vulnerable to DoS if many operators are unresponsive.

**Recommendation**: The `PeerCache` refresh logic (in `node_tick`) should probe node health and store the results. The `/nodes` endpoint should simply return this cached data.

### M3. CORS Defaults to Wildcard in Production
**File**: `enclave/app.py`
**Source**: Report 2 (M7).

`CORS_ORIGINS` defaults to `*` if not set, which is overly permissive for a security-critical service.

**Recommendation**: Enforce explicit CORS origins in production or default to empty.

---

## 🔵 Low / Informational Findings

| Finding | File | Notes |
| :--- | :--- | :--- |
| **Transaction Methods in Client** | `kms_registry.py` | Client includes tx submission methods despite "read-only" doc claims. |
| **Dead Code: `wait_for_master_secret`** | `sync_manager.py` | Unused method; logic replaced by `node_tick`. |
| **Duplicate `get_sync_key`** | `kdf.py` | Method defined twice in `MasterSecretManager`. |
| **Nonce Store Unbounded** | `auth.py` | Cleanup only runs on issuance; attack vectors exist. |
| **`__UUPSUpgradeable_init` Missing** | `KMSRegistry.sol` | Conventional init missing (harmless in current OZ, but bad practice). |
| **`kmsAppId` Mutable** | `KMSRegistry.sol` | Owner can change App ID post-deployment. |
| **Storage Gap Undocumented** | `KMSRegistry.sol` | `_gap` exists but calculation not explained. |
| **Duplicate ABI Helpers** | `kms_registry.py` / `nova_registry.py` | Code duplication. |
| **DataStore.get` Silent Failure** | `data_store.py` | Returns `None` on decryption failure instead of error. |
| **Auth Cache Latency (60s)** | `nova_registry.py` | Accepted risk: revocation takes up to 60s to propagate. |
| **Last-Writer-Wins** | `data_store.py` | Accepted risk: concurrent writes may be dropped. |
| **Doc Mismatch: Code Measure** | `auth.py` | Check done in Registry; update docs to reflect this. |
| **Deferred: Upgrade Check** | `KMSRegistry.sol` | Upgrade checks temporarily deferred. |
| **Last-Writer-Wins** | `data_store.py` | Accepted risk: concurrent writes may be dropped. |

---

## Consolidated Recommendations

### Priority 0 (Must Fix Before Production)
1.  **Secure Master Secret Sync**: Add `if not config.IN_ENCLAVE` guard to client-side plaintext fallback.
2.  **Remove Redundant Scheduler**: Delete `_start_scheduler` in `sync_manager.py`; `node_tick` handles peer refresh.
3.  **Fix Rate Limiter**: Enforce body limits via stream counting, not just `Content-Length`.

### Priority 1 (Strongly Recommended)
4.  **Implement teePubkey TLS**: Enforce TLS with `teePubkey` verification for all enclave-to-enclave connections.

### Priority 2 (Hygiene & Defense-in-Depth)
5.  **Clean Up Dead Code**: Remove `wait_for_master_secret`, duplicates, and unused imports.
6.  **Remove Unused Epoch**: Simplify KDF and sync logic by removing the unused `epoch` parameter.
7.  Secure `/nodes` endpoint (serve cached status).
8.  Correct documentation regarding "read-only" nature of KMS nodes.
9.  Enforce strict CORS origins.
