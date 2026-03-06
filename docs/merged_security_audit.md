# Nova KMS Security Notes

This document is a code-aligned summary of the security controls and limits that exist in the repository today.

## 1. Scope

Covered:

- `src/auth.rs`
- `src/server.rs`
- `src/sync.rs`
- `src/crypto.rs`
- `src/registry.rs`
- `contracts/src/KMSRegistry.sol`

Not covered:

- external network policy
- Nova platform control plane
- Odyn implementation internals

## 2. Implemented Controls

### 2.1 On-Chain Authorization

App routes authorize against `NovaAppRegistry`:

- instance must be ACTIVE
- instance must be `zkVerified`
- app must be ACTIVE
- version must not be REVOKED

Peer sync authorizes against `PeerCache`, which is itself refreshed from `NovaAppRegistry`.

### 2.2 Recipient-Bound PoP

Current message formats:

- app:
  - `NovaKMS:AppAuth:<nonce_b64>:<kms_wallet>:<timestamp>`
- peer:
  - `NovaKMS:Auth:<nonce_b64>:<recipient_wallet>:<timestamp>`
- response:
  - `NovaKMS:Response:<caller_signature>:<recipient_wallet>`

Recipient binding prevents replaying a signature to a different KMS node.

### 2.3 Single-Use Nonces And Timestamp Freshness

The nonce subsystem provides:

- random 16-byte nonces
- base64 encoding
- LRU-backed storage
- single-use consumption
- freshness enforced through `POP_TIMEOUT_SECONDS`

### 2.4 Encrypted Envelopes With Sender Key Binding

Sensitive request and response bodies use:

- `sender_tee_pubkey`
- `nonce`
- `encrypted_data`

Before decrypting, the node verifies that `sender_tee_pubkey` matches the authenticated caller's on-chain `teePubkey`.

This blocks re-encryption with an attacker-controlled key.

### 2.5 Sync Integrity HMAC

When `sync_key` exists, `/sync` requires `x-sync-signature` for:

- `delta`
- `snapshot_request`

The HMAC is computed over the canonical JSON of the on-the-wire request body.

`master_secret_request` is exempt so a node without the cluster secret can still bootstrap.

### 2.6 Secret Distribution

Master-secret transfer uses:

- ephemeral P-384 ECDH
- HKDF-SHA256
- AES-256-GCM

The receiver never returns the master secret in plaintext.

### 2.7 Readiness Gate

App routes are unavailable until:

- peer membership is valid
- local `teePubkey` matches the registry
- local master secret matches the on-chain hash

This prevents serving derivation or KV traffic from a node that is detached from cluster state.

### 2.8 Peer URL Validation

Peers are admitted to `PeerCache` only if their `instanceUrl`:

- parses as a URL
- has a host
- has no embedded credentials
- uses:
  - `https` in enclave mode
  - `http` or `https` in dev mode

## 3. Operationally Important Boundaries

### 3.1 Liveness Is Not Readiness

`GET /health` always reports process liveness.

Use `GET /status` to evaluate:

- `node.service_available`
- `node.master_secret`

### 3.2 Cache Windows Exist

Authorization changes do not apply instantly at the request path:

- app auth depends on `REGISTRY_CACHE_TTL_SECONDS`
- peer auth depends on successful `PeerCache` refresh

### 3.3 In-Memory Only Store

The KV store has no persistence layer.

After restart:

- local data is gone
- the node must rebuild from peers after master-secret convergence

### 3.4 Only `/nonce` Is Rate-Limited

The live code enforces a token bucket on `/nonce`.

There is no general request-rate limiter applied to other routes in the current router.

## 4. Declared But Not Enforced In The Current Request Path

The following config fields exist but do not currently enforce security behavior:

- `RATE_LIMIT_PER_MINUTE`
- `ALLOW_PLAINTEXT_DEV`
- `MAX_REQUEST_BODY_BYTES`
- `MAX_SYNC_PAYLOAD_BYTES`
- `PEER_BLACKLIST_DURATION_SECONDS`

Practical reading:

- plaintext business requests are still rejected, but not because `ALLOW_PLAINTEXT_DEV` is active
- request-size protection is expected to come from the deployment edge unless the handlers are wired to those settings
- automatic peer blacklisting is not active

## 5. Dev-Only Shortcut

When `IN_ENCLAVE=false`, app routes accept `x-tee-wallet` as an identity shortcut.

That shortcut is not available in enclave mode.

It also does not change the body requirement:

- business payloads still need encrypted envelopes

## 6. Contract-Side Constraints

`KMSRegistry.setMasterSecretHash()` is allowed only when:

- `masterSecretHash == 0`
- `kmsAppId != 0`
- the caller is an ACTIVE instance of `kmsAppId`
- the caller's version status is ENROLLED

This is stricter than runtime peer acceptance, which allows ENROLLED and DEPRECATED versions for peer membership.

## 7. Residual Risks To Watch

- a stale peer cache can temporarily admit or reject peers incorrectly
- the store is memory-only, so cluster recovery depends on healthy peers
- request-size limits are not enforced in-handler
- there is no automatic peer quarantine path despite the presence of a blacklist primitive

If any of these areas change in code, update this file together with `docs/architecture.md` and `docs/kms-core-workflows.md`.
