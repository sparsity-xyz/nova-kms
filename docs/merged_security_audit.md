# Nova KMS — Security Notes (Code-Aligned)

This document is a **living, code-aligned security review note**, not an independent third‑party audit.

It summarizes the **security-relevant behaviors that are implemented in this repo**, plus **explicitly-known boundaries/assumptions**.

---

## Scope

- KMS service: Rust/Axum app under `nova-kms/src/`
- On-chain trust roots: `NovaAppRegistry` and `KMSRegistry` clients
- App↔KMS and KMS↔KMS request authentication, authorization, encryption, and sync integrity

---

## Trust & Threat Model (What the code assumes)

- The host and network are treated as **untrusted**.
- **Authorization** decisions are made via on-chain state (queried via `NovaAppRegistry`).
- **Confidentiality** of request/response bodies is provided by teePubkey-based **E2E encryption envelopes** (P‑384 ECDH + AES‑256‑GCM via Odyn), not by assuming TLS is always end-to-end.

---

## Implemented Controls (What exists today)

### 1) On-chain authorization (NovaAppRegistry)

- **App→KMS** requests are authenticated (PoP) and then authorized via `AppAuthorizer.verify()`:
  - instance must be `ACTIVE`
  - instance must be `zkVerified`
  - app must be `ACTIVE`
  - version must not be `REVOKED` (current app logic accepts `ENROLLED` and `DEPRECATED`)
- **KMS↔KMS** sync authorizes peers via `PeerCache.verify_kms_peer()` (cache refreshed from `NovaAppRegistry` with `KMS_APP_ID` membership, `ACTIVE`, `zkVerified`, version status checks).

### 2) Mutual PoP authentication (EIP-191)

- Nonce + timestamp freshness checks are enforced.
- Recipient wallet binding is enforced in the signed message:
  - App→KMS: `NovaKMS:AppAuth:<nonce_b64>:<kms_wallet>:<ts>`
  - KMS↔KMS: `NovaKMS:Auth:<nonce_b64>:<recipient_wallet>:<ts>`
- Responses include a recipient signature over `NovaKMS:Response:<caller_sig>:<recipient_wallet>`.

### 3) E2E encryption envelopes + sender teePubkey binding

- Sensitive payloads are carried in an envelope:
  - `sender_tee_pubkey`, `nonce`, `encrypted_data`
- Before decrypting an encrypted envelope, the server verifies:
  - `envelope.sender_tee_pubkey` matches the **on-chain** teePubkey for the authenticated wallet

This prevents a class of MitM “re-encryption” attacks where an attacker substitutes their own teePubkey.

### 4) Sync integrity via HMAC (when configured)

- When the node has a sync key configured, `/sync` requires `X-Sync-Signature`.
- The HMAC is computed over the canonical JSON of the **on-the-wire request body**.
  - For encrypted sync, this is the canonical JSON of the E2E envelope.
- Bootstrap exception: `master_secret_request` is accepted without HMAC so a new node can obtain the initial sync key.

### 5) Sealed master secret exchange

- Master secret transfer supports a sealed ECDH exchange (ephemeral P‑384 + HKDF + AES‑GCM) via `src/crypto.rs`.
- Plaintext master secret exchange is rejected in production (`IN_ENCLAVE=true`).

### 6) SSRF and network hardening for peer URLs

- Peer URLs are validated for scheme/host/credential format before outbound requests.
- In production, default allowed peer URL schemes are `https` (via `ALLOWED_PEER_URL_SCHEMES`).
- DNS/IP allow/deny and egress controls are expected to be enforced by network policy/proxy.

### 7) DoS protection

- `/nonce` is guarded by a token-bucket limiter.
- Additional ingress/body-size controls are expected at the deployment edge (load balancer / proxy policy).

---

## Known Boundaries / Non-goals (As implemented)

- **Eventual consistency** for KV sync: last-writer-wins semantics can drop concurrent writes.
- **Registry cache TTL** means authorization changes (revocations) may take up to the cache window to fully propagate.
- **Dev shortcuts** exist (e.g., header-based identity), but are blocked when running in production enclave mode.

---

## How to use this doc

- Treat it as the “security contract” for what the repo actually enforces.
- If you change auth, envelope formats, or sync signing, update this doc together with `docs/architecture.md` and `docs/kms-core-workflows.md`.
