# Nova KMS

Distributed Key Management Service for the Nova Platform. Runs inside AWS Nitro Enclaves and provides **key derivation**, **certificate signing**, and an **in-memory KV store** to other Nova applications.

It is designed with a **Zero-Trust** architecture where no single node is trusted by default. Trust is established via on-chain registries, cryptographic proofs, and strict consensus mechanisms.

## Features

| Feature | Description |
|---------|-------------|
| **Key Derivation (KDF)** | HKDF-SHA256 from a shared cluster master secret, partitioned by on-chain App ID. |
| **In-Memory KV Store** | Per-app namespace, vector-clock versioning, TTL, LRU eviction. Values are encrypted-at-rest (AES-GCM). |
| **Distributed Sync** | Delta + snapshot sync across KMS nodes (Eventual Consistency, Last-Writer-Wins). |
| **Dual Keypairs** | Separated keys for Identity (secp256k1) and Encryption (P-384/secp384r1). |
| **Anti-Split-Brain** | Strict initialization logic using an immutable on-chain Master Secret Hash. |

## Security Architecture

The system implements a **Defense in Depth** strategy with four layers of security:

### 1. On-Chain Identity & Authorization (The "Who")
*   **Nodes**: Must be registered as `ACTIVE` instances in `NovaAppRegistry` and recognized as operators in `KMSRegistry`.
*   **Apps**: Clients must be registered `ACTIVE` apps in `NovaAppRegistry`.
*   **Verification**: All access (App-to-KMS, KMS-to-KMS) validates the caller's wallet address against these registries.

### 2. Mutual Authentication (The "Handshake")
*   **Mechanism**: Lightweight Proof-of-Possession (PoP) signatures (EIP-191).
*   **Flow**:
    1.  Caller requests a `nonce`.
    2.  Caller signs: `NovaKMS:Auth:<Nonce>:<Recipient_Wallet>:<Timestamp>`.
    3.  Recipient verifies signature and checks registry status.
    4.  Recipient returns a signed response: `NovaKMS:Response:<Caller_Sig>:<My_Wallet>`.

### 3. End-to-End Encryption (The "Tunnel")
*   **Mechanism**: NIST P-384 ECDH + AES-256-GCM.
*   **Key**: Uses the separate `teePubkey` (P-384) registered on-chain.
*   **Benefit**: Ensures confidentiality even if TLS is terminated at a load balancer.

### 4. Data Integrity (The "Guard")
*   **Mechanism**: HMAC-SHA256 Sync Signatures.
*   **Purpose**: Prevents "Split-Brain" or "Confused Deputy" attacks.
*   **Details**: All sync traffic is signed with a key derived from the Master Secret. Nodes **instantly reject** peers that don't share the same cluster secret, even if they are valid operators.

## Architecture Diagram

```mermaid
graph LR
  subgraph Apps["Nova Apps"]
    A1["App Instance (TEE wallet)"]
  end

  subgraph KMS["Nova KMS Cluster (Nitro Enclave)"]
    N1["KMS Node"]
    N2["KMS Node"]
  end

  subgraph Chain["Blockchain"]
    R["NovaAppRegistry\n(app → version → instance)"]
    K["KMSRegistry\n(operator set & master secret hash)"]
  end

  A1 -->|"PoP + E2E (P-384)"| N1
  N1 <-->|"PoP + HMAC + Sealed ECDH"| N2
  N1 -->|"Read-only eth_call"| R
  N1 -->|"Read-only eth_call"| K
  R -->|"addOperator/removeOperator callbacks"| K
```

## Anti-Split-Brain Initialization

To prevent cluster fragmentation, nodes follow a strict startup protocol:

1.  **Check Chain**: Read `masterSecretHash` from `KMSRegistry`.
2.  **If Hash == 0**:
    *   **Optimistic Init**: Generate new secret & attempt to set hash on-chain.
    *   **Defense**: Implementation uses `masterSecretHash` as a mutex—first successful transaction wins.
    *   **Retry**: If tx fails (race lost), loop back to step 1.
3.  **If Hash != 0**:
    *   **Verify**: Does my local secret match the hash?
        *   **Yes**: Node Ready.
        *   **No**: **Attempt Sync** from a verified peer.
            *   **Success** (Hash matches): Node Ready.
            *   **Failure** (Network error or Hash mismatch): Stay Offline (Retry Loop).

## Project Structure

```
nova-kms/
├── contracts/           # Solidity (KMSRegistry + tests)
├── enclave/             # Python KMS application
│   ├── app.py           # FastAPI entry point
│   ├── auth.py          # PoP auth & Registry integration
│   ├── kdf.py           # Key Derivation & Master Secret management
│   ├── secure_channel.py# E2E Encryption (P-384) & ECDH
│   ├── sync_manager.py  # Peer sync & HMAC logic
│   └── ...
├── tests/               # Python (pytest) & Solidity (forge) tests
├── docs/                # Detailed Documentation
├── Dockerfile           # Production Docker image
└── Makefile             # Developer commands
```

## Quick Start (Simulation)

To run a local simulation (no Enclave, mocked Registry):

```bash
# 1. Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r enclave/requirements.txt

# 2. Run
make simulation
# Listens on localhost:4000

# 3. Verify
curl http://localhost:4000/status
```

## Client Integration

Clients should use the `nova-kms-client` pattern (see `nova-examples/`):

1.  **Discover**: Query `NovaAppRegistry` for `ACTIVE` instances of the KMS App ID.
2.  **Authenticate**: Use `Odyn` SDK to sign PoP headers.
3.  **Encrypt**: Encrypt sensitive payloads using the target node's `teePubkey`.

## License

Apache-2.0