# Nova KMS — Developer Guide

## Overview

This guide covers local development setup for the Nova KMS distributed Key Management Service.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.11+ | Enclave application |
| pip | latest | Python package manager |
| Foundry | latest | Solidity contracts |
| Docker | 24+ | Container builds |
| Node.js | 18+ | (optional, for portal frontend) |

## Project Structure

```
nova-kms/
├── contracts/                    # Solidity smart contracts
│   ├── src/
│   │   ├── KMSRegistry.sol       # Main KMS node registry
│   │   └── interfaces/
│   │       └── INovaAppInterface.sol
│   ├── test/
│   │   └── KMSRegistry.t.sol     # Foundry unit tests
│   ├── script/
│   │   └── DeployKMSRegistry.s.sol
│   └── foundry.toml
├── enclave/                      # Python KMS application
│   ├── app.py                    # FastAPI entry point
│   ├── config.py                 # Configuration constants
│   ├── odyn.py                   # Odyn SDK wrapper (DO NOT MODIFY)
│   ├── chain.py                  # Blockchain / RPC helpers
│   ├── nova_registry.py          # NovaAppRegistry read wrapper
│   ├── kms_registry.py           # KMSRegistry read-only wrapper
│   ├── auth.py                   # App authorization via PoP + registry
│   ├── kdf.py                    # HKDF key derivation + sealed exchange
│   ├── secure_channel.py         # P-384 teePubkey validation + ECDH
│   ├── data_store.py             # In-memory KV store (vector clocks)
│   ├── sync_manager.py           # Peer synchronization
│   ├── probe.py                  # Liveness probing
│   ├── routes.py                 # API endpoint definitions
│   └── requirements.txt
├── scripts/                      # Helper scripts
├── tests/                        # Python unit & integration tests
│   ├── test_auth.py
│   ├── test_data_store.py
│   ├── test_encryption.py
│   ├── test_integration_pop.py
│   ├── test_kdf.py
│   ├── test_kms_registry.py
│   ├── test_nova_registry.py
│   ├── test_registry_abi.py
│   ├── test_routes.py
│   ├── test_secure_channel.py    # P-384 ECDH + identity verification
│   ├── test_security.py
│   └── test_sync.py
├── docs/
│   ├── architecture.md           # Design document
│   ├── development.md            # This file
│   ├── testing.md                # Testing guide
│   └── deployment.md             # Deployment guide
├── Dockerfile                    # Production Docker image
├── Makefile                      # Project management
├── enclaver.yaml                 # Enclaver configuration
├── nova-build.yaml               # Nova Platform build config
└── README.md
```

## Local Development Setup

### 1. Clone and Setup Python Environment

```bash
cd nova-kms

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r enclave/requirements.txt
pip install pytest httpx  # for testing
```

### 2. Configure `enclave/config.py`

Edit the configuration constants:

```python
# config.py — fill in your values
CHAIN_ID = 84532  # Base Sepolia
NOVA_APP_REGISTRY_ADDRESS = "0x..."   # NovaAppRegistry proxy
KMS_REGISTRY_ADDRESS = "0x..."        # Deployed KMSRegistry
KMS_APP_ID = 0                        # Assigned by NovaAppRegistry
```

### 3. Run the Application Locally

```bash
# From the nova-kms directory
cd enclave
python app.py
```

### 4. Test API Endpoints
 
 ```bash
 # Health check
 curl http://localhost:8000/health
 
 # Status
 curl http://localhost:8000/status
 ```
 
 > **Note:** In production (inside enclave), the service requires PoP headers (`x-app-signature`, `x-app-nonce`, `x-app-timestamp`). For local development, overrides may apply if the `IN_ENCLAVE` environment variable is set to `false` (for example, `export IN_ENCLAVE=false` before running; see config documentation), but full identity verification still requires valid on-chain registration.

---

## Local Development
 
 The `nova-kms` application is designed to run in a trusted execution environment. For local development, you can run the application directly, but it will lack the cryptographic attestation context.
 
 ### 1. Setup Python Environment
 
 ```bash
 cd nova-kms
 python3 -m venv .venv
 source .venv/bin/activate
 pip install -r enclave/requirements.txt
 ```
 
 ### 2. Configuration
 
 Ensure `enclave/config.py` is configured with valid contract addresses for your chain.
 
 ### 3. Run
 
 ```bash
 cd enclave
 python app.py
 ```

---

## Contract Development

### Setup Foundry

```bash
cd contracts

# Install dependencies
make install

# Build
make build

# Test
make test

# Format
make fmt
```

### Deploy KMSRegistry (Testnet)

```bash
export NOVA_APP_REGISTRY_PROXY=0x...  # NovaAppRegistry proxy address
export KMS_APP_ID=...                  # KMS app ID from NovaAppRegistry
export PRIVATE_KEY=0x...               # Deployer private key

make deploy
```

## Module Overview

### `odyn.py` — Platform SDK (DO NOT MODIFY)
Standard TEE SDK. Auto-detects enclave vs dev mode. Provides:
- `eth_address()` — TEE wallet address
- `sign_message(msg)` — EIP-191 signing for PoP
- `get_random_bytes()` — hardware RNG
- `s3_put/get/delete` — persistent storage (not used by KMS)

### `chain.py` — Blockchain Helpers
`Chain` class wrapping Web3.py. Key functions:
- `wait_for_helios()` — blocks until RPC is synced
- `eth_call(to, data)` — read-only call
- `eth_call_finalized(to, data)` — read-only call at confirmed block depth

### `auth.py` — Authorization
`AppAuthorizer` verifies the caller identity (from PoP signer wallet) against NovaAppRegistry:
1. `getInstanceByWallet(teeWallet)` → instance
2. Check `ACTIVE` + `zkVerified`
3. `getApp(appId)` → `ACTIVE`
4. `getVersion(appId, versionId)` → `ENROLLED`

### `kms_registry.py` — KMSRegistry (contract wrapper)
Wraps the on-chain `KMSRegistry` contract for:

- reads: operator set (optional for external tooling) and `masterSecretHash`
- writes (bootstrap/maintenance): `setMasterSecretHash` and owner-only `resetMasterSecretHash`

In the current implementation, the KMS node lifecycle is **mostly** read-only on-chain, but during bootstrap (when `masterSecretHash == 0x0`) an eligible node will submit a single `setMasterSecretHash` transaction.

### `kdf.py` — Key Derivation
Uses HKDF-SHA256. `MasterSecretManager` holds the cluster secret.


### `data_store.py` — KV Store
In-memory only. `VectorClock` for causal ordering. `DataRecord` with TTL and tombstone support.
Per-app namespace isolation. LRU eviction when quota exceeded.

### `sync_manager.py` — Peer Sync
- **Delta push**: periodic push of recent changes
- **Snapshot**: full state transfer for rehydration
- **Master secret sharing**: new nodes receive secret from peers

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IN_ENCLAVE` | Enclave mode switch (`true` uses local Helios endpoint and strict auth rules) | `true` |
| `HELIOS_RPC_URL` | Optional override for local Helios JSON-RPC endpoint | `http://127.0.0.1:18545` (when `IN_ENCLAVE=true`) |
| `NODE_URL` | Public URL of this KMS node | (empty) |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |
