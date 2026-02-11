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
│   ├── simulation.py             # Simulation mode (fake registries)
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
├── scripts/                      # Bash scripts for development
│   ├── run_dev.sh                # Single-node simulation launcher
│   └── run_multi_node.sh         # Multi-node simulation launcher
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
│   ├── test_simulation.py
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

The server starts on `http://localhost:8000`. In dev mode:

- If you want **dev/sim identity headers** (`x-tee-wallet`) to work, set `IN_ENCLAVE=false` (header-based identity is blocked when `IN_ENCLAVE=true` and `SIMULATION_MODE=false`).
- When `IN_ENCLAVE=false`, peer HTTPS enforcement is relaxed and plaintext fallbacks can be enabled for local testing.

### 4. Test API Endpoints

```bash
# Health check
curl http://localhost:8000/health

# Status
curl http://localhost:8000/status

# Derive a key (with mock auth headers)
curl -X POST http://localhost:8000/kms/derive \
  -H "Content-Type: application/json" \
  -H "x-tee-wallet: 0x1234567890abcdef1234567890abcdef12345678" \
  -d '{"path": "my_key", "context": "v1"}'

# Put data
curl -X PUT http://localhost:8000/kms/data \
  -H "Content-Type: application/json" \
  -H "x-tee-wallet: 0x1234567890abcdef1234567890abcdef12345678" \
  -d '{"key": "test", "value": "aGVsbG8="}'

# Get data
curl http://localhost:8000/kms/data/test \
  -H "x-tee-wallet: 0x1234567890abcdef1234567890abcdef12345678"
```

> **Note:** In development mode, the auth header `x-tee-wallet` is accepted as a convenience identity shim. In production (inside enclave), header-based identity is disabled and the service requires PoP headers (`x-app-signature`, `x-app-nonce`, `x-app-timestamp`).

---

## Simulation Mode

Simulation mode lets you run one or more KMS nodes locally **without any blockchain connection** (no Helios, no on-chain contracts). It replaces on-chain registries with in-memory fakes while keeping the exact same auth, sync, and key-derivation logic. A local in-process signer is used to support PoP flows.

### Quick Start — Single Node

```bash
make simulation
```

The server starts on `http://localhost:4000` with:
- 3 default simulated peers (deterministic wallets derived from seeds)
- Deterministic master secret (`SHA256("nova-kms-simulation-master-secret")`)
- Open auth mode: any `x-tee-wallet` header is accepted

### Quick Start — Multi-Node (3 nodes)

```bash
make simulation-multi
# To stop:
make stop-simulation
```

Or manually:

```bash
SIMULATION_MODE=1 SIM_NODE_INDEX=0 SIM_PORT=4000 python app.py &
SIMULATION_MODE=1 SIM_NODE_INDEX=1 SIM_PORT=4001 python app.py &
SIMULATION_MODE=1 SIM_NODE_INDEX=2 SIM_PORT=4002 python app.py &
```

### How It Works

| Production | Simulation |
|-----------|------------|
| `Odyn` SDK ➜ TEE wallet | Wallet from `DEFAULT_SIM_PEERS[SIM_NODE_INDEX]` |
| `KMSRegistryClient` (on-chain) | `SimKMSRegistryClient` (in-memory list) |
| `NovaRegistry` (on-chain) | `SimNovaRegistry` (in-memory, open auth) |
| Hardware RNG master secret | `SHA256("nova-kms-simulation-master-secret")` |
| Helios light-client ➜ RPC | Skipped entirely |
| `AppAuthorizer` | **Same class**, backed by sim registries |

The toggle is controlled by `SIMULATION_MODE` environment variable (takes precedence) or `config.SIMULATION_MODE` constant.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SIMULATION_MODE` | Enable simulation mode (`1`, `true`, `yes`) | off |
| `SIM_NODE_INDEX` | Index in peer list for this node's identity | `0` |
| `SIM_PORT` | Override the listening port | `4000` |
| `SIM_PEERS_CSV` | Override peer list: `wallet\|url,wallet\|url,...` | use defaults |
| `SIM_MASTER_SECRET` | Hex-encoded 32-byte master secret | deterministic |

### Config Constants

In `enclave/config.py`:

```python
SIMULATION_MODE: bool   # Fallback if env var not set (default: False)
SIM_PEERS: list         # List of SimPeer objects to use instead of defaults
SIM_MASTER_SECRET_HEX: str  # Hex-encoded master secret override
```

### Testing a Complete Flow

```bash
# Terminal 1: Start node 0
SIMULATION_MODE=1 SIM_NODE_INDEX=0 python enclave/app.py

# Terminal 2: Derive a key
curl -X POST http://localhost:4000/kms/derive \
  -H "Content-Type: application/json" \
  -H "x-tee-wallet: 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  -d '{"path": "app/secrets/api_key"}'

# Terminal 2: Store data
curl -X PUT http://localhost:4000/kms/data \
  -H "Content-Type: application/json" \
  -H "x-tee-wallet: 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  -d '{"key": "config", "value": "eyJrZXkiOiAidmFsdWUifQ=="}'

# Terminal 2: Read data
curl http://localhost:4000/kms/data/config \
  -H "x-tee-wallet: 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

### Architecture Diagram

```
  ┌─────────────────────────────────────┐
  │   is_simulation_mode()?             │
  │     ├── YES ──► build_sim_components│
  │     │           ├── SimKMSRegistry  │
  │     │           ├── SimNovaRegistry │
  │     │           └── deterministic   │
  │     │               master secret   │
  │     └── NO ──► _startup_production  │
  │                 ├── Helios/Odyn     │
  │                 ├── KMSRegistryClient│
  │                 └── NovaRegistry    │
  │                                     │
  │   Both paths converge to:           │
  │     routes.init(authorizer, ...)    │
  │     scheduler.start()               │
  └─────────────────────────────────────┘
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

> Note: simulation mode is guarded by `IN_ENCLAVE`. For local development, the
> helper scripts set `IN_ENCLAVE=false` so `SIMULATION_MODE=1` is allowed.

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_URL` | Public URL of this KMS node | (empty) |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |
| `SIMULATION_MODE` | Enable simulation mode (`1`/`true`/`yes`) | off |
| `SIM_NODE_INDEX` | Peer index for this node's identity | `0` |
| `SIM_PORT` | Override listening port in sim mode | `4000` |
| `SIM_PEERS_CSV` | Peer list override: `wallet\|url,wallet\|url` | default 3 peers |
| `SIM_MASTER_SECRET` | Hex-encoded 32-byte master secret | deterministic |
