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
│   │       └── INovaAppRegistry.sol
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
│   ├── auth.py                   # App authorization via Nitro attestation + registry
│   ├── kdf.py                    # HKDF key derivation + CA
│   ├── data_store.py             # In-memory KV store (vector clocks)
│   ├── sync_manager.py           # Peer synchronization
│   ├── probe.py                  # Liveness probing
│   ├── routes.py                 # API endpoint definitions
│   ├── run_dev.sh                # Single-node simulation launcher
│   ├── run_multi_node.sh         # Multi-node simulation launcher
│   ├── requirements.txt
│   └── Dockerfile
├── tests/                        # Python unit & integration tests
│   ├── test_simulation.py        # Simulation mode tests (45 tests)
│   ├── test_auth.py
│   ├── test_data_store.py
│   ├── test_kdf.py
│   ├── test_routes.py
│   └── test_sync.py
├── docs/
│   ├── architecture.md           # Design document
│   ├── development.md            # This file
│   ├── testing.md                # Testing guide
│   └── deployment.md             # Deployment guide
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
- Odyn SDK connects to mock endpoint (`odyn.sparsity.cloud:18000`)
- Chain helper connects to mock RPC (`odyn.sparsity.cloud:8545`)
- KMS nodes do NOT submit on-chain transactions (operator management is handled by NovaAppRegistry callbacks)

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

> **Note:** In development mode, auth headers (`x-tee-wallet`, `x-tee-measurement`) substitute for production Nitro attestation. The authorizer will attempt to query the on-chain registry, so **set contract addresses** or mock them for full local testing — or use **Simulation Mode** (see below).

---

## Simulation Mode

Simulation mode lets you run one or more KMS nodes locally **without any blockchain connection** (no Helios, no Odyn, no on-chain contracts). It replaces on-chain registries with in-memory fakes while keeping the exact same auth, sync, and key-derivation logic.

### Quick Start — Single Node

```bash
cd enclave
SIMULATION_MODE=1 python app.py
# or
./run_dev.sh
```

The server starts on `http://localhost:8000` with:
- 3 default simulated peers (wallets `0xAAA…`, `0xBBB…`, `0xCCC…`)
- Deterministic master secret (`SHA256("nova-kms-simulation-master-secret")`)
- Open auth mode: any `x-tee-wallet` header is accepted

### Quick Start — Multi-Node (3 nodes)

```bash
cd enclave
./run_multi_node.sh         # Starts 3 nodes on 8000/8001/8002
./run_multi_node.sh stop    # Stop all
```

Or manually:

```bash
SIMULATION_MODE=1 SIM_NODE_INDEX=0 python app.py &  # port 8000
SIMULATION_MODE=1 SIM_NODE_INDEX=1 SIM_PORT=8001 python app.py &  # port 8001
SIMULATION_MODE=1 SIM_NODE_INDEX=2 SIM_PORT=8002 python app.py &  # port 8002
```

### How It Works

| Production | Simulation |
|-----------|------------|
| `Odyn` SDK ➜ TEE wallet | Wallet from `DEFAULT_SIM_PEERS[SIM_NODE_INDEX]` |
| `KMSRegistryClient` (on-chain) | `SimKMSRegistryClient` (in-memory list) |
| `NovaRegistry` (on-chain) | `SimNovaRegistry` (in-memory, open auth) |
| Hardware RNG master secret | `SHA256("nova-kms-simulation-master-secret")` |
| Helios light-client ➜ RPC | Skipped entirely |
| `AppAuthorizer` + `KMSNodeVerifier` | **Same classes**, backed by sim registries |

The toggle is controlled by `SIMULATION_MODE` environment variable (takes precedence) or `config.SIMULATION_MODE` constant.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SIMULATION_MODE` | Enable simulation mode (`1`, `true`, `yes`) | off |
| `SIM_NODE_INDEX` | Index in peer list for this node's identity | `0` |
| `SIM_PORT` | Override the listening port | `8000` |
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
curl -X POST http://localhost:8000/kms/derive \
  -H "Content-Type: application/json" \
  -H "x-tee-wallet: 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  -d '{"path": "app/secrets/api_key"}'

# Terminal 2: Store data
curl -X PUT http://localhost:8000/kms/data \
  -H "Content-Type: application/json" \
  -H "x-tee-wallet: 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  -d '{"key": "config", "value": "eyJrZXkiOiAidmFsdWUifQ=="}'

# Terminal 2: Read data
curl http://localhost:8000/kms/data/config \
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
- `sign_tx(tx)` — sign EIP-1559 transactions
- `get_attestation()` — Nitro attestation document
- `get_random_bytes()` — hardware RNG
- `s3_put/get/delete` — persistent storage (not used by KMS)

### `chain.py` — Blockchain Helpers
`Chain` class wrapping Web3.py. Key functions:
- `wait_for_helios()` — blocks until RPC is synced
- `eth_call(to, data)` — read-only call
- `sign_and_broadcast()` — build, sign via Odyn, broadcast

### `auth.py` — Authorization
`AppAuthorizer` verifies client attestation against NovaAppRegistry:
1. `getInstanceByWallet(teeWallet)` → instance
2. Check `ACTIVE` + `zkVerified`
3. `getApp(appId)` → `ACTIVE`
4. `getVersion(appId, versionId)` → `ENROLLED` or `DEPRECATED`
5. Match `codeMeasurement`

### `kms_registry.py` — KMSRegistry (read-only)
Queries operator list from the simplified KMSRegistry contract:
- `get_operators()` — list of operator addresses
- `is_operator(wallet)` — check if wallet is a KMS operator
- `operator_count()` / `operator_at(index)` — enumeration helpers

KMS nodes do NOT submit on-chain transactions. For full instance details,
use `NovaRegistry.get_instance_by_wallet(operator)`.

### `kdf.py` — Key Derivation
Uses HKDF-SHA256. `MasterSecretManager` holds the cluster secret.
`CertificateAuthority` signs CSRs using a CA key derived from the master secret.

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
| `IN_ENCLAVE` | Whether running inside Nitro Enclave | `False` |
| `NODE_URL` | Public URL of this KMS node | (empty) |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |
| `SIMULATION_MODE` | Enable simulation mode (`1`/`true`/`yes`) | off |
| `SIM_NODE_INDEX` | Peer index for this node's identity | `0` |
| `SIM_PORT` | Override listening port in sim mode | `8000` |
| `SIM_PEERS_CSV` | Peer list override: `wallet\|url,wallet\|url` | default 3 peers |
| `SIM_MASTER_SECRET` | Hex-encoded 32-byte master secret | deterministic |
