# Nova KMS — Developer Guide

## Overview

This guide covers local development setup for the Nova KMS distributed Key Management Service, now implemented in **Rust**.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | 1.76+ | KMS application |
| Cargo | latest | Rust package manager |
| Foundry | latest | Solidity contracts |
| Docker | 24+ | Container builds |

## Project Structure

```text
nova-kms/
├── contracts/                    # Solidity smart contracts
├── src/                          # Rust KMS application
│   ├── main.rs                   # Tokio entry & shutdown
│   ├── config.rs                 # Figment TOML config loader
│   ├── odyn.rs                   # Odyn TEE SDK wrapper
│   ├── registry.rs               # NovaAppRegistry & KMSRegistry wrapper (alloy)
│   ├── auth.rs                   # App authorization via PoP
│   ├── crypto.rs                 # HKDF key derivation + AES-GCM encryption
│   ├── store.rs                  # Thread-safe LWW KV store
│   ├── sync.rs                   # Active-active sync manager 
│   ├── server.rs                 # Axum API routing
│   └── models.rs                 # Shared types
├── tests/                        # Cross-language compatibility checks
├── docs/
│   ├── architecture.md           # Design document
│   ├── development.md            # This file
│   ├── testing.md                # Testing guide
│   └── deployment.md             # Deployment guide
├── Dockerfile                    # Production Docker image (Multi-stage Rust)
├── Makefile                      # Make shortcuts for Cargo
├── enclaver.yaml                 # Enclaver configuration
└── README.md
```

## Local Development Setup

### 1. Build and Run the Application

```bash
cd nova-kms

# Build the project
cargo build

# Run formatting checks
cargo fmt --all -- --check

# Run lints
cargo clippy --quiet

# Run tests
cargo test
```

### 2. Configure Environment Variables

The application utilizes `figment` to parse configuration out of environment variables. The variables broadly map back to the Python version's exact environment variable names:

| Variable | Description | Default |
|----------|-------------|---------|
| `NOVA_APP_REGISTRY_PROXY` | Proxy address for NovaAppRegistry | `0x...` |
| `KMS_REGISTRY_ADDRESS` | Address for deployed KMSRegistry contract | `0x...` |
| `KMS_APP_ID` | Assigned KMS App ID for derivation namespace | `0` |
| `NODE_URL` | Public URL of this KMS node | `http://localhost:8000` |
| `HELIOS_RPC_URL` | Override for local Helios JSON-RPC endpoint | `http://127.0.0.1:18545` |
| `IN_ENCLAVE` | Switch to verify strict TLS behaviors if necessary | `true` |

These can also be provided within a `Kms.toml` root file!

### 3. Running Locally

```bash
# Set required env vars
export KMS_APP_ID=49
export NODE_URL=http://localhost:8000

# Start server
cargo run
```

### 4. Test API Endpoints
 
 ```bash
 # Health check
 curl http://localhost:8000/health
 
 # Status
 curl http://localhost:8000/status
 ```
 
 > **Note:** In production (inside enclave), the service requires PoP headers (`x-app-signature`, `x-app-nonce`, `x-app-timestamp`). For local development, refer to `src/auth.rs` for verification details.

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
