# Nova KMS — Deployment Guide

## Overview

This guide covers deploying Nova KMS to production on the Nova Platform (AWS Nitro Enclave).

## Deployment Architecture

```
┌──────────────────────────────────────────────────────────┐
│  AWS Nitro Enclave                                       │
│  ┌─────────────────────────────────────────────┐         │
│  │  nova-kms (Docker)                          │         │
│  │  ┌──────────┐  ┌────────────┐  ┌─────────┐ │         │
│  │  │ FastAPI   │  │ Helios RPC │  │ Odyn API│ │         │
│  │  │ :8000     │  │ :8545      │  │ :18000  │ │         │
│  │  └──────────┘  └────────────┘  └─────────┘ │         │
│  └─────────────────────────────────────────────┘         │
│                                                          │
│  ┌──────────────────┐                                    │
│  │ ZKP Verification │                                    │
│  │ Service          │                                    │
│  └──────────────────┘                                    │
└──────────────────────────────────────────────────────────┘
         │
    Base Sepolia
    ┌────────────────┐  ┌────────────────────┐
    │ KMSRegistry    │  │ NovaAppRegistry    │
    │ (deployed)     │  │ (platform-managed) │
    └────────────────┘  └────────────────────┘
```

## Prerequisites

1. **Nova Platform Account** with admin access
2. **NovaAppRegistry** proxy address (provided by platform)
3. **KMS App** created in NovaAppRegistry (note the assigned `appId`)
4. **KMSRegistry** contract deployed and configured
5. **Docker** for building the enclave image
6. **Foundry** (if deploying contracts)

## Step 1: Deploy KMSRegistry Contract

### 1.1 Configure Environment

```bash
cd nova-kms/contracts

export NOVA_APP_REGISTRY_PROXY=0x...   # NovaAppRegistry proxy address
export PRIVATE_KEY=0x...                # Deployer private key (admin)
```

### 1.2 Deploy

```bash
make deploy
```

Save the deployed **Proxy** contract address (the stable entry point) and the **Implementation** address (which contains the logic). You will primarily use the Proxy address for integration.

### 1.3 Configure KMS App ID

Once the KMS application is created in the Nova Platform and you have an `appId`:

```bash
export PROXY_ADDRESS=<KMS_REGISTRY_PROXY_ADDRESS>
export KMS_APP_ID=<ASSIGNED_APP_ID>
make set-app-id
```

### 1.4 Verify

```bash
# Check the deployment
cast call <KMS_REGISTRY_ADDRESS> "kmsAppId()" --rpc-url https://sepolia.base.org
cast call <KMS_REGISTRY_ADDRESS> "owner()" --rpc-url https://sepolia.base.org
```

## Step 2: Configure the Enclave Application

### 2.1 Update `enclave/config.py`

```python
CHAIN_ID = 84532
NOVA_APP_REGISTRY_ADDRESS = "0x..."     # NovaAppRegistry proxy
KMS_REGISTRY_ADDRESS = "0x..."          # KMSRegistry (from Step 1)
KMS_APP_ID = ...                        # appId assigned by platform
```

### 2.2 Update `enclaver.yaml`

```yaml
storage:
  s3:
    enabled: false    # KMS is non-persistent

defaults:
  cpu_count: 2
  memory_mb: 4096     # Adjust based on expected data size

helios_rpc:
  enabled: true
  kind: opstack
  network: base-sepolia
  listen_port: 8545
  execution_rpc: "https://sepolia.base.org"
```

## Step 3: Build the Docker Image

```bash
make build-docker
```

Or manually from the root directory:
```bash
docker build -t nova-kms:latest .
```

## Step 4: Deploy via Nova Platform

### 4.1 Register as Nova App

If not already done, create the KMS application in the Nova Platform:

```bash
# Use nova-cli or platform dashboard
# 1. Create app → get appId
# 2. Register version with code measurement
# 3. Enable ZK verification
```

### 4.2 Deploy to Nitro Enclave

The Nova Platform handles:
1. Pushing the Docker image to the enclave
2. Running enclaver with the `enclaver.yaml` configuration
3. Setting up the vsock proxy for network access
4. Exposing the enclave ingress port(s)

### 4.3 Automatic Startup Sequence

On boot, the KMS node:
1. Waits for Helios light client to sync
2. Gets its TEE wallet address from Odyn
3. ZKP service verifies the enclave and registers the instance in NovaAppRegistry
4. NovaAppRegistry calls `KMSRegistry.addOperator()` → node is discoverable
5. KMS node queries `getOperators()` + `getInstanceByWallet()` to discover peers
6. Attempts to receive master secret from an existing peer
7. If no peers exist, generates a new master secret from hardware RNG
8. Starts the sync scheduler
9. Begins serving API requests

> **Note:** KMS nodes do NOT submit any on-chain transactions. Operator management is fully handled by NovaAppRegistry callbacks to KMSRegistry.

## Step 5: Verify Deployment

### 5.1 Check Health

```bash
curl https://<kms-node-url>/health
# {"status": "healthy"}
```

### 5.2 Check Status

```bash
curl https://<kms-node-url>/status
# {
#   "node": {"tee_wallet": "0x...", "is_operator": true, ...},
#   "cluster": {"total_operators": 3, ...},
#   "data_store": {"namespaces": 0, "total_keys": 0, "total_bytes": 0}
# }
```

### 5.3 Verify On-Chain Registration

```bash
# Check if the node's wallet is a registered operator
cast call <KMS_REGISTRY_ADDRESS> \
  "isOperator(address)" <TEE_WALLET_ADDRESS> \
  --rpc-url https://sepolia.base.org

# List all operators
cast call <KMS_REGISTRY_ADDRESS> \
  "getOperators()" \
  --rpc-url https://sepolia.base.org
```

## Multi-Node Deployment

### Scaling Strategy

Deploy multiple KMS nodes for high availability:

```
KMS Node 1  ←→  KMS Node 2  ←→  KMS Node 3
     ↕               ↕               ↕
  KMSRegistry (shared on-chain membership)
```

### Node Discovery

Nodes discover each other via `KMSRegistry.getOperators()` → `NovaAppRegistry.getInstanceByWallet()`. No external service discovery needed.

### Master Secret Propagation

- **First node**: generates master secret from hardware RNG
- **Subsequent nodes**: request secret from an existing healthy peer via `/sync`
- All nodes share the same master secret → identical key derivation results

### Consistency Model

- **Eventual consistency** via vector-clock-based sync
- **LWW** (Last-Writer-Wins) for concurrent conflicts
- **Delta sync** every `SYNC_INTERVAL_SECONDS` (default: 60s)
- **Snapshot sync** for nodes that are far behind

## Monitoring

### Key Metrics to Watch

| Metric | Source | Alert Threshold |
|--------|--------|-----------------|
| `/health` response | HTTP probe | Non-200 for >30s |
| `cluster.total_operators` | `/status` | Below expected count |
| `data_store.total_bytes` | `/status` | Approaching `MAX_APP_STORAGE` |
| Sync success rate | Application logs | <50% peer sync success |
| On-chain `isOperator` | KMSRegistry | Unexpected removal |

### Logging

Application logs are written to stdout (captured by the enclave runtime):

```
2024-01-15 10:30:00 [INFO] nova-kms: === Nova KMS started successfully ===
2024-01-15 10:30:00 [INFO] nova-kms: TEE wallet: 0x...
2024-01-15 10:30:00 [INFO] nova-kms: This node is a registered KMS operator
2024-01-15 10:31:00 [INFO] nova-kms.sync: Delta push: 2/2 peers synced
```

## Emergency Operations

### Remove an Operator

Operators are managed by NovaAppRegistry. To remove an operator, stop or deregister its instance on NovaAppRegistry, which triggers `removeOperator` on KMSRegistry automatically.

### Transfer Admin

```bash
cast send <KMS_REGISTRY_ADDRESS> \
  "setAdmin(address)" <NEW_ADMIN> \
  --private-key <CURRENT_ADMIN_KEY> \
  --rpc-url https://sepolia.base.org
```

## Security Checklist

- [ ] KMSRegistry deployed with correct `novaAppRegistry` and `kmsAppId`
- [ ] Admin key stored securely (hardware wallet recommended)
- [ ] `NODE_URL` set to the correct public HTTPS endpoint
- [ ] All nodes running the same code measurement (version)
- [ ] ZK verification enabled for the KMS app in NovaAppRegistry
- [ ] No trusted proxies in front of the enclave app (PoP auth is verified in-app)
- [ ] Firewall allows egress to Base Sepolia RPC
- [ ] At least 2 nodes deployed for redundancy
