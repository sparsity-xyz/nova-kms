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
│  │  │ :8000     │  │ :18545     │  │ :18000  │ │         │
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

Save the deployed `KMSRegistry` contract address (non-upgradeable deployment in current code).

### 1.3 Configure KMS App ID

Once the KMS application is created in the Nova Platform and you have an `appId`:

```bash
export CONTRACT_ADDRESS=<KMS_REGISTRY_ADDRESS>
export KMS_APP_ID=<ASSIGNED_APP_ID>
make set-app-id
```

### 1.4 Verify

```bash
# Check the deployment
cast call <KMS_REGISTRY_ADDRESS> "kmsAppId()" --rpc-url https://sepolia.base.org
cast call <KMS_REGISTRY_ADDRESS> "OWNER()" --rpc-url https://sepolia.base.org
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
defaults:
  cpu_count: 2
  memory_mb: 4096     # Adjust based on expected data size

helios_rpc:
  enabled: true
  chains:
    - name: "L2-base-sepolia"
      network_id: "84532"
      kind: opstack
      network: base-sepolia
      execution_rpc: "https://sepolia.base.org"
      local_rpc_port: 18545
```

For `nova-kms`, omit `storage.s3` entirely (the service is intentionally non-persistent).

Runtime reads registry/auth-chain RPC from `http://127.0.0.1:18545` by default.
Set `HELIOS_RPC_URL` only if you intentionally need a different local endpoint.

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
5. KMS node discovers peers by enumerating `ACTIVE` KMS instances from `NovaAppRegistry` (scoped by `KMS_APP_ID`, with version status not `REVOKED`)
6. Reads `masterSecretHash` from `KMSRegistry`
7. If `masterSecretHash == 0x0` (bootstrap):
  - generates a fresh master secret from Odyn hardware RNG (if needed)
  - computes `keccak256(master_secret)` and submits **one** `setMasterSecretHash` transaction (eligible callers are enforced by `KMSRegistry` via NovaAppRegistry checks)
  - stays `503 Unavailable` until the on-chain hash becomes non-zero and matches
8. If `masterSecretHash != 0x0` (running):
  - ensures the local master secret hash matches the on-chain hash
  - if missing/mismatched, syncs the master secret from a verified peer via sealed ECDH over `/sync`
9. Starts periodic `node_tick` scheduling and begins serving API requests once the node is marked available

> **Note:** KMS nodes are *mostly* read-only on-chain. The only routine write in the current implementation is the one-time `setMasterSecretHash` during cluster bootstrap when the hash is unset.

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
#   "cluster": {"total_instances": 3, ...},
#   "data_store": {"namespaces": 0, "total_keys": 0, "total_bytes": 0}
# }
```

### 5.3 Verify On-Chain Registration

```bash
# Optional: Inspect KMSRegistry on-chain state.
# Note: the KMS service's runtime peer discovery uses NovaAppRegistry (via PeerCache),
# not the operator list in KMSRegistry. These calls are useful for auditing.

# Check if the node's wallet is present in the KMSRegistry operator set
cast call <KMS_REGISTRY_ADDRESS> \
  "isOperator(address)" <TEE_WALLET_ADDRESS> \
  --rpc-url https://sepolia.base.org

# List all operator wallets tracked by KMSRegistry
cast call <KMS_REGISTRY_ADDRESS> \
  "getOperators()" \
  --rpc-url https://sepolia.base.org

# Read the current master secret hash coordination value
cast call <KMS_REGISTRY_ADDRESS> \
  "masterSecretHash()" \
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

Nodes discover each other via `NovaAppRegistry` (scoped by `KMS_APP_ID` → `ACTIVE` instances with non-`REVOKED` version). No external service discovery is required.

### Master Secret Propagation

- **First node**: generates master secret from hardware RNG
- **Subsequent nodes**: request secret from an existing healthy peer via `/sync`
- All nodes share the same master secret → identical key derivation results

### Consistency Model

- **Eventual consistency** via vector-clock-based sync
- **LWW** (Last-Writer-Wins) for concurrent conflicts
- **Delta sync** every `DATA_SYNC_INTERVAL_SECONDS` (default: 10s)
- **Snapshot sync** for nodes that are far behind

## Monitoring

### Key Metrics to Watch

| Metric | Source | Alert Threshold |
|--------|--------|-----------------|
| `/health` response | HTTP probe | Non-200 for >30s |
| `cluster.total_instances` | `/status` | Below expected count |
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
# KMSRegistry uses Ownable2StepUpgradeable (UUPS). Ownership transfer is two-step.

# 1) Current owner nominates the new owner
cast send <KMS_REGISTRY_ADDRESS> \
  "transferOwnership(address)" <NEW_OWNER> \
  --private-key <CURRENT_OWNER_KEY> \
  --rpc-url https://sepolia.base.org

# 2) New owner accepts
cast send <KMS_REGISTRY_ADDRESS> \
  "acceptOwnership()" \
  --private-key <NEW_OWNER_KEY> \
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
