# Nova KMS - Smart Contracts

This directory contains the Solidity smart contracts for the Nova KMS (Key Management Service) node registry.

## Overview

The core contract is `KMSRegistry.sol`. It is responsible for:
- Tracking active KMS operators (nodes).
- Receiving callbacks from the platform's `NovaAppRegistry` when instances are added or removed.
- Providing a secure list of authorized KMS peers for cluster synchronization and master secret sharing.

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (forge, cast)
- [Make](https://www.gnu.org/software/make/)

## Setup

1. **Install dependencies**:
   ```bash
   make install
   ```

2. **Build contracts**:
   ```bash
   make build
   ```

## Testing

Run the test suite using Foundry:
```bash
make test
```

## Deployment Flow

The deployment process uses Foundry scripts and is automated via the `Makefile`.

### 1. Environment Configuration

Copy the example environment file and fill in your details:
```bash
cp .env.example .env
```

Or export the following variables in your shell:

| Variable | Description |
|----------|-------------|
| `RPC_URL` | The RPC endpoint for the target network (e.g., Base Sepolia) |
| `PRIVATE_KEY` | Hex-encoded private key of the deployer |
| `NOVA_APP_REGISTRY_PROXY` | Address of the `NovaAppRegistry` proxy contract |
| `KMS_APP_ID` | The Application ID assigned to Nova KMS by the platform |

### 2. Deploy `KMSRegistry`

Run the deployment script:
```bash
make deploy
```

The script will:
1. Deploy `KMSRegistry` with the configured `NOVA_APP_REGISTRY_PROXY` and `KMS_APP_ID`.
2. Output the deployed contract address.

### 3. Post-Deployment: Platform Registration

After deployment, you **must** register the `KMSRegistry` address with the Nova Platform:

1. Locate your KMS application in the `NovaAppRegistry`.
2. Set the `dappContract` field to the address of the newly deployed `KMSRegistry`.
3. This ensures that when a new KMS node is successfully verified (ZKP), the platform automatically calls `addOperator` on your contract.

## Contract Verification

In the UUPS pattern, you must verify the **Implementation** contract.

### 1. Verify Implementation
Find the `KMSRegistry Implementation` address from your deployment output:
```bash
export CONTRACT_ADDRESS=0x_IMPLEMENTATION_ADDRESS
make verify-basescan # or verify-blockscout
```

### 2. Link Proxy on Explorer
Once the implementation is verified:
1. Go to the **Proxy** address on Basescan.
2. Go to the "Contract" tab.
3. Click "More Options" -> "Is this a proxy?".
4. Follow the prompts to verify the Proxy and link it to the implementation.

### Management Operations

#### Set KMS App ID
If you deployed with App ID 0 or need to update it:
```bash
export CONTRACT_ADDRESS=0x_PROXY_ADDRESS
export KMS_APP_ID=your_assigned_id
make set-app-id
```

#### Manual Check
Example manual check (using `cast`):
```bash
# Check if a node is an operator
cast call <KMSRegistry_Address> "isOperator(address)" <Node_Wallet_Address> --rpc-url <RPC_URL>
```
