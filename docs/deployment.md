# Nova KMS Deployment Guide

This guide covers the current deployment flow for the Rust node and the `KMSRegistry` contract.

## 1. What Must Exist Before A Node Can Serve Traffic

You need:

1. a deployed `KMSRegistry`
2. a Nova app registered for KMS
3. the KMS app wired so its `dappContract` points to the `KMSRegistry`
4. `setKmsAppId()` called on `KMSRegistry`
5. at least one ACTIVE, `zkVerified` KMS instance registered in `NovaAppRegistry`

Without that wiring, `node_tick()` will never mark the service available.

## 2. Deploy `KMSRegistry`

From [contracts/](../contracts):

```bash
cd contracts
make install
make build
make test
```

Deploy:

```bash
export RPC_URL=https://sepolia.base.org
export NOVA_APP_REGISTRY_PROXY=0x...
export PRIVATE_KEY=0x...

make deploy
```

The deploy script creates `KMSRegistry(initialOwner, novaAppRegistry)`.

## 3. Bind The KMS App ID

Once Nova assigns the KMS app an `appId`, set it exactly once:

```bash
export RPC_URL=https://sepolia.base.org
export CONTRACT_ADDRESS=0x...
export PRIVATE_KEY=0x...
export KMS_APP_ID=49

make set-app-id
```

Current contract behavior:

- `kmsAppId` can only be set once
- `setMasterSecretHash()` can be called only while `masterSecretHash == 0`
- the caller must be:
  - an ACTIVE instance of `kmsAppId`
  - on a version whose status is ENROLLED

Operational implication:

- a node on a DEPRECATED version can still join the peer set
- it cannot be the node that seeds `masterSecretHash`

## 4. Register The App Correctly In Nova

The Nova-side KMS app must point its `dappContract` to the deployed `KMSRegistry`.

That enables:

- `addOperator(...)`
- `removeOperator(...)`

Those callbacks maintain the contract operator list, but the runtime node still discovers peers from `NovaAppRegistry`, not from `KMSRegistry.getOperators()`.

## 5. Build The Node Image

From the repository root:

```bash
make build-docker
```

Or:

```bash
docker build -t nova-kms:latest .
```

## 6. Runtime Configuration

Canonical environment variables to set in deployment:

```ini
IN_ENCLAVE=true
LOG_LEVEL=INFO
BIND_ADDR=0.0.0.0:8000

NODE_URL=http://127.0.0.1:18545
NODE_INSTANCE_URL=https://kms-1.example.com
NODE_WALLET=0x...

NOVA_APP_REGISTRY_ADDRESS=0x...
KMS_REGISTRY_ADDRESS=0x...
KMS_APP_ID=49

KMS_NODE_TICK_SECONDS=60
DATA_SYNC_INTERVAL_SECONDS=10
PEER_CACHE_TTL_SECONDS=180
REGISTRY_CACHE_TTL_SECONDS=180
```

Optional:

- `MASTER_SECRET_HEX`
  - use only when you intend to seed a known cluster secret

Notes:

- in enclave mode, the node refreshes `NODE_WALLET` from Odyn at startup and during `node_tick`
- if `NODE_INSTANCE_URL` is left empty, the node backfills it from the registry entry for its own wallet once peer refresh succeeds
- peer URLs must be `https` in enclave mode

## 7. Enclave Runtime Assumptions

The current code assumes:

- chain RPC is reachable at `NODE_URL`
- Odyn is reachable at `http://127.0.0.1:18000`
- the instance has a registered `teePubkey` and wallet in `NovaAppRegistry`

If peer refresh succeeds, the node also probes each peer `/status` with a 3-second timeout and exposes that metadata through `/nodes`.

## 8. Startup Sequence

The real startup path is:

1. load config
2. create shared state
3. start background tasks
4. `node_tick()` runs immediately
5. peer refresh reads `NovaAppRegistry`
6. the node verifies:
   - it is present in current KMS membership
   - its local `teePubkey` matches its own registry entry
7. the node reads `KMSRegistry.masterSecretHash`
8. if the on-chain hash is zero:
   - use `MASTER_SECRET_HEX` if already configured, otherwise generate 32 random bytes
   - compute `keccak256(master_secret)`
   - call `setMasterSecretHash`
   - stay unavailable until the chain reflects the hash
9. if the on-chain hash is non-zero and local state does not match:
   - request the sealed master secret from a verified peer
   - immediately request a full snapshot from that same peer
10. derive the sync HMAC key
11. set `service_available=true`

`sync_tick()` does not help with readiness. It only pushes deltas after the node is already available.

## 9. Probes And Operational Checks

### 9.1 HTTP Checks

```bash
curl https://<kms-node>/health
curl https://<kms-node>/status
curl https://<kms-node>/nodes
```

Use them this way:

- `/health`
  - liveness only
- `/status`
  - readiness, master-secret state, store metrics
- `/nodes`
  - current peer-cache view and probe metadata

### 9.2 Contract Checks

```bash
cast call <KMS_REGISTRY_ADDRESS> "kmsAppId()" --rpc-url <RPC_URL>
cast call <KMS_REGISTRY_ADDRESS> "masterSecretHash()" --rpc-url <RPC_URL>
cast call <KMS_REGISTRY_ADDRESS> "isOperator(address)" <TEE_WALLET> --rpc-url <RPC_URL>
cast call <KMS_REGISTRY_ADDRESS> "novaAppRegistry()" --rpc-url <RPC_URL>
cast call <KMS_REGISTRY_ADDRESS> "OWNER()" --rpc-url <RPC_URL>
```

## 10. Multi-Node Behavior

### 10.1 Discovery

Each node discovers peers through:

1. `getActiveInstances(KMS_APP_ID)`
2. `getInstanceByWallet(wallet)`
3. `getVersion(app_id, version_id)`

Peers are accepted when:

- instance ACTIVE
- `zkVerified=true`
- version ENROLLED or DEPRECATED
- URL passes local policy

### 10.2 Replication

Once available, each node:

- pushes deltas every `DATA_SYNC_INTERVAL_SECONDS`
- accepts inbound deltas on `/sync`
- can serve full snapshots on demand

There is no persistent local database. A restarted node rebuilds store state from peers after it has the correct master secret.

## 11. Common Unavailable States

The node will keep `/kms/*` unavailable when it reaches conditions such as:

- peer cache refresh failed and no peers are cached
- self wallet not present in current KMS membership
- local `teePubkey` mismatch with registry
- chain `masterSecretHash` unreadable
- failed master-secret convergence

Read the exact current reason from:

- `/status.node.service_available`
- `/status.node.master_secret`

## 12. Rotation And Emergency Actions

Owner-only contract action:

```bash
export RPC_URL=https://sepolia.base.org
export CONTRACT_ADDRESS=0x...
export PRIVATE_KEY=0x...

make reset-secret-hash
```

This resets `masterSecretHash` to zero. After that, the cluster must converge again from a fresh bootstrap cycle.
