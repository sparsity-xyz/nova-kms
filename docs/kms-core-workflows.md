# KMS Core Workflows

This document consolidates the core KMS workflows for deployment, node enrollment, node initialization, and Nova app access.

## KMS Registry Deployment Workflow

This workflow describes how to deploy the KMS registry and wire it into Nova App Registry so KMS nodes and Nova apps can discover it.

### Workflow

1. Set the Nova App Registry address in the deploy script or environment.
2. Deploy the KMS registry contract.
3. Record the deployed KMS registry address.
4. When creating the KMS app in Nova Platform, set the Nova App Registry contract address as a KMS app property.

### Mermaid Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Operator
    participant DeployScript as Deploy Script
    participant NovaRegistry as Nova App Registry
    participant KMSRegistry as KMS Registry

    Operator->>DeployScript: Set NOVA_APP_REGISTRY address
    Operator->>DeployScript: Deploy KMS registry
    DeployScript->>KMSRegistry: Create contract
    DeployScript-->>Operator: Output KMS registry address
    Operator->>NovaRegistry: Set KMS app property: Nova App Registry address
    NovaRegistry-->>Operator: Confirmation
```

## KMS Node Join Workflow

This workflow describes how a KMS node is enrolled into the KMS registry by Nova Platform.

### Workflow

1. The KMS service is registered as a Nova app, and the KMS registry contract address is set as the app contract address in Nova Platform.
2. Nova App Registry stores app metadata (KMS app id, KMS registry contract address), enrolled versions, and code measurements per version.
3. A KMS node is deployed on Nova Platform with the KMS registry as the app contract address.
4. Nova Platform generates a node ZK proof and verifies it on-chain.
5. Nova Platform verifies the node code measurement against the enrolled version.
6. If all checks pass, Nova Platform registers the node as a KMS app instance.
7. Nova App Registry calls `addOperator` on the KMS registry to add the node wallet.

### Mermaid Diagram

```mermaid
sequenceDiagram
    autonumber
    participant NovaPlatform as Nova Platform
    participant NovaRegistry as Nova App Registry
    participant Chain as Blockchain
    participant KMSRegistry as KMS Registry
    participant KMSNode as KMS Node

    NovaPlatform->>NovaRegistry: Register KMS app (app contract = KMS registry)
    NovaPlatform->>KMSNode: Deploy node with KMS registry address
    NovaPlatform->>Chain: Submit ZK proof
    Chain-->>NovaPlatform: ZK proof verified
    NovaPlatform->>NovaRegistry: Verify code measurement
    NovaPlatform->>NovaRegistry: Register KMS node instance
    NovaRegistry->>KMSRegistry: addOperator(teeWallet, appId, versionId, instanceId)
    KMSRegistry-->>NovaRegistry: Operator added
```

## KMS Node Initialization Workflow

This workflow describes how a KMS node initializes itself after deployment.

### Workflow

0. Configure the Nova App Registry and KMS registry addresses.
1. Query the KMS registry to get all operator wallets.
2. Query the Nova App Registry for instance details of each operator.
3. If this is the first KMS node, perform initial setup (master secret, namespace bootstrap).
4. If this is not the first node, synchronize from an existing KMS node.
5. Periodically repeat step 1 to refresh the operator list.

### Mermaid Diagram

```mermaid
sequenceDiagram
    autonumber
    participant KMSNode as KMS Node
    participant KMSRegistry as KMS Registry
    participant NovaRegistry as Nova App Registry
    participant PeerNode as Existing KMS Node

    KMSNode->>KMSNode: Load registry addresses
    KMSNode->>KMSRegistry: getOperators()
    KMSRegistry-->>KMSNode: operator wallets
    KMSNode->>NovaRegistry: getInstanceByWallet(wallets)
    NovaRegistry-->>KMSNode: instance details
    alt First KMS node
        KMSNode->>KMSNode: Initialize master secret and state
    else Not first node
        KMSNode->>PeerNode: Sync data
        PeerNode-->>KMSNode: Snapshot + deltas
    end
    KMSNode->>KMSNode: Schedule periodic refresh
```

## Nova App Access to KMS Workflow

This workflow describes how a Nova app discovers and accesses the KMS service.

### Workflow

0. Configure the Nova App Registry and KMS registry addresses.
1. Query the KMS registry to get all operator wallets.
2. Query the Nova App Registry for instance details of each operator.
3. Select a reachable KMS node from the list.
4. Establish mutual RA-TLS with the selected KMS node. The attestation user data includes the wallet address.
5. The client validates that the wallet address in the KMS node attestation matches the operator wallet from the KMS registry. If it does not match, abort.
6. The KMS node validates the app identity and metadata:
    6.1 Extract wallet address and public key from the app attestation.
    6.2 Query Nova App Registry for app metadata by wallet.
    6.3 Authorize access based on registry data.
7. The KMS node returns or stores data for the app.

### Mermaid Diagram

```mermaid
sequenceDiagram
    autonumber
    participant NovaApp as Nova App
    participant KMSRegistry as KMS Registry
    participant NovaRegistry as Nova App Registry
    participant KMSNode as KMS Node

    NovaApp->>KMSRegistry: getOperators()
    KMSRegistry-->>NovaApp: operator wallets
    NovaApp->>NovaRegistry: getInstanceByWallet(wallets)
    NovaRegistry-->>NovaApp: instance details
    NovaApp->>NovaApp: Pick reachable KMS node
    NovaApp->>KMSNode: Establish mutual RA-TLS session
    NovaApp->>NovaApp: Verify KMS node wallet in attestation
    KMSNode->>NovaRegistry: Verify app metadata by wallet
    NovaRegistry-->>KMSNode: App data and permissions
    KMSNode->>KMSNode: Authorize request
    KMSNode-->>NovaApp: Return or store data
```
