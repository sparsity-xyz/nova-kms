# KMS Registry Deployment Workflow

This document describes how to deploy the KMS registry and wire it into Nova App Registry so KMS nodes and Nova apps can discover it.

## Workflow

1. Set the Nova App Registry address in the deploy script or environment.
2. Deploy the KMS registry contract.
3. Record the deployed KMS registry address.
4. When creating the KMS app in Nova Platform, set the Nova App Registry contract address as a KMS app property.

## Mermaid Diagram

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
