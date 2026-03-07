# Nova KMS

Nova Platform gives applications a trusted runtime and shared services such as Helios-backed chain access, app-registry discovery and metadata like dapp contract addresses and active instances, and Odyn for enclave signing, encryption, and decryption.

Nova KMS is unusual because it is both a Nova Platform application and a service provider for other Nova Platform applications. It is a decentralized KMS that runs as a distributed set of TEE-backed nodes, uses the platform's own capabilities to operate securely, and in turn exposes KMS services to other Nova apps. The current node is implemented as a Rust HTTP service built with Axum, authorizes callers via `NovaAppRegistry`, and coordinates cluster master-secret state through `KMSRegistry`.

Put simply, Nova KMS is not just a demo of Nova Platform capabilities. It is a real decentralized application running on Nova that uses the platform's own trust, identity, and discovery services to deliver a security-critical service back to the rest of the ecosystem.

The service provides two application-facing capabilities:

- Key derivation from a cluster-wide master secret
- An encrypted, in-memory KV store partitioned by caller `app_id`

## Why Use Nova KMS

- It is native to Nova. Your application uses a KMS that already understands Nova identities, Nova app registration, and Nova runtime trust assumptions.
- It avoids concentrating trust in a single node. The service is distributed across multiple TEE-backed KMS nodes instead of depending on one machine to hold the only live secret state.
- It gives each application its own namespace. Derived keys and KV data are scoped by caller `app_id`, so one app does not share logical keyspace with another.
- It is built for applications, not just operators. App-facing capabilities stay simple: derive keys and read or write encrypted KV values.

## What Your Application Gets

- Deterministic key derivation from a cluster-wide master secret.
- An encrypted KV store partitioned by caller `app_id`.
- A KMS service that can keep operating as cluster membership changes, as long as verified KMS peers remain available.
- A service boundary that is designed for confidential Nova applications instead of generic public clients.

## How To Use Nova KMS In Your Own Nova App

There are two practical ways to adopt Nova KMS in your own Nova application.

1. Directly call Nova KMS, like `demo-client`.

This is the most explicit integration model. Your application discovers active KMS instances, authenticates itself as a Nova app, and sends KMS requests to the cluster directly. Choose this path if you want full control over request flow, node selection, retries, and how your app uses derived keys or KV state.

2. Use the Nova KMS service integrated into Enclaver, like `demo-client-enclaver`.

This is the simpler integration model for apps that want Nova KMS as a platform-style dependency instead of managing the interaction details themselves. Choose this path if you want your app to consume Nova KMS through Enclaver's built-in service surface rather than implementing direct KMS communication logic inside your app.

## Security Design

Nova KMS is meant for applications that care about more than simple key storage. Its security design is built around one idea: a node should only serve sensitive KMS traffic when its identity, cluster membership, and secret state are all verifiably correct.

### 1. Verified KMS nodes, not just reachable servers

Nova KMS does not trust peer nodes just because they respond on the network. Peer membership and identity come from `NovaAppRegistry`. In practice that means the service only accepts KMS peers that match the current registry view of:

- active KMS membership
- registered instance URL
- registered `teePubkey`
- verified TEE-backed identity

This reduces the risk of rogue peers joining replication, master-secret exchange, or recovery flows.

### 2. Verified calling applications, not anonymous clients

Nova KMS also verifies the applications that call it. App requests are authenticated against registry-backed identity, and encrypted request bodies are tied back to the caller's registered TEE key material before the node accepts and decrypts them.

For users of the service, that means Nova KMS is not only checking "who signed this request". It is checking that the request is coming from the right registered Nova application identity.

### 3. End-to-end encrypted KMS traffic

Sensitive request and response bodies are carried in encrypted envelopes, rather than being treated as ordinary plaintext HTTP payloads. This protects key-derivation requests, KV reads, KV writes, and inter-node sync payloads while they move between trusted participants.

The service also validates that the encrypted sender identity matches the authenticated caller before it decrypts payloads. That closes an important gap: encryption alone is not enough unless the encrypted sender is also verified.

### 4. Split-brain resistance by design

Nova KMS does not let each node invent its own master-secret truth. The cluster uses `KMSRegistry.masterSecretHash` as the single on-chain source of truth for the active master-secret lineage. A node does not serve `/kms/*` traffic until it has confirmed that:

- it is part of the current KMS membership
- its local TEE identity matches the registry entry for that instance
- its local master secret matches the on-chain cluster hash

If a node is new, restarted, or out of sync, it must recover the master secret from a verified peer and catch up before it is allowed to serve requests. In other words, when Nova KMS is uncertain, it prefers to stay unavailable rather than serve divergent or unsafe state.

### 5. Strong isolation between applications

Nova KMS is shared infrastructure, but it does not expose one shared logical keyspace to all callers.

- derived keys are scoped to the calling application
- KV entries are partitioned by caller `app_id`
- one application's KMS state is not supposed to be readable or writable as another application's state

This matters because the service is designed for many Nova applications to rely on the same KMS cluster without collapsing their trust boundaries into one bucket.

### 6. Consistent distributed KV behavior

Nova KMS is not only a key-derivation service. It also offers an encrypted KV store, and that store is replicated across KMS peers. To keep the data model sane in a distributed setting, the service:

- rejects stale updates instead of letting them overwrite newer state
- resolves true concurrent writes deterministically
- propagates deletions as tombstones
- uses delta sync for normal replication and snapshot sync for catch-up

From the application's point of view, the important property is simple: the cluster is designed to converge on one consistent value per app-scoped key, even when different KMS nodes receive traffic at different times.

## What Makes Nova KMS Special On Nova

Most applications consume platform services. Nova KMS both consumes them and extends them.

- It uses Nova Platform services such as Helios-backed chain access, app-registry discovery, and Odyn enclave cryptography to operate securely.
- It then turns those platform primitives into a higher-level service that other Nova applications can depend on.
- Because it runs inside the same trust model as the apps it serves, it can validate peers and callers using Nova-native identity and registry state rather than bolting on an unrelated trust system.

That combination is the core product story of Nova KMS: a decentralized KMS built as a first-class Nova application for other Nova applications.

## For Developers And Operators

This repository contains the current Rust implementation of the Nova KMS node. The README stays high level on purpose. For protocol details, deployment flow, and code-level behavior, use the docs:

- `docs/architecture.md`
- `docs/app-to-kms-connection.md`
- `docs/deployment.md`
- `docs/development.md`
- `docs/cache-and-registry-model.md`
- `docs/kms-core-workflows.md`

Common commands:

```bash
cargo test
make build-docker
```
