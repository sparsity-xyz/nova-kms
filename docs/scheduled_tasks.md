# KMS Scheduled Tasks

The Nova KMS operates using a **single main periodic task** called `node_tick`. This design ensures a strict ordering of operations (Discovery -> Auth/Secret Check -> Data Sync) and prevents race conditions between dependent sub-tasks.

## Main Task: `node_tick`

The `node_tick` function is the heartbeat of the KMS node. It is scheduled by `app.py` to run at a configurable interval.

*   **Function**: `sync_manager.node_tick`
*   **Configuration**: `KMS_NODE_TICK_SECONDS` (default: 5 seconds in production)
*   **Scheduler**: `BackgroundScheduler` (APScheduler)

### Workflow Per Tick

1.  **Peer Discovery (`peer_cache.refresh`)**
    *   Fetches the latest list of `ACTIVE` KMS instances from the `NovaAppRegistry` (filtering by `KMS_APP_ID`).
    *   Updates the local peer cache.
    *   **Gate check**: If the local node (`self`) is not in the list of active KMS instances, the node marks itself as `503 Unavailable` and stops processing for this tick.

2.  **Master Secret Integrity Check**
    *   **Read On-Chain Hash**: Fetches the `masterSecretHash` from the `KMSRegistry` contract.
    *   **Scenario A: Hash is Zero (Bootstrap)**
        *   If the local node has a master secret (seeded), it attempts to write its hash to the chain.
    *   **Scenario B: Hash is Non-Zero (Running)**
        *   Compares local master secret hash against the on-chain hash.
        *   **Mismatch**: Attempts to sync the correct master secret from verified peers.
        *   **Gate check**: If hashes still mismatch, the node remains `503 Unavailable`.

3.  **Service Availability**
    *   If the node is an operator and the master secret matches the on-chain hash, the service is marked `200 OK` (Healthy).

4.  **Data Synchronization (`push_deltas`)**
    *   **Rate Limiting**: Checks if `SYNC_INTERVAL_SECONDS` has passed since the last push.
    *   **Push**: Sends recent KV deltas to all healthy peers.
    *   **Protocol**: Uses HMAC-signed JSON payloads over HTTPS.

## Configuration Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `KMS_NODE_TICK_SECONDS` | `15` | core heartbeat interval |
| `SYNC_INTERVAL_SECONDS` | `60` | interval for pushing data deltas to peers |
| `PEER_CACHE_TTL_SECONDS` | `30` | (internal) max age of peer cache before forced refresh |
