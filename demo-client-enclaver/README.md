# Nova KMS Demo Client (Enclaver APIs)

This demo provides the same core behavior as `nova-kms/demo-client`: it periodically runs a KMS verification cycle (derive + KV read/write) and exposes the results via `/logs`.

The difference is that it directly uses enclaver-provided Odyn KMS APIs:

- `POST /v1/kms/derive`
- `POST /v1/kms/kv/get` (returns base64-encoded value)
- `POST /v1/kms/kv/put` (expects base64-encoded value)

So this client no longer needs to implement the following in application code:

- KMS node discovery
- PoP signing flow construction
- E2E request encryption/decryption
- KMS response signature verification

As a result, the code is significantly smaller than the original `demo-client`.

## Behavior

- Startup is non-blocking. The web server starts even if KMS access is not ready yet.
- Runs one test cycle immediately in background, then repeats every `TEST_CYCLE_INTERVAL_SECONDS`.
- Each cycle performs:
  - Fixed-path derive (`FIXED_DERIVE_PATH`)
  - Read `KV_DATA_KEY`
  - Write current timestamp to `KV_DATA_KEY`
- If `/v1/kms/*` fails because the enclave is not yet registered in app-registry, the cycle is logged as `PendingRegistration` (retryable) instead of crashing startup.
- View recent cycle results via `GET /logs` (plain text).

## Directory Structure

```text
nova-kms/demo-client-enclaver/
├── Dockerfile
├── enclaver.yaml
└── enclave/
    ├── app.py
    ├── config.py
    ├── odyn.py
    └── requirements.txt
```

## Configurable Environment Variables

The following environment variables can be overridden at runtime:

- `TEST_CYCLE_INTERVAL_SECONDS` (default: `30`)
- `FIXED_DERIVE_PATH` (default: `nova-kms-client/fixed-derive`)
- `KV_DATA_KEY` (default: `nova-kms-client/timestamp`)
- `ODYN_ENDPOINT` (default: `http://localhost:18000` in-enclave, mock endpoint outside enclave)
- `ODYN_TIMEOUT_SECONDS` (default: `30`)
