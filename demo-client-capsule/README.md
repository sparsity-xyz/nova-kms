# Nova KMS Demo Client (Capsule APIs)

This demo provides the same user-facing verification loop as `demo-client`, but it uses capsule's higher-level KMS APIs directly instead of implementing the KMS protocol in application code.

It periodically runs:

- fixed-path derive
- KV read
- KV write

and exposes the most recent results on `GET /logs`.

## How It Differs From `demo-client`

This demo calls capsule-provided endpoints:

- `POST /v1/kms/derive`
- `POST /v1/kms/kv/get`
- `POST /v1/kms/kv/put`
- `POST /v1/kms/kv/delete`

That means the application itself does **not** need to implement:

- KMS node discovery
- nonce fetching
- PoP message construction
- E2E envelope encryption/decryption
- KMS response signature verification

Those responsibilities move into capsule's KMS integration layer.

## Principle

Think of this demo as the "thin client" version:

- `demo-client` proves how to talk to KMS directly
- `demo-client-capsule` proves how to consume capsule's already-integrated KMS interface

So the value of this demo is different:

- it tests your application logic against `/v1/kms/*`
- it does not test your own PoP/E2E implementation, because your app no longer owns that logic

## What "Local Testing" Means Here

This demo is the better fit when you want to run locally with the capsule mockup service.

When `IN_ENCLAVE=false`, `demo-client-capsule/enclave/capsule.py` defaults to:

- `CAPSULE_ENDPOINT=http://capsule.sparsity.cloud:18000`

In that mode, your local Python process calls the public mockup service instead of a real enclave-local Capsule running on `localhost:18000`.

The identity detail is the same as `demo-client`:

- requests are not issued as a custom local app identity
- they are issued as the fixed app / TEE identity exposed by the mockup service
- that mockup-service-backed app identity is anchored on registry here:
  - <https://sparsity.cloud/explore/70>

This lets you validate:

- application startup behavior
- periodic `/v1/kms/*` test cycles
- derive consistency across cycles
- KV read/write flow
- retryable handling for transport failures and registration-related failures

## Capsule Mockup Service

The mock service is documented here:

- <https://github.com/sparsity-xyz/capsule/blob/sparsity/docs/internal_api_mockup.md>

That document describes capsule's public development endpoint and the internal APIs it exposes for testing outside a real enclave.

For this demo, the important point is that the mockup service includes the app-integration category used by `/v1/kms/*`, so you can exercise the capsule KMS abstraction from a normal local process.

Practical boundary:

- good for local development and integration testing
- local requests still represent the mockup service identity, not your own registered app identity
- the registry anchor for that identity is <https://sparsity.cloud/explore/70>
- not a replacement for a real enclave deployment
- not a byte-for-byte guarantee of production behavior

## Local Run With Mockup Service

### 1. Install dependencies

```bash
cd demo-client-capsule/enclave
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Set local-development environment

```bash
export IN_ENCLAVE=false
export CAPSULE_ENDPOINT=http://capsule.sparsity.cloud:18000
export TEST_CYCLE_INTERVAL_SECONDS=30
export FIXED_DERIVE_PATH=nova-kms-client/fixed-derive
export KV_DATA_KEY=nova-kms-client/timestamp
```

Notes:

- `CAPSULE_ENDPOINT` is optional because outside enclave mode the demo already defaults to the same mock endpoint.
- keeping it explicit in local testing makes the dependency obvious.

### 3. Start the demo server

```bash
cd demo-client-capsule/enclave
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 4. Inspect results

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/logs
```

Behavior to expect:

- startup is non-blocking
- one cycle starts in the background immediately
- later cycles repeat every `TEST_CYCLE_INTERVAL_SECONDS`
- registration-related failures are logged as retryable states instead of crashing the app

If you need to test authorization or policy decisions for your own app identity, this local mode is not sufficient. It is exercising the mockup service identity path instead.

## Runtime Configuration

The following environment variables are supported:

- `IN_ENCLAVE`
- `TEST_CYCLE_INTERVAL_SECONDS`
- `FIXED_DERIVE_PATH`
- `KV_DATA_KEY`
- `CAPSULE_ENDPOINT`
- `CAPSULE_TIMEOUT_SECONDS`

These are already surfaced in `demo-client-capsule/capsule.yaml`.

## Running in Enclave

For production, deploy this demo as a Nova app through Nova Platform.

In enclave mode, the same code will talk to the local capsule/Capsule endpoint at `http://localhost:18000` instead of the public mockup service.

## Directory Structure

```text
nova-kms/demo-client-capsule/
├── Dockerfile
├── capsule.yaml
└── enclave/
    ├── app.py
    ├── config.py
    ├── capsule.py
    └── requirements.txt
```
