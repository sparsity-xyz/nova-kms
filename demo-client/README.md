# Nova KMS Client Example

This demo shows how an application can talk to a `nova-kms` cluster directly.
It implements the full client-side flow in application code:

- discover KMS nodes from `NovaAppRegistry`
- fetch a nonce from a target node
- build the PoP signature with Odyn
- encrypt request payloads end-to-end
- verify the KMS response signature
- decrypt the KMS response

Compared with `demo-client-enclaver`, this example is closer to what a custom app would need if it integrates with KMS without relying on enclaver's higher-level `/v1/kms/*` APIs.

## How It Works

Each test cycle does the following:

1. Query `NovaAppRegistry` for ACTIVE KMS instances for `KMS_APP_ID`.
2. Pick a node and call `/nonce`.
3. Use Odyn to sign `NovaKMS:AppAuth:<nonce>:<kms_wallet>:<timestamp>`.
4. Use Odyn encryption APIs to build an E2E envelope for `/kms/derive` and `/kms/data`.
5. Call:
   - `POST /kms/derive`
   - `PUT /kms/data`
   - `GET /kms/data/{key}`
6. Verify the response signature and decrypt the response body.
7. Expose the latest run summaries on `GET /logs`.

In other words, this demo exercises the same trust model as a real app: the application owns the KMS protocol details instead of delegating them to enclaver.

## What "Local Testing" Means Here

Local testing for this demo does **not** mean a fully local KMS cluster.

When `IN_ENCLAVE=false`, the app can still run on your laptop because two enclave-local dependencies are replaced by remote mock services:

- Odyn mock API: `http://odyn.sparsity.cloud:18000`
- mock RPC / Helios replacement: `http://odyn.sparsity.cloud:18545`

The important identity detail is:

- requests are not sent as "your local app identity"
- they are sent using the fixed app / TEE identity exposed by the mockup service
- that mockup-service-backed app identity is anchored on registry here:
  - <https://sparsity.cloud/explore/70>

This lets you test:

- PoP signing flow
- request/response E2E encryption logic
- KMS discovery logic
- client log formatting and periodic scan behavior

But this mode still expects:

- a real `NovaAppRegistry` address
- a real `KMS_APP_ID`
- reachable KMS nodes behind that registry

So this is best described as "local client process + remote mock Odyn/RPC + real registry/KMS".

## Enclaver Mockup Service

The remote mock service is documented here:

- <https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/internal_api_mockup.md>

That document describes enclaver's public mockup endpoint, intended for development and testing when you are not running inside an enclave.

For this demo, the important takeaway is:

- you can use the mockup service to replace enclave-local Odyn identity, signing, encryption, and mock RPC access
- in local mode, the app identity presented to KMS is the mockup service's identity, not a custom local identity
- that identity is tied to the registry entry at <https://sparsity.cloud/explore/70>
- you are **not** spinning up a local enclave
- you are **not** mocking the KMS cluster itself

## Local Run With Mockup Service

### 1. Install dependencies

```bash
cd demo-client/enclave
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure registry discovery

Edit `demo-client/enclave/config.py` and set:

- `NOVA_APP_REGISTRY_ADDRESS`
- `KMS_APP_ID`

These are static constants in this demo; they are not read from environment variables.

### 3. Use local-development mode

```bash
export IN_ENCLAVE=false
export HELIOS_RPC_URL=http://odyn.sparsity.cloud:18545
```

Notes:

- `IN_ENCLAVE=false` makes `enclave/odyn.py` use the Odyn mock endpoint.
- `HELIOS_RPC_URL` is optional because `demo-client/enclave/chain.py` already defaults to the mock RPC outside enclave mode.

### 4. Start the demo server

```bash
cd demo-client/enclave
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 5. Inspect results

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/logs
```

On startup, the app waits for RPC readiness, then starts a periodic scan. By default it runs one cycle immediately and then repeats every 30 seconds.

If you need to validate authorization behavior for your own app identity, this local mode is not enough. In that case you need a real enclave-backed deployment or another identity that is actually anchored in app registry for your target app.

## Running in Enclave

The production path is unchanged.

1. Build the image:

```bash
enclaver build
```

2. Deploy using the standard Nova workflow.

3. Make sure the image was built with the correct values in `demo-client/enclave/config.py`, especially:

- `NOVA_APP_REGISTRY_ADDRESS`
- `KMS_APP_ID`

## Feature Summary

- periodic derive + KV read/write verification
- node discovery through `NovaAppRegistry`
- PoP authentication built in application code
- E2E request/response encryption built in application code
- plain-text run summaries on `GET /logs`
