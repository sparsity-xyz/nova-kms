# Nova KMS — Testing Guide

## Overview

Nova KMS has two test suites:

| Suite | Tool | Location | Scope |
|-------|------|----------|-------|
| **Solidity** | Foundry (`forge test`) | `contracts/test/` | KMSRegistry contract logic |
| **Python** | pytest | `tests/` | Enclave application modules |

## Quick Start

```bash
# Run all Python tests
cd nova-kms
pip install pytest httpx
pytest tests/ -v

# Run all Solidity tests
cd nova-kms/contracts
forge test -vvv
```

---

## Python Tests

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r enclave/requirements.txt
pip install pytest httpx
```

### Test Files

| File | Module Under Test | Coverage |
|------|-------------------|----------|
| `test_data_store.py` | `data_store.py` | VectorClock, DataRecord, DataStore CRUD, merge, snapshot |
| `test_kdf.py` | `kdf.py` | HKDF derivation, MasterSecretManager, CertificateAuthority |
| `test_auth.py` | `auth.py` | AppAuthorizer (auth/authorization paths), dev header identity |
| `test_sync.py` | `sync_manager.py` | SyncManager delta/snapshot handling, PeerCache |
| `test_routes.py` | `routes.py` + `app.py` | Full API integration via FastAPI TestClient |

### Running Tests

```bash
# All tests
pytest tests/ -v

# Single module
pytest tests/test_data_store.py -v

# Single test class
pytest tests/test_auth.py::TestAppAuthorizer -v

# With coverage
pip install pytest-cov
pytest tests/ --cov=enclave --cov-report=term-missing
```

### Test Architecture

Tests use **mocking** to avoid real blockchain and Odyn calls:

```python
# Example: mock the NovaRegistry for auth tests
from unittest.mock import MagicMock

mock_registry = MagicMock(spec=NovaRegistry)
mock_registry.get_instance_by_wallet.return_value = _make_instance()
authorizer = AppAuthorizer(registry=mock_registry)
```

For route tests, `test_routes.py` uses FastAPI's `TestClient` with all dependencies mocked:

```python
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)
resp = client.get("/health")
assert resp.status_code == 200
```

### Key Test Scenarios

#### Data Store
- Put and get a record
- Namespace isolation (different app_ids don't interfere)
- Delete creates a tombstone
- TTL expiration
- Value size limit enforcement
- LWW (Last-Writer-Wins) conflict resolution
- Delta extraction and snapshot merge

#### KDF
- Deterministic key derivation (same inputs → same key)
- Different paths / app_ids / secrets → different keys
- MasterSecretManager lifecycle (uninitialized → error, initialized → works)
- CA certificate signing and determinism

#### Auth
- Full success path (ACTIVE instance + zkVerified + ACTIVE app + ENROLLED version)
- Missing wallet → rejected
- Instance not found → rejected
- Instance STOPPED → rejected
- Instance not zkVerified → rejected
- App not ACTIVE → rejected
- Version REVOKED → rejected
- Measurement mismatch → rejected
- DEPRECATED version → accepted
- Missing measurement → check skipped

#### Sync
- Delta merge incoming records
- Snapshot request returns full state
- Unknown sync type → error
- PeerCache refresh and self-exclusion

#### Routes (Integration)
- `/health` → 200
- `/status` → node and cluster info
- `/nodes` → paginated list
- `/kms/derive` → returns base64 key
- `/kms/data` PUT + GET → round-trip
- `/kms/data` DELETE → removes key
- `/sync` delta + snapshot_request

---

## Solidity Tests

### Setup

```bash
cd contracts
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Running

```bash
forge test           # all tests
forge test -vvv      # verbose with traces
forge test --match-test test_addOperator_success  # single test
forge test --gas-report  # gas usage
```

### Test File: `KMSRegistry.t.sol`

Uses a mock `novaAppRegistry` address to simulate the callback pattern.

| Test | Scenario |
|------|----------|
| `test_initialize_setsState` | Proxy initialization sets registry, appId, owner |
| `test_initialize_revert_alreadyInitialized` | Cannot re-initialize |
| `test_setNovaAppRegistry_byOwner` | Owner can update registry address |
| `test_setNovaAppRegistry_revert_notOwner` | Non-owner cannot update registry |
| `test_setKmsAppId_byOwner` | Owner can set KMS app ID |
| `test_setKmsAppId_revert_notOwner` | Non-owner cannot set app ID |
| `test_addOperator_success` | Successful operator addition via callback |
| `test_addOperator_emitsEvent` | OperatorAdded event emitted |
| `test_removeOperator_success` | Operator removed via callback |
| `test_transferOwnership` | Ownable2Step ownership transfer |
| `test_upgrade_authorized` | Owner can upgrade proxy |
| `test_upgrade_revert_unauthorized` | Non-owner cannot upgrade |
| `test_getOperators_empty` | Empty operator list |
| `test_fullLifecycle` | Add 3 operators, remove 1, verify state |

---

## CI Integration

Add to your CI pipeline:

```yaml
# .github/workflows/test.yml
jobs:
  python-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: |
          pip install -r nova-kms/enclave/requirements.txt
          pip install pytest httpx
          cd nova-kms && pytest tests/ -v

  solidity-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: foundry-rs/foundry-toolchain@v1
      - run: cd nova-kms/contracts && forge test -vvv
```
