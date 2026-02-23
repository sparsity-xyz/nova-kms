import importlib
import os
import sys
from contextlib import contextmanager
from pathlib import Path
import asyncio


THIS_DIR = Path(__file__).resolve().parent
ENCLAVE_DIR = THIS_DIR.parent / "enclave"
_IMPORT_SCOPE_MODULES = ("config", "odyn", "app")


@contextmanager
def _demo_enclave_import_scope():
    saved_modules = {name: sys.modules.get(name) for name in _IMPORT_SCOPE_MODULES}
    inserted_path = False
    enclave_path = str(ENCLAVE_DIR)
    if enclave_path not in sys.path:
        sys.path.insert(0, enclave_path)
        inserted_path = True

    for name in _IMPORT_SCOPE_MODULES:
        sys.modules.pop(name, None)

    try:
        yield
    finally:
        for name in _IMPORT_SCOPE_MODULES:
            sys.modules.pop(name, None)
        if inserted_path:
            try:
                sys.path.remove(enclave_path)
            except ValueError:
                pass
        for name, module in saved_modules.items():
            if module is not None:
                sys.modules[name] = module


class FakeOdyn:
    def __init__(
        self,
        derive_key="k1",
        read_value=None,
        read_found=False,
        put_success=True,
        derive_exc=None,
    ):
        self._derive_key = derive_key
        self._read_value = read_value
        self._read_found = read_found
        self._put_success = put_success
        self._derive_exc = derive_exc

    def kms_derive(self, path, context="", length=32):
        if self._derive_exc is not None:
            raise self._derive_exc
        return {"key": self._derive_key}

    def kms_kv_get(self, key):
        return {"found": self._read_found, "value": self._read_value}

    def kms_kv_put(self, key, value, ttl_ms=0):
        return {"success": self._put_success}


def _load_app_module():
    # Ensure deterministic import config for tests.
    os.environ.setdefault("TEST_CYCLE_INTERVAL_SECONDS", "30")
    with _demo_enclave_import_scope():
        return importlib.import_module("app")


def test_first_run_has_no_previous_derive_match():
    app_mod = _load_app_module()
    client = app_mod.KMSDemoClient()
    client.odyn = FakeOdyn(derive_key="derived-A", read_value=None, read_found=False, put_success=True)

    result = client._run_once_sync()

    assert result["derived_key"] == "derived-A"
    assert result["derive_matches_previous"] is None
    assert result["write_success"] is True


def test_second_run_detects_derive_mismatch():
    app_mod = _load_app_module()
    client = app_mod.KMSDemoClient()

    client.odyn = FakeOdyn(derive_key="derived-A", read_value=None, read_found=False, put_success=True)
    _ = client._run_once_sync()

    client.odyn = FakeOdyn(derive_key="derived-B", read_value="123", read_found=True, put_success=True)
    result = client._run_once_sync()

    assert result["derive_matches_previous"] is False


def test_failed_write_does_not_advance_last_written_value():
    app_mod = _load_app_module()
    client = app_mod.KMSDemoClient()

    client.odyn = FakeOdyn(derive_key="derived-A", read_value=None, read_found=False, put_success=True)
    _ = client._run_once_sync()
    first_written = client._last_written_value

    client.odyn = FakeOdyn(derive_key="derived-A", read_value=first_written, read_found=True, put_success=False)
    try:
        client._run_once_sync()
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass

    assert client._last_written_value == first_written


def test_run_once_marks_registration_pending_for_kms_authz_error():
    app_mod = _load_app_module()
    app_mod.request_logs.clear()

    client = app_mod.KMSDemoClient()
    client.odyn = FakeOdyn(
        derive_exc=app_mod.OdynRequestError(
            method="POST",
            path="/v1/kms/derive",
            url="http://localhost:18000/v1/kms/derive",
            status_code=400,
            reason="Bad Request",
            response_body="instance 0xe06d... is not ACTIVE on registry",
        )
    )

    asyncio.run(client.run_once())

    latest = app_mod.request_logs[0]
    assert latest["status"] == "PendingRegistration"
    assert latest["details"]["retryable"] is True
    assert latest["details"]["http_status"] == 400
    assert latest["details"]["path"] == "/v1/kms/derive"


def test_run_once_marks_transport_timeout_as_transient_failure():
    app_mod = _load_app_module()
    app_mod.request_logs.clear()

    client = app_mod.KMSDemoClient()
    client.odyn = FakeOdyn(
        derive_exc=app_mod.OdynTransportError(
            method="POST",
            path="/v1/kms/derive",
            url="http://localhost:18000/v1/kms/derive",
            timeout_seconds=10.0,
            cause=TimeoutError("timed out"),
        )
    )

    asyncio.run(client.run_once())

    latest = app_mod.request_logs[0]
    assert latest["status"] == "TransientFailure"
    assert latest["details"]["retryable"] is True
    assert latest["details"]["path"] == "/v1/kms/derive"
    assert latest["details"]["transport_error"] == "TimeoutError"


def test_run_once_marks_registry_discovery_rpc_failure_as_transient_failure():
    app_mod = _load_app_module()
    app_mod.request_logs.clear()

    client = app_mod.KMSDemoClient()
    client.odyn = FakeOdyn(
        derive_exc=app_mod.OdynRequestError(
            method="POST",
            path="/v1/kms/derive",
            url="http://localhost:18000/v1/kms/derive",
            status_code=400,
            reason="Bad Request",
            response_body=(
                "registry discovery failed: error sending request for url "
                "(http://127.0.0.1:18545/)"
            ),
        )
    )

    asyncio.run(client.run_once())

    latest = app_mod.request_logs[0]
    assert latest["status"] == "TransientFailure"
    assert latest["details"]["retryable"] is True
    assert latest["details"]["http_status"] == 400
    assert latest["details"]["path"] == "/v1/kms/derive"


def test_run_once_marks_kms_instance_not_found_as_pending_registration():
    app_mod = _load_app_module()
    app_mod.request_logs.clear()

    client = app_mod.KMSDemoClient()
    client.odyn = FakeOdyn(
        derive_exc=app_mod.OdynRequestError(
            method="POST",
            path="/v1/kms/derive",
            url="http://localhost:18000/v1/kms/derive",
            status_code=400,
            reason="Bad Request",
            response_body='KMS HTTP 403: {"detail":"Instance not found"}',
        )
    )

    asyncio.run(client.run_once())

    latest = app_mod.request_logs[0]
    assert latest["status"] == "PendingRegistration"
    assert latest["details"]["retryable"] is True
    assert latest["details"]["http_status"] == 400
    assert latest["details"]["path"] == "/v1/kms/derive"
