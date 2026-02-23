import importlib
import os
import sys
from pathlib import Path
import asyncio


THIS_DIR = Path(__file__).resolve().parent
ENCLAVE_DIR = THIS_DIR.parent / "enclave"
if str(ENCLAVE_DIR) not in sys.path:
    sys.path.insert(0, str(ENCLAVE_DIR))

from odyn import OdynRequestError


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
    if "app" in sys.modules:
        return importlib.reload(sys.modules["app"])
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
        derive_exc=OdynRequestError(
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
