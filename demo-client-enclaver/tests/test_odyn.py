import importlib
import sys
from contextlib import contextmanager
from pathlib import Path

import requests


THIS_DIR = Path(__file__).resolve().parent
ENCLAVE_DIR = THIS_DIR.parent / "enclave"


_IMPORT_SCOPE_MODULES = ("config", "odyn")


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


def _load_odyn_module():
    with _demo_enclave_import_scope():
        return importlib.import_module("odyn")


class DummyResponse:
    def __init__(
        self,
        payload=None,
        status_code=200,
        text="",
        reason="",
        json_exc=None,
    ):
        self._payload = payload
        self.status_code = status_code
        self.text = text
        self.reason = reason
        self._json_exc = json_exc

    def json(self):
        if self._json_exc is not None:
            raise self._json_exc
        return self._payload


class DummySession:
    def __init__(self, response=None, post_exc=None, get_exc=None):
        self.response = response
        self.post_exc = post_exc
        self.get_exc = get_exc

    def post(self, *args, **kwargs):
        if self.post_exc is not None:
            raise self.post_exc
        return self.response

    def get(self, *args, **kwargs):
        if self.get_exc is not None:
            raise self.get_exc
        return self.response

    def close(self):
        return None


def test_odyn_rejects_non_dict_json():
    odyn_mod = _load_odyn_module()
    od = odyn_mod.Odyn(endpoint="http://example.com")
    od._session = DummySession(response=DummyResponse(payload=["not", "dict"]))

    try:
        od.kms_kv_get("k")
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass


def test_odyn_includes_http_error_body():
    odyn_mod = _load_odyn_module()
    od = odyn_mod.Odyn(endpoint="http://example.com")
    od._session = DummySession(
        response=DummyResponse(
            status_code=400,
            text="instance 0xabc is not ACTIVE on registry",
            reason="Bad Request",
            json_exc=ValueError("not json"),
        )
    )

    try:
        od.kms_derive("nova-kms-client/fixed-derive")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        message = str(exc)
        assert "HTTP 400 Bad Request" in message
        assert "/v1/kms/derive" in message
        assert "not ACTIVE on registry" in message


def test_odyn_prefers_json_error_field():
    odyn_mod = _load_odyn_module()
    od = odyn_mod.Odyn(endpoint="http://example.com")
    od._session = DummySession(
        response=DummyResponse(
            status_code=503,
            payload={"error": "registry discovery returned no ACTIVE KMS nodes"},
            reason="Service Unavailable",
        )
    )

    try:
        od.kms_derive("nova-kms-client/fixed-derive")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        message = str(exc)
        assert "HTTP 503 Service Unavailable" in message
        assert "no ACTIVE KMS nodes" in message


def test_odyn_wraps_timeout_as_transport_error():
    odyn_mod = _load_odyn_module()
    od = odyn_mod.Odyn(endpoint="http://example.com", timeout_seconds=10.0)
    od._session = DummySession(
        post_exc=requests.exceptions.Timeout("read timed out"),
    )

    try:
        od.kms_derive("nova-kms-client/fixed-derive")
        assert False, "Expected OdynTransportError"
    except odyn_mod.OdynTransportError as exc:
        message = str(exc)
        assert "Odyn transport error" in message
        assert "POST /v1/kms/derive" in message
        assert "read timed out" in message
