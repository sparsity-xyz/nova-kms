import sys
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
ENCLAVE_DIR = THIS_DIR.parent / "enclave"
if str(ENCLAVE_DIR) not in sys.path:
    sys.path.insert(0, str(ENCLAVE_DIR))


import odyn as odyn_mod
import requests


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
    od = odyn_mod.Odyn(endpoint="http://example.com")
    od._session = DummySession(response=DummyResponse(payload=["not", "dict"]))

    try:
        od.kms_kv_get("k")
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass


def test_odyn_includes_http_error_body():
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
