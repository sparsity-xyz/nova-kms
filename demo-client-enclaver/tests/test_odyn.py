import sys
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
ENCLAVE_DIR = THIS_DIR.parent / "enclave"
if str(ENCLAVE_DIR) not in sys.path:
    sys.path.insert(0, str(ENCLAVE_DIR))


import odyn as odyn_mod


class DummyResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class DummySession:
    def __init__(self, payload):
        self.payload = payload

    def post(self, *args, **kwargs):
        return DummyResponse(self.payload)

    def get(self, *args, **kwargs):
        return DummyResponse(self.payload)

    def close(self):
        return None


def test_odyn_rejects_non_dict_json():
    od = odyn_mod.Odyn(endpoint="http://example.com")
    od._session = DummySession(payload=["not", "dict"])

    try:
        od.kms_kv_get("k")
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass
