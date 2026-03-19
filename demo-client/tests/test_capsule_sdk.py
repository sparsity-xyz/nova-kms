import importlib
import os
import sys
from contextlib import contextmanager
from pathlib import Path


THIS_DIR = Path(__file__).resolve().parent
ENCLAVE_DIR = THIS_DIR.parent / "enclave"
_IMPORT_SCOPE_MODULES = ("capsule",)


@contextmanager
def _enclave_import_scope():
    saved_modules = {name: sys.modules.get(name) for name in _IMPORT_SCOPE_MODULES}
    saved_env = {
        "IN_ENCLAVE": os.environ.get("IN_ENCLAVE"),
        "CAPSULE_ENDPOINT": os.environ.get("CAPSULE_ENDPOINT"),
        "CAPSULE_TIMEOUT_SECONDS": os.environ.get("CAPSULE_TIMEOUT_SECONDS"),
    }
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
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        for name, module in saved_modules.items():
            if module is not None:
                sys.modules[name] = module


def test_capsule_prefers_env_endpoint():
    os.environ["IN_ENCLAVE"] = "true"
    os.environ["CAPSULE_ENDPOINT"] = "http://example.com:18000"
    with _enclave_import_scope():
        capsule_mod = importlib.import_module("capsule")
        client = capsule_mod.Capsule()
    assert client.endpoint == "http://example.com:18000"


def test_capsule_reads_timeout_from_env():
    os.environ["CAPSULE_TIMEOUT_SECONDS"] = "12.5"
    with _enclave_import_scope():
        capsule_mod = importlib.import_module("capsule")
        client = capsule_mod.Capsule()
    assert client.timeout_seconds == 12.5
