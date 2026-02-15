from __future__ import annotations

from dataclasses import dataclass

import pytest

import config
from nova_registry import InstanceStatus, VersionStatus


@dataclass
class _FakeVersion:
    status: object


@dataclass
class _FakeInstance:
    instance_id: int
    app_id: int
    version_id: int
    status: object
    zk_verified: bool
    instance_url: str
    tee_pubkey: bytes


class _FakeOdyn:
    def __init__(self, local_pubkey: bytes):
        self._local_pubkey = local_pubkey

    def eth_address(self) -> str:
        return "0x" + ("ab" * 20)

    def get_encryption_public_key_der(self) -> bytes:
        return self._local_pubkey


class _FakeNovaRegistry:
    def __init__(self, inst: _FakeInstance, ver: _FakeVersion):
        self._inst = inst
        self._ver = ver

    def get_instance_by_wallet(self, _wallet: str):
        return self._inst

    def get_version(self, _app_id: int, _version_id: int):
        return self._ver


class _FakeKMSRegistryClient:
    pass


@pytest.mark.parametrize("version_status", [VersionStatus.ENROLLED, VersionStatus.DEPRECATED])
def test_startup_allows_enrolled_or_deprecated_version(monkeypatch, version_status):
    import app as app_module

    local_pubkey = b"\x01" * 97
    inst = _FakeInstance(
        instance_id=1,
        app_id=int(config.KMS_APP_ID),
        version_id=7,
        status=InstanceStatus.ACTIVE,
        zk_verified=True,
        instance_url="https://kms-node.example.com",
        tee_pubkey=local_pubkey,
    )
    ver = _FakeVersion(status=version_status)

    monkeypatch.setattr("chain.wait_for_helios", lambda timeout=60: True)
    monkeypatch.setattr("odyn.Odyn", lambda: _FakeOdyn(local_pubkey))
    monkeypatch.setattr("kms_registry.KMSRegistryClient", _FakeKMSRegistryClient)
    monkeypatch.setattr("nova_registry.NovaRegistry", lambda: _FakeNovaRegistry(inst, ver))
    monkeypatch.setattr("nova_registry.CachedNovaRegistry", lambda reg: reg)

    components = app_module._startup_production()
    assert components["node_info"]["is_operator"] is True


def test_startup_fails_fast_on_tee_pubkey_mismatch(monkeypatch):
    import app as app_module

    local_pubkey = b"\x01" * 97
    registered_pubkey = b"\x02" * 97
    inst = _FakeInstance(
        instance_id=1,
        app_id=int(config.KMS_APP_ID),
        version_id=7,
        status=InstanceStatus.ACTIVE,
        zk_verified=True,
        instance_url="https://kms-node.example.com",
        tee_pubkey=registered_pubkey,
    )
    ver = _FakeVersion(status=VersionStatus.ENROLLED)

    monkeypatch.setattr("chain.wait_for_helios", lambda timeout=60: True)
    monkeypatch.setattr("odyn.Odyn", lambda: _FakeOdyn(local_pubkey))
    monkeypatch.setattr("kms_registry.KMSRegistryClient", _FakeKMSRegistryClient)
    monkeypatch.setattr("nova_registry.NovaRegistry", lambda: _FakeNovaRegistry(inst, ver))
    monkeypatch.setattr("nova_registry.CachedNovaRegistry", lambda reg: reg)

    with pytest.raises(RuntimeError, match="teePubkey"):
        app_module._startup_production()
