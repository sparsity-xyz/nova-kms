"""
Tests for nova_registry.py — NovaRegistry + CachedNovaRegistry.

Covers:
  - _call unwrap logic (regression)
  - All NovaRegistry methods: get_app, get_version, get_instance,
    get_instance_by_wallet, get_instances_for_version
  - Missing address error
  - CachedNovaRegistry: caching, expiry, invalidate (all + specific),
    all cached methods, pass-through for uncached methods
"""

import time
import pytest
from unittest.mock import MagicMock
from web3 import Web3

from nova_registry import (
    App,
    AppStatus,
    AppVersion,
    CachedNovaRegistry,
    InstanceStatus,
    NovaRegistry,
    RuntimeInstance,
    VersionStatus,
)


# =============================================================================
# Helpers
# =============================================================================

def _make_registry():
    """Create a NovaRegistry with mocked chain (no real RPC)."""
    reg = NovaRegistry.__new__(NovaRegistry)
    reg.address = "0x" + "00" * 20
    reg.chain = MagicMock()
    reg.chain.eth_call_finalized.return_value = b"\x00"
    reg.contract = MagicMock()
    reg.contract.encodeABI.return_value = "0xdeadbeef"
    # Registry wrappers decode outputs via the function ABI (web3 7.x)
    reg.contract.get_function_by_name.return_value.decode_output.return_value = (None,)
    return reg


def _app_tuple(app_id=1, status=0):
    return (
        app_id,                     # id
        "0x" + "aa" * 20,          # owner
        b"\x00" * 32,              # teeArch
        "0x" + "bb" * 20,          # dappContract
        "https://example.com",     # metadataUri
        1,                          # latestVersionId
        1700000000,                # createdAt
        status,                    # status (AppStatus)
    )


def _version_tuple(version_id=1, status=0):
    return (
        version_id,                # id
        "v1.0",                    # versionName
        b"\xab" * 32,             # codeMeasurement
        "docker://img",           # imageUri
        "https://audit.example",  # auditUrl
        "abc123",                 # auditHash
        "12345",                  # githubRunId
        status,                   # status (VersionStatus)
        1700000000,               # enrolledAt
        "0x" + "cc" * 20,        # enrolledBy
    )


def _instance_tuple(instance_id=1, app_id=1, zk_verified=True, status=0):
    return (
        instance_id,              # id
        app_id,                   # appId
        1,                        # versionId
        "0x" + "dd" * 20,        # operator
        "https://app.example",   # instanceUrl
        b"\x04" * 65,            # teePubkey
        "0x" + "ee" * 20,        # teeWalletAddress
        zk_verified,             # zkVerified
        status,                  # status (InstanceStatus)
        1700000000,              # registeredAt
    )


# =============================================================================
# _call unwrap
# =============================================================================


class TestCallUnwrap:
    def test_unwraps_single_output_tuple(self):
        """Regression: _call correctly unwraps 1-tuple from web3.py."""
        reg = _make_registry()
        mock_struct = (1, 2, 3)
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (mock_struct,)

        out = reg._call("getApp", [123])
        assert out == mock_struct
        assert out[0] == 1

    def test_passes_through_multi_output(self):
        """Multi-value outputs should not be unwrapped."""
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = ("a", "b")
        out = reg._call("someFunc", [])
        assert out == ("a", "b")

    def test_encodes_and_calls_finalized(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (42,)
        reg._call("func", [1, 2])
        reg.contract.encodeABI.assert_called_with(fn_name="func", args=[1, 2])
        reg.chain.eth_call_finalized.assert_called_once()


# =============================================================================
# NovaRegistry methods
# =============================================================================


class TestGetApp:
    def test_returns_app_dataclass(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (_app_tuple(app_id=42),)
        app = reg.get_app(42)
        assert isinstance(app, App)
        assert app.app_id == 42
        assert app.status == AppStatus.ACTIVE

    def test_revoked_status(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (_app_tuple(status=2),)
        app = reg.get_app(1)
        assert app.status == AppStatus.REVOKED


class TestGetVersion:
    def test_returns_version_dataclass(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (_version_tuple(version_id=3),)
        ver = reg.get_version(1, 3)
        assert isinstance(ver, AppVersion)
        assert ver.version_id == 3
        assert ver.version_name == "v1.0"
        assert ver.status == VersionStatus.ENROLLED

    def test_deprecated_status(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (_version_tuple(status=1),)
        ver = reg.get_version(1, 1)
        assert ver.status == VersionStatus.DEPRECATED


class TestGetInstance:
    def test_returns_instance_dataclass(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (_instance_tuple(instance_id=5, app_id=42),)
        inst = reg.get_instance(5)
        assert isinstance(inst, RuntimeInstance)
        assert inst.instance_id == 5
        assert inst.app_id == 42
        assert inst.zk_verified is True
        assert inst.status == InstanceStatus.ACTIVE

    def test_stopped_instance(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (_instance_tuple(status=1),)
        inst = reg.get_instance(1)
        assert inst.status == InstanceStatus.STOPPED


class TestGetInstanceByWallet:
    def test_returns_instance(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (_instance_tuple(instance_id=7),)
        inst = reg.get_instance_by_wallet("0x" + "ee" * 20)
        assert inst.instance_id == 7

    def test_checksum_is_applied(self):
        """get_instance_by_wallet should checksum the address before ABI encoding."""
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = (_instance_tuple(),)
        wallet_lower = "0x" + "aa" * 20
        reg.get_instance_by_wallet(wallet_lower)
        call_args = reg.contract.encodeABI.call_args
        passed_wallet = call_args[1]["args"][0]
        assert passed_wallet == Web3.to_checksum_address(wallet_lower)


class TestGetInstancesForVersion:
    def test_returns_list_of_ids(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = ([10, 20, 30],)
        ids = reg.get_instances_for_version(1, 1)
        assert ids == [10, 20, 30]

    def test_empty_list(self):
        reg = _make_registry()
        reg.contract.get_function_by_name.return_value.decode_output.return_value = ([],)
        ids = reg.get_instances_for_version(1, 1)
        assert ids == []


# =============================================================================
# CachedNovaRegistry
# =============================================================================


class TestCachedNovaRegistry:
    def test_caches_app_result(self):
        mock_inner = MagicMock()
        app_obj = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.return_value = app_obj

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        result1 = cached.get_app(1)
        result2 = cached.get_app(1)
        assert result1.app_id == 1
        assert result2.app_id == 1
        assert mock_inner.get_app.call_count == 1  # second call served from cache

    def test_caches_version_result(self):
        mock_inner = MagicMock()
        ver = AppVersion(1, "v1", b"", "", "", "", "", VersionStatus.ENROLLED, 0, "0x00")
        mock_inner.get_version.return_value = ver

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_version(1, 1)
        cached.get_version(1, 1)
        assert mock_inner.get_version.call_count == 1

    def test_caches_instance_result(self):
        mock_inner = MagicMock()
        inst = RuntimeInstance(1, 1, 1, "0x00", "url", b"", "0xAA", True, InstanceStatus.ACTIVE, 0)
        mock_inner.get_instance.return_value = inst

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_instance(1)
        cached.get_instance(1)
        assert mock_inner.get_instance.call_count == 1

    def test_caches_instance_by_wallet(self):
        mock_inner = MagicMock()
        inst = RuntimeInstance(1, 1, 1, "0x00", "url", b"", "0xAA", True, InstanceStatus.ACTIVE, 0)
        mock_inner.get_instance_by_wallet.return_value = inst

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_instance_by_wallet("0xAA")
        cached.get_instance_by_wallet("0xAA")
        assert mock_inner.get_instance_by_wallet.call_count == 1

    def test_cache_expires(self):
        mock_inner = MagicMock()
        app_obj = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.return_value = app_obj

        cached = CachedNovaRegistry(inner=mock_inner, ttl=0)  # TTL=0 → always expired
        cached.get_app(1)
        cached.get_app(1)
        assert mock_inner.get_app.call_count == 2

    def test_invalidate_all(self):
        mock_inner = MagicMock()
        app_obj = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.return_value = app_obj

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_app(1)
        cached.invalidate()
        cached.get_app(1)
        assert mock_inner.get_app.call_count == 2

    def test_invalidate_specific_key(self):
        mock_inner = MagicMock()
        app_obj = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.return_value = app_obj

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_app(1)
        cached.invalidate("app:1")
        cached.get_app(1)
        assert mock_inner.get_app.call_count == 2

    def test_get_instances_for_version_not_cached(self):
        """get_instances_for_version is a pass-through (not cached)."""
        mock_inner = MagicMock()
        mock_inner.get_instances_for_version.return_value = [1, 2, 3]

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        cached.get_instances_for_version(1, 1)
        cached.get_instances_for_version(1, 1)
        assert mock_inner.get_instances_for_version.call_count == 2

    def test_address_proxy(self):
        mock_inner = MagicMock()
        mock_inner.address = "0xREG"
        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        assert cached.address == "0xREG"

    def test_different_keys_use_different_cache_entries(self):
        mock_inner = MagicMock()
        app1 = App(1, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        app2 = App(2, "0x00", b"", "0x00", "", 1, 0, AppStatus.ACTIVE)
        mock_inner.get_app.side_effect = [app1, app2]

        cached = CachedNovaRegistry(inner=mock_inner, ttl=60)
        r1 = cached.get_app(1)
        r2 = cached.get_app(2)
        assert r1.app_id == 1
        assert r2.app_id == 2
        assert mock_inner.get_app.call_count == 2
