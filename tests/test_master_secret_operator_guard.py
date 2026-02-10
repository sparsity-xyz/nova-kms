"""Regression tests: non-operator nodes must never generate/sync the master secret."""

from unittest.mock import MagicMock

from data_store import DataStore
from kdf import MasterSecretManager
from sync_manager import SyncManager


def test_wait_for_master_secret_non_operator_never_generates(monkeypatch):
    mgr = MasterSecretManager()
    mgr.initialize_from_random = MagicMock(side_effect=AssertionError("must not generate"))

    peer_cache = MagicMock()
    peer_cache.refresh.return_value = None
    peer_cache.get_peers.return_value = []

    sync_mgr = SyncManager(
        DataStore(node_id="0x" + "11" * 20),
        "0x" + "aa" * 20,
        peer_cache,
        odyn=MagicMock(),
        scheduler=False,
    )

    kms_registry = MagicMock()
    kms_registry.is_operator.return_value = False

    sync_mgr.wait_for_master_secret(kms_registry=kms_registry, master_secret_mgr=mgr, retry_interval=0)

    assert mgr.is_initialized is False
    assert mgr.init_state == "uninitialized"


def test_wait_for_master_secret_no_registry_never_generates(monkeypatch):
    mgr = MasterSecretManager()
    mgr.initialize_from_random = MagicMock(side_effect=AssertionError("must not generate"))

    peer_cache = MagicMock()
    peer_cache.refresh.return_value = None
    peer_cache.get_peers.return_value = []

    sync_mgr = SyncManager(
        DataStore(node_id="0x" + "22" * 20),
        "0x" + "bb" * 20,
        peer_cache,
        odyn=MagicMock(),
        scheduler=False,
    )

    sync_mgr.wait_for_master_secret(kms_registry=None, master_secret_mgr=mgr, retry_interval=0)

    assert mgr.is_initialized is False
    assert mgr.init_state == "uninitialized"
