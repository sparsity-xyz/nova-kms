"""
Tests for kdf.py — Key Derivation and Certificate Authority.
"""

import pytest

from kdf import MasterSecretManager, derive_app_key, derive_data_key


class TestDeriveAppKey:
    def test_deterministic(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 42, "path_a")
        k2 = derive_app_key(secret, 42, "path_a")
        assert k1 == k2

    def test_different_path(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 42, "path_a")
        k2 = derive_app_key(secret, 42, "path_b")
        assert k1 != k2

    def test_different_app_id(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 1, "path")
        k2 = derive_app_key(secret, 2, "path")
        assert k1 != k2

    def test_different_secret(self):
        k1 = derive_app_key(b"a" * 32, 1, "path")
        k2 = derive_app_key(b"b" * 32, 1, "path")
        assert k1 != k2

    def test_custom_length(self):
        key = derive_app_key(b"x" * 32, 1, "p", length=64)
        assert len(key) == 64

    def test_context(self):
        k1 = derive_app_key(b"x" * 32, 1, "p", context="v1")
        k2 = derive_app_key(b"x" * 32, 1, "p", context="v2")
        assert k1 != k2


class TestDeriveDataKey:
    def test_returns_32_bytes(self):
        key = derive_data_key(b"s" * 32, 100)
        assert len(key) == 32


class TestMasterSecretManager:
    def test_not_initialized(self):
        mgr = MasterSecretManager()
        assert not mgr.is_initialized
        with pytest.raises(RuntimeError):
            _ = mgr.secret

    def test_initialize_from_peer(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        assert mgr.is_initialized
        assert mgr.secret == b"\x01" * 32

    def test_reject_short_secret(self):
        mgr = MasterSecretManager()
        with pytest.raises(ValueError):
            mgr.initialize_from_peer(b"short")

    def test_derive(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xab" * 32)
        key = mgr.derive(42, "test_path")
        assert len(key) == 32



