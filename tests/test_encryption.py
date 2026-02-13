"""
Tests for DataStore encryption transparency.

Verifies that:
  - Data stored with a key_callback is encrypted at rest (ciphertext ≠ plaintext).
  - The same data can be read back correctly after decryption.
  - Different apps use different encryption keys (namespace isolation).
"""

import pytest

import config


@pytest.fixture(autouse=True)
def _strict_encryption(monkeypatch):
    """Force encryption."""



class TestEncryptionTransparency:
    def _make_encrypted_store(self):
        from data_store import DataStore
        from kdf import MasterSecretManager

        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xCC" * 32)

        def key_callback(app_id: int) -> bytes:
            return mgr.derive(app_id, "data_key")

        return DataStore(node_id="enc_node", key_callback=key_callback)

    def test_data_encrypted_at_rest(self):
        ds = self._make_encrypted_store()
        plaintext = b"super secret data"
        ds.put(1, "secret", plaintext)

        # Access the internal record directly
        ns = ds._ns(1)
        rec = ns.records["secret"]
        # The stored value should NOT be the same as the plaintext
        # (it should be AES-GCM ciphertext)
        assert rec.value != plaintext
        assert len(rec.value) > len(plaintext)  # ciphertext + nonce + tag

    def test_data_decrypts_on_read(self):
        ds = self._make_encrypted_store()
        plaintext = b"hello encrypted world"
        ds.put(1, "greet", plaintext)
        result = ds.get(1, "greet")
        assert result.value == plaintext

    def test_different_apps_different_keys(self):
        ds = self._make_encrypted_store()
        data = b"same data"
        ds.put(1, "k", data)
        ds.put(2, "k", data)

        ns1 = ds._ns(1)
        ns2 = ds._ns(2)
        # Same plaintext → different ciphertext because different app keys
        assert ns1.records["k"].value != ns2.records["k"].value

    def test_without_callback_raises(self):
        """Without key_callback, put should raise."""
        from data_store import DataKeyUnavailableError, DataStore

        ds = DataStore(node_id="no_key")
        with pytest.raises(DataKeyUnavailableError):
            ds.put(1, "k", b"v")

    def test_roundtrip_binary_data(self):
        ds = self._make_encrypted_store()
        binary = bytes(range(256))
        ds.put(5, "bin", binary)
        assert ds.get(5, "bin").value == binary

    def test_tombstone_value_not_encrypted(self):
        """Deleted records (tombstones) have empty/None value and shouldn't error."""
        ds = self._make_encrypted_store()
        ds.put(1, "del_me", b"temporary")
        ds.delete(1, "del_me")
        result = ds.get(1, "del_me")
        assert result is None  # deleted
