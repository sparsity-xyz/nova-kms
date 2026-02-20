import time
from unittest.mock import MagicMock, patch
import os
import sys
import pytest

# sys.path is handled by tests/conftest.py when running with pytest,
# but we add it here just in case this file is run directly.
enclave_dir = os.path.join(os.path.dirname(__file__), "..", "enclave")
if enclave_dir not in sys.path:
    sys.path.append(enclave_dir)

from sync_manager import PeerCache
from data_store import DataStore, DecryptionError
from auth import _NonceStore


# -------------------------------------------------------------------------
# PeerCache Blacklist Tests
# -------------------------------------------------------------------------
def test_peer_cache_blacklist():
    pc = PeerCache(kms_registry_client=MagicMock(), nova_registry=MagicMock())
    peer1 = {"tee_wallet_address": "0x111", "node_url": "http://1.1.1.1"}
    peer2 = {"tee_wallet_address": "0x222", "node_url": "http://2.2.2.2"}
    
    pc._peers = [peer1, peer2]
    pc._last_refresh = time.time()
    
    # 1. Initial state: multiple peers
    assert len(pc.get_peers(refresh_if_stale=False)) == 2
    
    # 2. Blacklist peer1
    pc.blacklist_peer("0x111", duration=10)
    assert "0x111" in pc._blacklist
    
    # 3. get_peers should filter out blacklisted
    peers = pc.get_peers(refresh_if_stale=False)
    assert len(peers) == 1
    assert peers[0]["tee_wallet_address"] == "0x222"
    
    # 4. Peer1 should be removed from _peers immediately too
    assert len(pc._peers) == 1
    
    # 5. Expire blacklist
    with patch("time.time", return_value=time.time() + 11):
        peers_after = pc.get_peers(refresh_if_stale=False)
        # It's purged from blacklist, but not in _peers anymore because we removed it
        assert "0x111" not in pc._blacklist
        assert len(peers_after) == 1

# -------------------------------------------------------------------------
# DataStore LRU Tests
# -------------------------------------------------------------------------
def test_datastore_lru_eviction():
    def mock_key_callback(app_id):
        return b"0" * 32
    
    def mock_encrypt(val):
        return val + b"0" * 28 # Simulate AESGCM overhead

    # Mock config to have small storage
    with patch("config.MAX_APP_STORAGE", 100):
        ds = DataStore(node_id="node1", key_callback=mock_key_callback)
        app_id = 42
        ns = ds._ns(app_id)
        ns._encrypt = mock_encrypt
        ns._decrypt = lambda val: val[:-28] # Reverse mock_encrypt
        
        # 32 bytes each
        ds.put(app_id, "key1", b"val1")
        ds.put(app_id, "key2", b"val2")
        ds.put(app_id, "key3", b"val3") # Total 96 bytes
        
        assert len(ns.records) == 3
        
        # Key 1 is oldest. Access Key 1 to make it newest.
        ds.get(app_id, "key1")
        
        # Put Key 4, should trigger eviction of Key 2 (now oldest)
        ds.put(app_id, "key4", b"val4")
        
        assert len(ns.records) == 3
        assert "key1" in ns.records
        assert "key2" not in ns.records
        assert "key3" in ns.records
        assert "key4" in ns.records

def test_datastore_decryption_error():
    def mock_key_callback(app_id):
        return b"0" * 32
    ds = DataStore(node_id="node1", key_callback=mock_key_callback)
    app_id = 42
    ds.put(app_id, "key1", b"secret")
    
    # Mock decrypt_data to fail
    with patch("kdf.decrypt_data", side_effect=Exception("corrupt")):
        with pytest.raises(DecryptionError):
            ds.get(app_id, "key1")

# -------------------------------------------------------------------------
# NonceStore Purge Tests
# -------------------------------------------------------------------------
def test_nonce_store_optimized_purge():
    ns = _NonceStore(ttl_seconds=10, max_nonces=2)
    
    now = time.time()
    with patch("time.time", return_value=now):
        n1 = ns.issue()
        n2 = ns.issue()
    
    # Move time forward so n1, n2 are expired
    now += 15
    with patch("time.time", return_value=now):
        # Issuing n3 should trigger _purge because len >= max_nonces
        n3 = ns.issue()
        
        assert len(ns._nonces) == 1
        assert n3 in ns._nonces
        assert n1 not in ns._nonces
        assert n2 not in ns._nonces
