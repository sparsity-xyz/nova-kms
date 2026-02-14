import unittest
import time
from unittest.mock import MagicMock, patch
from collections import OrderedDict
import sys
import os

# sys.path is handled by tests/conftest.py when running with pytest,
# but we add it here just in case this file is run directly.
enclave_dir = os.path.join(os.path.dirname(__file__), "..", "enclave")
if enclave_dir not in sys.path:
    sys.path.append(enclave_dir)

import config
from sync_manager import PeerCache
from data_store import DataStore, _Namespace, DataRecord, VectorClock, DecryptionError
from auth import _NonceStore

class TestImprovements(unittest.TestCase):

    # -------------------------------------------------------------------------
    # PeerCache Blacklist Tests
    # -------------------------------------------------------------------------
    def test_peer_cache_blacklist(self):
        pc = PeerCache(kms_registry_client=MagicMock(), nova_registry=MagicMock())
        peer1 = {"tee_wallet_address": "0x111", "node_url": "http://1.1.1.1"}
        peer2 = {"tee_wallet_address": "0x222", "node_url": "http://2.2.2.2"}
        
        pc._peers = [peer1, peer2]
        pc._last_refresh = time.time()
        
        # 1. Initial state: multiple peers
        self.assertEqual(len(pc.get_peers(refresh_if_stale=False)), 2)
        
        # 2. Blacklist peer1
        pc.blacklist_peer("0x111", duration=10)
        self.assertIn("0x111", pc._blacklist)
        
        # 3. get_peers should filter out blacklisted
        peers = pc.get_peers(refresh_if_stale=False)
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["tee_wallet_address"], "0x222")
        
        # 4. Peer1 should be removed from _peers immediately too
        self.assertEqual(len(pc._peers), 1)
        
        # 5. Expire blacklist
        with patch("time.time", return_value=time.time() + 11):
            peers_after = pc.get_peers(refresh_if_stale=False)
            # It's purged from blacklist, but not in _peers anymore because we removed it
            self.assertNotIn("0x111", pc._blacklist)
            self.assertEqual(len(peers_after), 1)

    # -------------------------------------------------------------------------
    # DataStore LRU Tests
    # -------------------------------------------------------------------------
    def test_datastore_lru_eviction(self):
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
            
            self.assertEqual(len(ns.records), 3)
            
            # Key 1 is oldest. Access Key 1 to make it newest.
            ds.get(app_id, "key1")
            
            # Put Key 4, should trigger eviction of Key 2 (now oldest)
            ds.put(app_id, "key4", b"val4")
            
            self.assertEqual(len(ns.records), 3)
            self.assertIn("key1", ns.records)
            self.assertNotIn("key2", ns.records)
            self.assertIn("key3", ns.records)
            self.assertIn("key4", ns.records)

    def test_datastore_decryption_error(self):
        def mock_key_callback(app_id):
            return b"0" * 32
        ds = DataStore(node_id="node1", key_callback=mock_key_callback)
        app_id = 42
        ds.put(app_id, "key1", b"secret")
        
        # Mock decrypt_data to fail
        with patch("kdf.decrypt_data", side_effect=Exception("corrupt")):
            with self.assertRaises(DecryptionError):
                ds.get(app_id, "key1")

    # -------------------------------------------------------------------------
    # NonceStore Purge Tests
    # -------------------------------------------------------------------------
    def test_nonce_store_optimized_purge(self):
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
            
            self.assertEqual(len(ns._nonces), 1)
            self.assertIn(n3, ns._nonces)
            self.assertNotIn(n1, ns._nonces)
            self.assertNotIn(n2, ns._nonces)

if __name__ == "__main__":
    unittest.main()
