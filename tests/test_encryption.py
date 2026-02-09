import pytest
import os
from data_store import DataStore
from kdf import MasterSecretManager

def test_in_memory_encryption_transparency():
    # 1. Setup MasterSecretManager
    msm = MasterSecretManager()
    msm.initialize_from_peer(os.urandom(32))
    
    # 2. Setup DataStore with encryption callback
    def key_callback(app_id):
        return msm.derive(app_id, "data_key")
    
    ds = DataStore(node_id="test-node", key_callback=key_callback)
    
    app_id = 123
    key = "my-secret"
    plaintext = b"super-sensitive-data"
    
    # 3. Put data
    ds.put(app_id, key, plaintext)
    
    # 4. Verify transparency via get()
    rec = ds.get(app_id, key)
    assert rec.value == plaintext
    
    # 5. Verify ENCRYPTION in memory
    # Access internal namespace and records directly
    ns = ds._ns(app_id)
    internal_rec = ns.records[key]
    
    # The internal value should NOT be the plaintext
    assert internal_rec.value != plaintext
    # The internal value should have the 12-byte nonce prefix
    assert len(internal_rec.value) == len(plaintext) + 12 + 16 # Nonce + Ciphertext (incl tag)
    
    print("Encryption test passed: value is encrypted in memory but transparently decrypted via GET")

if __name__ == "__main__":
    test_in_memory_encryption_transparency()
