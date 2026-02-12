#!/usr/bin/env python3
"""
Verify data sync between simulated KMS nodes.
Usage: python3 scripts/verify_sync.py
"""

import time
import requests
import secrets
from eth_account import Account
from eth_account.messages import encode_defunct

# Configuration
NODE0_URL = "http://localhost:4000"
NODE1_URL = "http://localhost:4001"

# Client Identity (Simulated)
CLIENT_PRIVATE_KEY = "0x" + secrets.token_hex(32)
CLIENT_WALLET = Account.from_key(CLIENT_PRIVATE_KEY).address.lower()

def get_auth_headers(node_url):
    try:
        resp = requests.get(f"{node_url}/nonce")
        resp.raise_for_status()
        nonce = resp.json()["nonce"]
        
        status = requests.get(f"{node_url}/status").json()
        kms_wallet = status["node"]["tee_wallet"]
        
        ts = str(int(time.time()))
        msg = f"NovaKMS:AppAuth:{nonce}:{kms_wallet}:{ts}"
        
        signed = Account.from_key(CLIENT_PRIVATE_KEY).sign_message(encode_defunct(text=msg))
        
        return {
            "x-app-signature": signed.signature.hex(),
            "x-app-nonce": nonce,
            "x-app-timestamp": ts,
            "x-app-wallet": CLIENT_WALLET,
            "x-tee-wallet": CLIENT_WALLET,
        }
    except Exception as e:
        print(f"Auth failed for {node_url}: {e}")
        return None

def verify_sync():
    key = f"sync-test-{int(time.time())}"
    import base64
    val_b64 = base64.b64encode(b"Synced Data").decode()
    
    print(f"--- KMS Sync Verification ---")
    print(f"1. Writing key '{key}' to Node 0 ({NODE0_URL})...")
    
    headers0 = get_auth_headers(NODE0_URL)
    if not headers0: return
    
    payload = {"key": key, "value": val_b64}
    try:
        r = requests.put(f"{NODE0_URL}/kms/data", json=payload, headers=headers0)
        r.raise_for_status()
        print("   Write successful.")
    except Exception as e:
        print(f"   Write failed: {e}")
        return

    print(f"2. Polling Node 1 ({NODE1_URL}) for key '{key}'...")
    print("   (Sync interval is 60s, so this may take a minute)")
    
    start = time.time()
    while time.time() - start < 70:
        headers1 = get_auth_headers(NODE1_URL)
        if headers1:
            try:
                r = requests.get(f"{NODE1_URL}/kms/data/{key}", headers=headers1)
                if r.status_code == 200:
                    print(f"\n[SUCCESS] Key '{key}' found on Node 1!")
                    print(f"Value: {r.json().get('value')}")
                    print(f"Time taken: {time.time() - start:.1f}s")
                    return
            except Exception:
                pass
        
        print(".", end="", flush=True)
        time.sleep(2)
        
    print(f"\n[FAIL] Key '{key}' not found on Node 1 after 70s.")
    print("Check logs to see if sync is running.")

if __name__ == "__main__":
    verify_sync()
