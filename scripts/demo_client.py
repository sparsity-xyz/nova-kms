#!/usr/bin/env python3
"""
Demo client to interact with the local KMS simulation cluster.
Requires: pip install requests web3 eth-account
Usage: python3 scripts/demo_client.py
"""

import time
import requests
import secrets
from eth_account import Account
from eth_account.messages import encode_defunct

# Configuration
KMS_URL = "http://localhost:4000"  # Node 0
CLIENT_PRIVATE_KEY = "0x" + secrets.token_hex(32)
CLIENT_WALLET = Account.from_key(CLIENT_PRIVATE_KEY).address.lower()

print(f"--- KMS Simulation Demo Client ---")
print(f"Target: {KMS_URL}")
print(f"Client Wallet: {CLIENT_WALLET}")

def get_auth_headers(payload_path: str):
    # 1. Get Nonce
    try:
        resp = requests.get(f"{KMS_URL}/nonce")
        resp.raise_for_status()
        nonce = resp.json()["nonce"]
    except Exception as e:
        print(f"Error getting nonce: {e}")
        return None

    # 2. Sign auth message
    # Format: NovaKMS:AppAuth:<Nonce>:<KMS_Wallet>:<Timestamp>
    # Note: In simulation, the Node wallet is checking against ITSELF in the auth wrapper 
    # if we don't provide a specific X-App-Wallet? 
    # Actually, auth.py app_identity_from_signature recovers the signer.
    # The message format requires the KMS Wallet (the recipient).
    
    # We need to know Node 0's wallet. 
    # In simulation defaults:
    # Node 0 wallet is deterministic. Let's fetch it from /status if possible, or use the known one.
    # For now, let's use the /status endpoint to find the node's wallet.
    status = requests.get(f"{KMS_URL}/status").json()
    kms_wallet = status["node"]["tee_wallet"]
    
    ts = str(int(time.time()))
    msg = f"NovaKMS:AppAuth:{nonce}:{kms_wallet}:{ts}"
    
    signed = Account.from_key(CLIENT_PRIVATE_KEY).sign_message(encode_defunct(text=msg))
    signature = signed.signature.hex()

    return {
        "x-app-signature": signature,
        "x-app-nonce": nonce,
        "x-app-timestamp": ts,
        "x-app-wallet": CLIENT_WALLET,
        "x-tee-wallet": CLIENT_WALLET, # Required in simulation mode (auth.py defaults to header auth)
    }

def test_derive_key():
    print(f"\n[1] Testing /kms/derive...")
    headers = get_auth_headers("/kms/derive")
    if not headers:
        return

    payload = {
        "path": "m/44/60/0/0/0",
        "context": "demo-context"
    }

    try:
        resp = requests.post(f"{KMS_URL}/kms/derive", json=payload, headers=headers)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 200:
            print(f"Derived Key: {resp.json().get('key')}")
        else:
            print(f"Error: {resp.text}")
    except Exception as e:
        print(f"Request failed: {e}")

def test_kv_store():
    print(f"\n[2] Testing KV Store (PUT /kms/data)...")
    headers = get_auth_headers("/kms/data")
    if not headers:
        return
        
    import base64
    value = base64.b64encode(b"Hello Nova").decode()
    payload = {
        "key": "greeting",
        "value": value
    }
    
    try:
        resp = requests.put(f"{KMS_URL}/kms/data", json=payload, headers=headers)
        print(f"PUT Status: {resp.status_code}")
        print(f"Response: {resp.text}")
        
        print(f"Testing KV Store (GET /kms/data/greeting)...")
        # GET needs auth too
        headers_get = get_auth_headers("/kms/data/greeting")
        resp_get = requests.get(f"{KMS_URL}/kms/data/greeting", headers=headers_get)
        print(f"GET Status: {resp_get.status_code}")
        if resp_get.status_code == 200:
            print(f"Got Value: {resp_get.json()}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    # Wait a bit for simulation to settle if just started
    time.sleep(1)
    test_derive_key()
    test_kv_store()
