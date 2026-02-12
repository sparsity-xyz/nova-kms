"""
Verification script for nova-kms-client.
Simulates a running KMS environment and checks if the client can successfully interact with it.
"""
import sys
import os
import asyncio
import time
from unittest.mock import MagicMock, patch

# Add enclave directory to path
enclave_path = os.path.join(os.getcwd(), "enclave")
sys.path.append(enclave_path)

# This verification script runs fully mocked (no chain, no real HTTP).
# Keep environment minimal; the example client itself is registry-only.
os.environ["IN_ENCLAVE"] = "false"

# Mock Key components BEFORE importing config
sys.modules["chain"] = MagicMock()
sys.modules["chain"].wait_for_helios = MagicMock()
sys.modules["chain"].function_selector = MagicMock()
sys.modules["chain"].encode_uint256 = MagicMock()
sys.modules["chain"].encode_address = MagicMock()
sys.modules["chain"].get_chain = MagicMock()

# Mock Web3
sys.modules["web3"] = MagicMock()
sys.modules["web3.exceptions"] = MagicMock()

# Mock Contract for KMSRegistry
mock_w3 = MagicMock()
mock_contract = MagicMock()
# Setup w3 chain connection
sys.modules["chain"].get_chain.return_value.w3 = mock_w3
# When contract() is called, return our mock contract
mock_w3.eth.contract.return_value = mock_contract

# Import config first to ensure mocks are in place, then app
import config
# Patch fixed parameters for test (required for registry-only client)
config.NOVA_APP_REGISTRY_ADDRESS = "0xMockNovaRegistry"
config.KMS_REGISTRY_ADDRESS = "0xMockKMSRegistry"

import app
from app import KMSClient, request_logs
import nova_registry

async def run_verification():
    print("Starting verification...")

    fixed_time = 1700000000
    fixed_ts = str(int(fixed_time))
    fixed_ts_b64 = __import__("base64").b64encode(fixed_ts.encode("utf-8")).decode("utf-8")
    
    # 1. Mock HTTPX Client
    mock_response_derive = MagicMock()
    mock_response_derive.status_code = 200
    mock_response_derive.json.return_value = {"key": "dGVzdF9rZXk="} # test_key base64

    mock_response_put = MagicMock()
    mock_response_put.status_code = 200
    mock_response_put.json.return_value = {"status": "ok"}

    mock_response_get = MagicMock()
    mock_response_get.status_code = 200
    mock_response_get.json.return_value = {"value": fixed_ts_b64}

    mock_response_health = MagicMock()
    mock_response_health.status_code = 200
    mock_response_health.json.return_value = {"status": "ok"}

    mock_response_nonce = MagicMock()
    mock_response_nonce.status_code = 200
    mock_response_nonce.json.return_value = {"nonce": "MDAwMA=="} # 0000 base64
    
    mock_response_status = MagicMock()
    mock_response_status.status_code = 200
    mock_response_status.json.return_value = {"node": {"tee_wallet": "0xKMSWallet"}}

    async def mock_request(*args, **kwargs):
        method = "UNKNOWN"
        url = "UNKNOWN"
        
        # Heuristic to find method and url
        if len(args) >= 3:
             method = args[1]
             url = args[2]
        elif len(args) >= 2:
            if args[0] in ["GET", "POST", "PUT", "DELETE"]:
                method = args[0]
                url = args[1]
        
        if "method" in kwargs: method = kwargs["method"]
        if "url" in kwargs: url = kwargs["url"]

        if "nonce" in str(url):
            return mock_response_nonce
        if "status" in str(url):
            return mock_response_status
        if "/health" in str(url):
            return mock_response_health
        if "derive" in str(url):
            return mock_response_derive
        if "data" in str(url) and method == "PUT":
            return mock_response_put
        if "data" in str(url) and method == "GET":
            return mock_response_get
        return MagicMock(status_code=404)

    # Patch httpx.AsyncClient.request
    with patch("httpx.AsyncClient.request", side_effect=mock_request) as mock_req:

        # Freeze time used by the client so GET returns the expected timestamp
        with patch.object(app.time, "time", return_value=fixed_time):
            # Run one cycle
            client = KMSClient()

            mock_instance = MagicMock()
            mock_instance.instance_id = 1
            mock_instance.app_id = 1
            mock_instance.version_id = 1
            mock_instance.operator = "0xOp1"
            mock_instance.instance_url = "http://mock-kms:4000"
            mock_instance.tee_wallet_address = "0xKMSWallet"
            mock_instance.zk_verified = True
            mock_instance.status = nova_registry.InstanceStatus.ACTIVE

            with patch.object(client, "get_operators", return_value=["0xOp1"]):
                with patch.object(client, "get_instance", return_value=mock_instance):
                    await client.run_test_cycle()

    # Check logs
    print("\nVerification Results:")
    found_success = False
    for log in request_logs:
        print(f"[{log['status']}] {log['action']} - {log['error'] if log['error'] else 'OK'}")
        if log['status'] == 'Success':
            found_success = True
    
    if found_success:
        print("\nSUCCESS: Client successfully executed test cycle.")
        sys.exit(0)
    else:
        print("\nFAILURE: No successful operations found in logs.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(run_verification())
