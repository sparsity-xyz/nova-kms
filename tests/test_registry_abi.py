import json
import os
import sys
from unittest.mock import MagicMock

# Mock chain module BEFORE importing registry modules to avoid connection attempts
mock_chain_module = MagicMock()
sys.modules["chain"] = mock_chain_module
sys.modules["enclave.chain"] = mock_chain_module

from enclave.kms_registry import _KMS_REGISTRY_ABI
from enclave.nova_registry import _NOVA_REGISTRY_ABI
import pytest

ARTIFACTS_DIR = os.path.join(
    os.path.dirname(__file__), 
    "../contracts/out"
)

def normalize_abi(abi_list):
    """
    Normalize ABI list for comparison.
    1. Filter out 'constructor', 'error', 'event' types as we only care about functions we call.
    2. Sort by name to ensure order independence.
    3. Remove 'internalType' as it's not strictly required for web3.py execution (though good to have).
    """
    normalized = []
    
    for item in abi_list:
        if item.get("type") != "function":
            continue
            
        # Create a copy to modify
        clean_item = item.copy()
        
        # We can keep internalType if we want strict matching, usually beneficial.
        # But if the python definition omits it, we might need to remove it from artifact.
        # checking the python code, it HAS internalType. So we should compare exactly.
        
        normalized.append(clean_item)
        
    # Sort by function name
    return sorted(normalized, key=lambda x: x.get("name", ""))

def load_artifact_abi(artifact_path):
    with open(artifact_path, "r") as f:
        data = json.load(f)
        return data["abi"]

def test_kms_registry_abi_matches_artifact():
    artifact_path = os.path.join(ARTIFACTS_DIR, "KMSRegistry.sol/KMSRegistry.json")
    artifact_abi = load_artifact_abi(artifact_path)
    
    norm_artifact = normalize_abi(artifact_abi)
    norm_python = normalize_abi(_KMS_REGISTRY_ABI)
    
    # We only implemented a SUBSET of the ABI in python (read-only views).
    # So we should check that every item in python ABI exists in the artifact ABI.
    
    artifact_map = {item["name"]: item for item in norm_artifact}
    
    for py_item in norm_python:
        func_name = py_item["name"]
        assert func_name in artifact_map, f"Function {func_name} in Python ABI not found in Solidity artifact"
        
        artifact_item = artifact_map[func_name]
        
        # Compare inputs
        assert py_item["inputs"] == artifact_item["inputs"], \
            f"Inputs mismatch for {func_name}.\nPy: {py_item['inputs']}\nArt: {artifact_item['inputs']}"
            
        # Compare outputs
        assert py_item["outputs"] == artifact_item["outputs"], \
            f"Outputs mismatch for {func_name}.\nPy: {py_item['outputs']}\nArt: {artifact_item['outputs']}"
            
        # Compare state mutability
        assert py_item["stateMutability"] == artifact_item["stateMutability"], \
            f"StateMutability mismatch for {func_name}"

# test_nova_registry_abi_matches_artifact skipped: 
# NovaAppRegistry is a platform contract external to this repo.
