
import pytest
from unittest.mock import MagicMock, patch
import sys
import os

# Add enclave to path
sys.path.append(os.path.join(os.getcwd(), "enclave"))





@patch.dict(sys.modules, {"config": MagicMock(), "chain": MagicMock()})
def test_kms_registry_init_abi():
    # Setup mocks
    sys.modules["config"].KMS_REGISTRY_ADDRESS = "0x" + "11" * 20

    sys.modules["chain"].get_chain = MagicMock()

    mock_w3 = MagicMock()
    mock_contract = MagicMock()
    sys.modules["chain"].get_chain.return_value.w3 = mock_w3
    mock_w3.eth.contract.return_value = mock_contract

    # Init client
    from kms_registry import KMSRegistryClient
    client = KMSRegistryClient()
    
    # Verify contract init
    mock_w3.eth.contract.assert_called_once()
    args, kwargs = mock_w3.eth.contract.call_args
    assert kwargs["address"] == "0x" + "11" * 20

    assert "abi" in kwargs
    # Check if getOperators is in ABI
    abi = kwargs["abi"]
    assert any(item["name"] == "getOperators" for item in abi)

@patch.dict(sys.modules, {"config": MagicMock(), "chain": MagicMock()})
def test_get_operators_call():
    # Setup
    sys.modules["config"].KMS_REGISTRY_ADDRESS = "0x" + "11" * 20

    sys.modules["chain"].get_chain = MagicMock()
    
    mock_w3 = MagicMock()
    mock_contract = MagicMock()
    sys.modules["chain"].get_chain.return_value.w3 = mock_w3
    mock_w3.eth.contract.return_value = mock_contract
    
    # Mock chain call
    mock_chain = sys.modules["chain"].get_chain.return_value
    mock_chain.eth_call_finalized.return_value = b"raw_bytes"
    
    # Mock decode
    mock_contract.decode_function_result.return_value = ["0x" + "aa" * 20, "0x" + "bb" * 20]


    from kms_registry import KMSRegistryClient
    client = KMSRegistryClient()
    ops = client.get_operators()
    
    # Verify
    mock_contract.encodeABI.assert_called_with(fn_name="getOperators", args=[])
    mock_chain.eth_call_finalized.assert_called()
    assert ops == ["0x" + "aa" * 20, "0x" + "bb" * 20]

