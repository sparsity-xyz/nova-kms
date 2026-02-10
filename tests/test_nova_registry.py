from unittest.mock import MagicMock
from web3 import Web3
from nova_registry import NovaRegistry

def test_nova_registry_call_unwraps_single_output_tuple():
    """
    Regression test: ensures _call correctly unwraps the 1-tuple returned by 
    web3.py for single-output (including struct/tuple) Solidity functions.
    """
    # Construct without running __init__ (avoids chain/RPC requirements).
    reg = NovaRegistry.__new__(NovaRegistry)
    reg.address = "0x" + "00" * 20

    reg.chain = MagicMock()
    # Mock some raw response
    reg.chain.eth_call_finalized.return_value = b"\x00"

    reg.contract = MagicMock()
    reg.contract.encodeABI.return_value = "0xdeadbeef"
    
    # web3.py decode_function_result returns a tuple of outputs.
    # For a struct return, it's a 1-tuple containing the struct (as a tuple).
    mock_struct = (1, 2, 3)
    reg.contract.decode_function_result.return_value = (mock_struct,)

    out = reg._call("getApp", [123])
    
    # Verify it unwrapped the outer 1-tuple
    assert out == mock_struct
    assert out[0] == 1
