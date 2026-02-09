"""Regression tests for NovaRegistry ABI decode behavior."""

from unittest.mock import MagicMock

from nova_registry import NovaRegistry


def test_nova_registry_call_unwraps_single_output_tuple():
    # Construct without running __init__ (avoids chain/RPC requirements).
    reg = NovaRegistry.__new__(NovaRegistry)
    reg.address = "0x" + "00" * 20

    reg.chain = MagicMock()
    reg.chain.eth_call_finalized.return_value = b"\x00"

    reg.contract = MagicMock()
    reg.contract.encodeABI.return_value = "0xdeadbeef"
    # web3.py decode_function_result returns a tuple of outputs; for one output it's a 1-tuple.
    reg.contract.decode_function_result.return_value = ((1, 2, 3),)

    out = reg._call("getApp", [123])
    assert out == (1, 2, 3)
