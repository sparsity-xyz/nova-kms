"""
Tests for kms_registry.py — KMSRegistryClient read-only contract wrapper.

Covers:
  - Initialization with ABI
  - Missing address error
  - All view methods: get_operators, is_operator, operator_count, operator_at
  - _call unwrap logic for single vs multi return values
"""

import pytest
from unittest.mock import MagicMock, patch
import sys


# =============================================================================
# Helpers
# =============================================================================

def _make_client(
    *,
    address="0x" + "11" * 20,
    eth_call_return=b"raw_bytes",
    decode_return=None,
):
    """Create a KMSRegistryClient with fully mocked chain."""
    with patch.dict(sys.modules, {"config": MagicMock(), "chain": MagicMock()}):
        sys.modules["config"].KMS_REGISTRY_ADDRESS = address
        mock_chain = MagicMock()
        mock_w3 = MagicMock()
        mock_contract = MagicMock()
        sys.modules["chain"].get_chain.return_value = mock_chain
        mock_chain.w3 = mock_w3
        mock_w3.eth.contract.return_value = mock_contract

        mock_chain.eth_call_finalized.return_value = eth_call_return
        if decode_return is not None:
            mock_fn = MagicMock()
            mock_fn.decode_output.return_value = decode_return
            mock_contract.get_function_by_name.return_value = mock_fn

        # Force fresh import
        if "kms_registry" in sys.modules:
            del sys.modules["kms_registry"]
        from kms_registry import KMSRegistryClient

        client = KMSRegistryClient()
        return client, mock_contract, mock_chain


# =============================================================================
# Initialization
# =============================================================================


class TestKMSRegistryInit:
    def test_init_creates_contract_with_abi(self):
        """Verify KMSRegistryClient stores a contract with the expected ABI methods."""
        client, mock_contract, _ = _make_client()
        # The client's contract attribute is the mock that w3.eth.contract() returned
        assert client.contract is mock_contract
        # Verify the ABI has all 4 view functions by checking the imported module-level constant
        from kms_registry import _KMS_REGISTRY_ABI
        fn_names = {item["name"] for item in _KMS_REGISTRY_ABI}
        assert fn_names == {"getOperators", "isOperator", "operatorCount", "operatorAt"}

    def test_init_missing_address_raises(self):
        with patch.dict(sys.modules, {"config": MagicMock(), "chain": MagicMock()}):
            sys.modules["config"].KMS_REGISTRY_ADDRESS = ""
            if "kms_registry" in sys.modules:
                del sys.modules["kms_registry"]
            from kms_registry import KMSRegistryClient
            with pytest.raises(ValueError, match="KMS_REGISTRY_ADDRESS"):
                KMSRegistryClient()


# =============================================================================
# _call unwrap logic
# =============================================================================


class TestCallUnwrap:
    def test_unwraps_single_return_value(self):
        """Single-output functions decode to a 1-tuple and should be unwrapped."""
        client, mock_contract, mock_chain = _make_client(decode_return=(42,))
        result = client._call("operatorCount", [])
        assert result == 42

    def test_passes_through_list_in_single_tuple(self):
        """A list inside a 1-tuple should be unwrapped to the list."""
        client, mock_contract, _ = _make_client(decode_return=(["0xAA", "0xBB"],))
        result = client._call("getOperators", [])
        assert result == ["0xAA", "0xBB"]

    def test_encodes_and_calls_finalized(self):
        """_call should use encodeABI + eth_call_finalized + decode."""
        client, mock_contract, mock_chain = _make_client(decode_return=(["0xAA"],))
        mock_contract.encodeABI.return_value = "0xdeadbeef"
        client._call("getOperators", [])
        mock_contract.encodeABI.assert_called_with(fn_name="getOperators", args=[])
        mock_chain.eth_call_finalized.assert_called_once()
        mock_contract.get_function_by_name.assert_called_with("getOperators")
        mock_contract.get_function_by_name.return_value.decode_output.assert_called_once()


# =============================================================================
# View methods
# =============================================================================


class TestGetOperators:
    def test_returns_operator_list(self):
        ops = ["0x" + "aa" * 20, "0x" + "bb" * 20]
        client, mock_contract, _ = _make_client(decode_return=(ops,))
        result = client.get_operators()
        assert result == ops
        mock_contract.encodeABI.assert_called_with(fn_name="getOperators", args=[])

    def test_empty_list(self):
        client, _, _ = _make_client(decode_return=([],))
        assert client.get_operators() == []


class TestIsOperator:
    def test_returns_true(self):
        client, _, _ = _make_client(decode_return=(True,))
        assert client.is_operator("0x" + "aa" * 20) is True

    def test_returns_false(self):
        client, _, _ = _make_client(decode_return=(False,))
        assert client.is_operator("0x" + "bb" * 20) is False

    def test_encodes_fn_name(self):
        client, mock_contract, _ = _make_client(decode_return=(True,))
        client.is_operator("0x" + "aa" * 20)
        mock_contract.encodeABI.assert_called_once()
        assert mock_contract.encodeABI.call_args[1]["fn_name"] == "isOperator"


class TestOperatorCount:
    def test_returns_count(self):
        client, _, _ = _make_client(decode_return=(5,))
        assert client.operator_count() == 5

    def test_zero(self):
        client, _, _ = _make_client(decode_return=(0,))
        assert client.operator_count() == 0


class TestOperatorAt:
    def test_returns_address(self):
        addr = "0x" + "cc" * 20
        client, _, _ = _make_client(decode_return=(addr,))
        assert client.operator_at(0) == addr

    def test_encodes_index(self):
        client, mock_contract, _ = _make_client(decode_return=("0xAA",))
        client.operator_at(3)
        mock_contract.encodeABI.assert_called_with(fn_name="operatorAt", args=[3])

