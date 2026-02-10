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

def _make_client(*, address="0x" + "11" * 20):
    """Create a KMSRegistryClient with fully mocked chain.
    
    Returns (client, mock_contract, mock_chain, kms_module).
    The kms_module reference is needed for _mock_decode to patch
    _decode_outputs on the correct module object.
    """
    with patch.dict(sys.modules, {"config": MagicMock(), "chain": MagicMock()}):
        sys.modules["config"].KMS_REGISTRY_ADDRESS = address
        mock_chain = MagicMock()
        mock_w3 = MagicMock()
        mock_contract = MagicMock()
        sys.modules["chain"].get_chain.return_value = mock_chain
        mock_chain.w3 = mock_w3
        mock_w3.eth.contract.return_value = mock_contract
        mock_chain.eth_call_finalized.return_value = b"\x00"

        # Make fn.abi an empty dict so the unwrap logic doesn't trip on MagicMock
        mock_contract.get_function_by_name.return_value.return_value.abi = {}

        # Force fresh import
        if "kms_registry" in sys.modules:
            del sys.modules["kms_registry"]
        import kms_registry as kms_mod

        client = kms_mod.KMSRegistryClient()
        return client, mock_contract, mock_chain, kms_mod


def _mock_decode(kms_mod, decode_return):
    """Patch _decode_outputs on the exact kms_registry module object."""
    return patch.object(kms_mod, "_decode_outputs", return_value=decode_return)


# =============================================================================
# Initialization
# =============================================================================


class TestKMSRegistryInit:
    def test_init_creates_contract_with_abi(self):
        """Verify KMSRegistryClient stores a contract with the expected ABI methods."""
        client, mock_contract, _, kms_mod = _make_client()
        assert client.contract is mock_contract
        fn_names = {item["name"] for item in kms_mod._KMS_REGISTRY_ABI}
        assert fn_names == {
            "getOperators", "isOperator", "operatorCount", "operatorAt",
            "masterSecretHash", "setMasterSecretHash", "resetMasterSecretHash",
        }

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
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (42,)):
            result = client._call("operatorCount", [])
        assert result == 42

    def test_passes_through_list_in_single_tuple(self):
        """A list inside a 1-tuple should be unwrapped to the list."""
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (["0xAA", "0xBB"],)):
            result = client._call("getOperators", [])
        assert result == ["0xAA", "0xBB"]

    def test_encodes_and_calls_finalized(self):
        """_call should use get_function_by_name + _encode_transaction_data + eth_call_finalized."""
        client, mock_contract, mock_chain, kms_mod = _make_client()
        with _mock_decode(kms_mod, (["0xAA"],)):
            client._call("getOperators", [])
        mock_contract.get_function_by_name.assert_called_with("getOperators")
        mock_contract.get_function_by_name.return_value.return_value._encode_transaction_data.assert_called_once()
        mock_chain.eth_call_finalized.assert_called_once()


# =============================================================================
# View methods
# =============================================================================


class TestGetOperators:
    def test_returns_operator_list(self):
        ops = ["0x" + "aa" * 20, "0x" + "bb" * 20]
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (ops,)):
            result = client.get_operators()
        assert result == ops

    def test_empty_list(self):
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, ([],)):
            assert client.get_operators() == []


class TestIsOperator:
    def test_returns_true(self):
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (True,)):
            assert client.is_operator("0x" + "aa" * 20) is True

    def test_returns_false(self):
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (False,)):
            assert client.is_operator("0x" + "bb" * 20) is False

    def test_encodes_fn_name(self):
        client, mock_contract, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (True,)):
            client.is_operator("0x" + "aa" * 20)
        mock_contract.get_function_by_name.assert_called_with("isOperator")


class TestOperatorCount:
    def test_returns_count(self):
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (5,)):
            assert client.operator_count() == 5

    def test_zero(self):
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (0,)):
            assert client.operator_count() == 0


class TestOperatorAt:
    def test_returns_address(self):
        addr = "0x" + "cc" * 20
        client, _, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, (addr,)):
            assert client.operator_at(0) == addr

    def test_encodes_index(self):
        client, mock_contract, _, kms_mod = _make_client()
        with _mock_decode(kms_mod, ("0xAA",)):
            client.operator_at(3)
        mock_contract.get_function_by_name.assert_called_with("operatorAt")
        mock_contract.get_function_by_name.return_value.assert_called_with(3)

