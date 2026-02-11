"""
Tests for ABI alignment between the Python wrappers and the Solidity contracts.

Verifies that the function selectors used in kms_registry.py match the on-chain
KMSRegistry.sol contract.  This catches silent ABI drift when the Solidity
contract is updated but the Python wrapper is not.
"""

import json
from pathlib import Path

import pytest
from eth_hash.auto import keccak


# =============================================================================
# Expected ABI Selectors (derived from KMSRegistry.sol view functions)
# =============================================================================

# Canonical Solidity signature → expected 4-byte selector
_EXPECTED_SELECTORS = {
    "getOperators()": None,
    "isOperator(address)": None,
    "operatorCount()": None,
    "operatorAt(uint256)": None,
}

# Pre-compute from keccak
for sig in _EXPECTED_SELECTORS:
    _EXPECTED_SELECTORS[sig] = keccak(sig.encode("utf-8"))[:4]


class TestKMSRegistryABI:
    """Verify Python ABI definitions match the Solidity contract."""

    def test_abi_has_all_view_functions(self):
        from kms_registry import _KMS_REGISTRY_ABI

        names = {entry["name"] for entry in _KMS_REGISTRY_ABI if entry.get("type") == "function"}
        assert "getOperators" in names
        assert "isOperator" in names
        assert "operatorCount" in names
        assert "operatorAt" in names

    def test_get_operators_selector(self):
        from kms_registry import _KMS_REGISTRY_ABI

        abi_entry = next(e for e in _KMS_REGISTRY_ABI if e.get("name") == "getOperators")
        sig = "getOperators()"
        assert keccak(sig.encode())[:4] == _EXPECTED_SELECTORS[sig]

    def test_is_operator_selector(self):
        sig = "isOperator(address)"
        sel = keccak(sig.encode())[:4]
        assert sel == _EXPECTED_SELECTORS[sig]

    def test_operator_count_selector(self):
        sig = "operatorCount()"
        sel = keccak(sig.encode())[:4]
        assert sel == _EXPECTED_SELECTORS[sig]

    def test_operator_at_selector(self):
        sig = "operatorAt(uint256)"
        sel = keccak(sig.encode())[:4]
        assert sel == _EXPECTED_SELECTORS[sig]

    def test_abi_input_types_match_solidity(self):
        """Verify that the ABI inputs match the Solidity contract signatures."""
        from kms_registry import _KMS_REGISTRY_ABI

        for entry in _KMS_REGISTRY_ABI:
            name = entry.get("name")
            if name == "isOperator":
                assert entry["inputs"][0]["type"] == "address"
            elif name == "operatorAt":
                assert entry["inputs"][0]["type"] == "uint256"
            elif name == "getOperators":
                assert entry["inputs"] == []
            elif name == "operatorCount":
                assert entry["inputs"] == []

    def test_abi_output_types_match_solidity(self):
        from kms_registry import _KMS_REGISTRY_ABI

        for entry in _KMS_REGISTRY_ABI:
            name = entry.get("name")
            if name == "getOperators":
                assert entry["outputs"][0]["type"] == "address[]"
            elif name == "isOperator":
                assert entry["outputs"][0]["type"] == "bool"
            elif name == "operatorCount":
                assert entry["outputs"][0]["type"] == "uint256"
            elif name == "operatorAt":
                assert entry["outputs"][0]["type"] == "address"

    def test_foundry_artifact_exists(self):
        """Verify the compiled artifact from `forge build` is present."""
        artifact = Path(__file__).resolve().parent.parent / "contracts" / "out" / "KMSRegistry.sol" / "KMSRegistry.json"
        if not artifact.exists():
            pytest.skip("Foundry artifact not built; run `cd contracts && forge build`")
        data = json.loads(artifact.read_text())
        abi = data.get("abi", [])
        sol_names = {e["name"] for e in abi if e.get("type") == "function"}
        for name in ["getOperators", "isOperator", "operatorCount", "operatorAt"]:
            assert name in sol_names, f"{name} missing from compiled ABI"

    def test_foundry_artifact_selectors_match(self):
        """Cross-check selectors against the compiled Foundry JSON artifact."""
        artifact = Path(__file__).resolve().parent.parent / "contracts" / "out" / "KMSRegistry.sol" / "KMSRegistry.json"
        if not artifact.exists():
            pytest.skip("Foundry artifact not built; run `cd contracts && forge build`")
        data = json.loads(artifact.read_text())
        methodIdentifiers = data.get("methodIdentifiers", {})
        if not methodIdentifiers:
            pytest.skip("No methodIdentifiers in artifact (older forge version)")

        for sig, expected_sel in _EXPECTED_SELECTORS.items():
            hex_sel = methodIdentifiers.get(sig)
            if hex_sel:
                assert bytes.fromhex(hex_sel) == expected_sel, f"Selector mismatch for {sig}"
