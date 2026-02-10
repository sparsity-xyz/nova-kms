"""
=============================================================================
KMSRegistry Python Wrapper (kms_registry.py)
=============================================================================

Read-only helpers for querying the KMSRegistry smart contract.

The simplified KMSRegistry only maintains an operator set managed by
NovaAppRegistry callbacks.  KMS nodes do NOT submit on-chain transactions.
Clients / KMS nodes call ``get_operators()`` here, then look up each
operator's instance details via ``NovaRegistry.get_instance_by_wallet()``.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Any

from web3 import Web3

from chain import get_chain
from config import KMS_REGISTRY_ADDRESS

logger = logging.getLogger("nova-kms.kms_registry")


# =============================================================================
# ABI Definition
# =============================================================================

_KMS_REGISTRY_ABI = [
    {
        "inputs": [],
        "name": "getOperators",
        "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
        "name": "isOperator",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "operatorCount",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "name": "operatorAt",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def _abi_type_to_eth_abi_str(abi_item: dict) -> str:
    abi_type = abi_item["type"]
    if not abi_type.startswith("tuple"):
        return abi_type

    # Supports tuple and tuple[]
    suffix = abi_type[len("tuple"):]
    components = abi_item.get("components") or []
    inner = ",".join(_abi_type_to_eth_abi_str(c) for c in components)
    return f"({inner}){suffix}"


def _decode_outputs(fn_abi: dict, raw_result: Any):
    from eth_abi import decode as abi_decode
    from hexbytes import HexBytes

    outputs = fn_abi.get("outputs") or []
    if not outputs:
        return tuple()
    output_types = [_abi_type_to_eth_abi_str(o) for o in outputs]
    return abi_decode(output_types, HexBytes(raw_result))


# =============================================================================
# Public API
# =============================================================================

class KMSRegistryClient:
    """Read-only wrapper for the KMSRegistry smart contract via ABI.

    The contract only stores an operator set (address[]).  For full
    instance details (instanceUrl, teePubkey, status, …), callers
    should use ``NovaRegistry.get_instance_by_wallet(operator)``.
    """

    def __init__(self, address: Optional[str] = None):
        self.address = address or KMS_REGISTRY_ADDRESS
        if not self.address:
            raise ValueError("KMS_REGISTRY_ADDRESS not configured")
        
        self.chain = get_chain()
        self.contract = self.chain.w3.eth.contract(
            address=Web3.to_checksum_address(self.address), 
            abi=_KMS_REGISTRY_ABI
        )

    # ------------------------------------------------------------------
    # Low-level RPC
    # ------------------------------------------------------------------

    def _call(self, fn_name: str, args: list) -> Any:
        """
        Execute a read-only registry call using eth_call_finalized via ABI.
        """
        # 1. Encode calldata (web3 7.x)
        fn = self.contract.get_function_by_name(fn_name)(*args)
        calldata = fn._encode_transaction_data()
        
        # 2. Perform finalized call (raw bytes)
        raw_result = self.chain.eth_call_finalized(self.address, calldata)

        # 3. Decode result (web3 7.x: decode via ABI)
        decoded = _decode_outputs(getattr(fn, "abi", {}), raw_result)
        
        # Unwrap single return values
        if isinstance(decoded, (list, tuple)) and len(decoded) == 1:
            value = decoded[0]
            outputs = (getattr(fn, "abi", {}) or {}).get("outputs") or []
            if outputs and outputs[0].get("type", "").endswith("[]") and isinstance(value, tuple):
                return list(value)
            return value
        return decoded

    # ------------------------------------------------------------------
    # Views
    # ------------------------------------------------------------------

    def get_operators(self) -> List[str]:
        """Return the full list of operator addresses from the contract."""
        return self._call("getOperators", [])

    def is_operator(self, wallet: str) -> bool:
        """Check whether *wallet* is a registered operator."""
        return self._call("isOperator", [Web3.to_checksum_address(wallet)])

    def operator_count(self) -> int:
        """Return the number of operators."""
        return self._call("operatorCount", [])

    def operator_at(self, index: int) -> str:
        """Return the operator address at *index*."""
        return self._call("operatorAt", [index])
