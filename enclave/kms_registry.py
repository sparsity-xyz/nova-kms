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
        # 1. Encode calldata
        calldata = self.contract.encodeABI(fn_name=fn_name, args=args)
        
        # 2. Perform finalized call (raw bytes)
        raw_result = self.chain.eth_call_finalized(self.address, calldata)

        # 3. Decode result
        decoded = self.contract.decode_function_result(fn_name, raw_result)
        
        # Unwrap single return values
        if isinstance(decoded, (list, tuple)) and len(decoded) == 1:
            return decoded[0]
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
