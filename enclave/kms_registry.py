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
from typing import List, Optional

from web3 import Web3

from chain import function_selector, encode_uint256, encode_address, get_chain
from config import KMS_REGISTRY_ADDRESS

logger = logging.getLogger("nova-kms.kms_registry")


# =============================================================================
# Selectors (read-only — KMS nodes never write to the contract)
# =============================================================================

_GET_OPERATORS = function_selector("getOperators()")
_IS_OPERATOR = function_selector("isOperator(address)")
_OPERATOR_COUNT = function_selector("operatorCount()")
_OPERATOR_AT = function_selector("operatorAt(uint256)")


# =============================================================================
# ABI decode helpers
# =============================================================================

def _u256(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 32], "big")


def _addr(data: bytes, off: int) -> str:
    return Web3.to_checksum_address("0x" + data[off + 12 : off + 32].hex())


# =============================================================================
# Public API
# =============================================================================

class KMSRegistryClient:
    """Read-only wrapper for the KMSRegistry smart contract.

    The contract only stores an operator set (address[]).  For full
    instance details (instanceUrl, teePubkey, status, …), callers
    should use ``NovaRegistry.get_instance_by_wallet(operator)``.
    """

    def __init__(self, address: Optional[str] = None):
        self.address = address or KMS_REGISTRY_ADDRESS
        if not self.address:
            raise ValueError("KMS_REGISTRY_ADDRESS not configured")

    # ------------------------------------------------------------------
    # Low-level RPC
    # ------------------------------------------------------------------

    def _call(self, data: str) -> bytes:
        """
        Low-level helper for read-only registry calls.

        Uses eth_call_finalized to reduce the risk of observing a transient
        operator set during short-lived chain reorgs. Falls back to latest
        if the RPC node cannot serve historical state.
        """
        chain = get_chain()
        return chain.eth_call_finalized(self.address, data)

    # ------------------------------------------------------------------
    # Views
    # ------------------------------------------------------------------

    def get_operators(self) -> List[str]:
        """Return the full list of operator addresses from the contract."""
        raw = self._call(_GET_OPERATORS)
        # ABI: address[] — dynamic array
        # word 0 = offset to array data (always 0x20)
        # at offset: word = length, then length × address words
        offset = _u256(raw, 0)
        length = _u256(raw, offset)
        return [_addr(raw, offset + 32 + i * 32) for i in range(length)]

    def is_operator(self, wallet: str) -> bool:
        """Check whether *wallet* is a registered operator."""
        raw = self._call(_IS_OPERATOR + encode_address(wallet))
        return _u256(raw, 0) != 0

    def operator_count(self) -> int:
        """Return the number of operators."""
        raw = self._call(_OPERATOR_COUNT)
        return _u256(raw, 0)

    def operator_at(self, index: int) -> str:
        """Return the operator address at *index*."""
        raw = self._call(_OPERATOR_AT + encode_uint256(index))
        return _addr(raw, 0)
