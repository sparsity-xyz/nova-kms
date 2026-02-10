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
    {
        "inputs": [],
        "name": "masterSecretHash",
        "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "newHash", "type": "bytes32"}],
        "name": "setMasterSecretHash",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "resetMasterSecretHash",
        "outputs": [],
        "stateMutability": "nonpayable",
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
    # Transaction helpers (signed by Odyn)
    # ------------------------------------------------------------------

    def _build_eip1559_tx(self, *, from_addr: str, to_addr: str, data: str) -> dict:
        """Build a minimal EIP-1559 transaction dict for Odyn signing."""
        priority_fee, max_fee = self.chain.estimate_fees()
        nonce = self.chain.get_nonce(from_addr)
        return {
            "chainId": self.chain.w3.eth.chain_id,
            "type": 2,
            "from": Web3.to_checksum_address(from_addr),
            "to": Web3.to_checksum_address(to_addr),
            "nonce": nonce,
            "data": data,
            "value": 0,
            "maxPriorityFeePerGas": int(priority_fee),
            "maxFeePerGas": int(max_fee),
            # Conservative gas; Odyn may not expose estimateGas inside enclave.
            "gas": 300000,
        }

    @staticmethod
    def _extract_raw_tx(sign_res: dict) -> Optional[str]:
        """Best-effort extraction of raw signed tx hex from Odyn response."""
        if not isinstance(sign_res, dict):
            return None
        for key in (
            "raw_transaction",
            "rawTransaction",
            "signed_tx",
            "signedTx",
            "tx",
            "transaction",
        ):
            v = sign_res.get(key)
            if isinstance(v, str) and v.startswith("0x"):
                return v
        payload = sign_res.get("payload")
        if isinstance(payload, dict):
            for key in ("raw_transaction", "rawTransaction", "signed_tx", "signedTx"):
                v = payload.get(key)
                if isinstance(v, str) and v.startswith("0x"):
                    return v
        return None

    def _send_signed_tx(self, raw_tx_hex: str) -> str:
        tx_hash = self.chain.w3.eth.send_raw_transaction(raw_tx_hex)
        if hasattr(tx_hash, "hex"):
            return tx_hash.hex()
        return Web3.to_hex(tx_hash)

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

    def get_master_secret_hash(self) -> bytes:
        """Return on-chain masterSecretHash as raw bytes32."""
        v = self._call("masterSecretHash", [])
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
        if isinstance(v, str) and v.startswith("0x"):
            return bytes.fromhex(v[2:])
        # web3 can return HexBytes
        try:
            return bytes(v)
        except Exception:
            raise ValueError("Unexpected masterSecretHash type")

    def set_master_secret_hash(self, odyn, *, setter_wallet: str, secret_hash32: bytes) -> str:
        """Submit tx to set masterSecretHash (allowed once when unset)."""
        if len(secret_hash32) != 32:
            raise ValueError("secret_hash32 must be 32 bytes")

        fn = self.contract.get_function_by_name("setMasterSecretHash")(secret_hash32)
        data = fn._encode_transaction_data()
        tx = self._build_eip1559_tx(from_addr=setter_wallet, to_addr=self.address, data=data)

        sign_res = odyn.sign_tx(tx)
        raw_tx = self._extract_raw_tx(sign_res)
        if not raw_tx:
            raise RuntimeError(f"Odyn sign_tx returned unexpected payload: {sign_res}")
        return self._send_signed_tx(raw_tx)

    def reset_master_secret_hash(self, odyn, *, owner_wallet: str) -> str:
        """Owner-only tx to reset masterSecretHash to 0."""
        fn = self.contract.get_function_by_name("resetMasterSecretHash")()
        data = fn._encode_transaction_data()
        tx = self._build_eip1559_tx(from_addr=owner_wallet, to_addr=self.address, data=data)

        sign_res = odyn.sign_tx(tx)
        raw_tx = self._extract_raw_tx(sign_res)
        if not raw_tx:
            raise RuntimeError(f"Odyn sign_tx returned unexpected payload: {sign_res}")
        return self._send_signed_tx(raw_tx)
