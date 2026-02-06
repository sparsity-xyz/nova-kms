"""
=============================================================================
Blockchain Interaction (chain.py)
=============================================================================

Helper for interacting with the blockchain via Helios light client RPC
(enclave) or a mock RPC (development).  Adapted from the Nova app-template
with KMS-specific contract helpers.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

from web3 import Web3
from web3.exceptions import ContractLogicError
from eth_hash.auto import keccak

from config import CHAIN_ID, CONFIRMATION_DEPTH

logger = logging.getLogger("nova-kms.chain")


# =============================================================================
# Chain (RPC wrapper)
# =============================================================================

class Chain:
    """Low-level RPC helper.  Auto-selects Helios or mock endpoint."""

    DEFAULT_MOCK_RPC = "http://odyn.sparsity.cloud:8545"
    DEFAULT_HELIOS_RPC = "http://127.0.0.1:8545"

    def __init__(self, rpc_url: Optional[str] = None):
        if rpc_url:
            self.endpoint = rpc_url
        else:
            is_enclave = os.getenv("IN_ENCLAVE", "False").lower() == "true"
            self.endpoint = self.DEFAULT_HELIOS_RPC if is_enclave else self.DEFAULT_MOCK_RPC
        self.w3 = Web3(Web3.HTTPProvider(self.endpoint))

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def wait_for_helios(self, timeout: int = 300) -> bool:
        """Block until the RPC node is synced and returns block > 0."""
        is_enclave = os.getenv("IN_ENCLAVE", "False").lower() == "true"
        start = time.time()
        while time.time() - start < timeout:
            try:
                if self.w3.is_connected():
                    if not is_enclave:
                        logger.info("Mock RPC connected")
                        return True
                    syncing = self.w3.eth.syncing
                    if not syncing:
                        block = self.w3.eth.block_number
                        if block > 0:
                            logger.info(f"Helios ready at block {block}")
                            return True
                logger.info(f"Waiting for {'Helios' if is_enclave else 'Mock'} RPC...")
            except Exception:
                pass
            time.sleep(5)
        raise TimeoutError("RPC failed to connect in time")

    # ------------------------------------------------------------------
    # Basic queries
    # ------------------------------------------------------------------

    def get_nonce(self, address: str) -> int:
        return self.w3.eth.get_transaction_count(Web3.to_checksum_address(address))

    def get_balance_eth(self, address: str) -> float:
        return self.w3.eth.get_balance(Web3.to_checksum_address(address)) / 1e18

    def get_latest_block(self) -> int:
        return self.w3.eth.block_number

    def estimate_fees(self):
        """Return (priority_fee, max_fee) for EIP-1559."""
        priority_fee = self.w3.eth.max_priority_fee
        base_fee = self.w3.eth.get_block("latest")["baseFeePerGas"]
        max_fee = (base_fee * 2) + priority_fee
        return priority_fee, max_fee

    # ------------------------------------------------------------------
    # eth_call helper
    # ------------------------------------------------------------------

    def eth_call(self, to: str, data: str) -> bytes:
        """Execute a read-only eth_call and return raw bytes."""
        result = self.w3.eth.call(
            {"to": Web3.to_checksum_address(to), "data": data}
        )
        return bytes(result)

    def eth_call_finalized(self, to: str, data: str) -> bytes:
        """
        Execute a read-only eth_call at a block that has sufficient
        confirmations (CONFIRMATION_DEPTH), protecting against reorg-based
        spoofing of on-chain state (e.g. operator sets).

        Falls back to "latest" if the chain doesn't support block-by-number
        calls or if the confirmed block is unavailable.
        """
        try:
            latest = self.w3.eth.block_number
            confirmed_block = max(0, latest - CONFIRMATION_DEPTH)
            result = self.w3.eth.call(
                {"to": Web3.to_checksum_address(to), "data": data},
                block_identifier=confirmed_block,
            )
            return bytes(result)
        except Exception as exc:
            logger.debug(f"Finalized call fell back to latest: {exc}")
            return self.eth_call(to, data)


# =============================================================================
# Module-level singleton
# =============================================================================

_chain = Chain()


def wait_for_helios(timeout: int = 300) -> bool:
    return _chain.wait_for_helios(timeout)


def get_chain() -> Chain:
    return _chain


# =============================================================================
# ABI helpers
# =============================================================================

def function_selector(signature: str) -> str:
    """Return the 4-byte function selector as 0x-prefixed hex."""
    return "0x" + keccak(signature.encode("utf-8")).hex()[:8]


def encode_uint256(val: int) -> str:
    return hex(val)[2:].zfill(64)


def encode_address(addr: str) -> str:
    return addr.lower().replace("0x", "").zfill(64)


# =============================================================================
# Transaction building & broadcasting
# =============================================================================

def build_tx(
    *,
    odyn: Any,
    chain: Chain,
    to: str,
    data: str,
    gas_limit: int = 300_000,
) -> dict:
    """Build an unsigned EIP-1559 tx dict ready for Odyn signing."""
    tee_address = Web3.to_checksum_address(odyn.eth_address())
    nonce = chain.get_nonce(tee_address)
    priority_fee, max_fee = chain.estimate_fees()

    return {
        "kind": "structured",
        "chain_id": hex(CHAIN_ID),
        "nonce": hex(nonce),
        "max_priority_fee_per_gas": hex(priority_fee),
        "max_fee_per_gas": hex(max_fee),
        "gas_limit": hex(gas_limit),
        "to": Web3.to_checksum_address(to),
        "value": "0x0",
        "data": data,
    }


def sign_and_broadcast(
    *,
    odyn: Any,
    chain: Chain,
    to: str,
    data: str,
    broadcast: bool = True,
    gas_limit: int = 300_000,
) -> Dict[str, Any]:
    """Build, sign and (optionally) broadcast a transaction."""
    tx = build_tx(odyn=odyn, chain=chain, to=to, data=data, gas_limit=gas_limit)
    signed = odyn.sign_tx(tx)

    result: Dict[str, Any] = {
        "raw_transaction": signed.get("raw_transaction"),
        "transaction_hash": signed.get("transaction_hash"),
        "address": signed.get("address"),
        "broadcasted": False,
    }

    if not broadcast:
        return result

    tee_address = Web3.to_checksum_address(odyn.eth_address())
    to_addr = Web3.to_checksum_address(to)

    # Pre-flight simulation
    try:
        chain.w3.eth.call({"from": tee_address, "to": to_addr, "data": data, "value": 0}, "latest")
    except ContractLogicError as cle:
        result["broadcast_error"] = f"Contract reverted: {cle}"
        logger.error(f"Pre-flight failed: {cle}")
        return result
    except Exception as e:
        result["broadcast_error"] = f"Simulation error: {e}"
        logger.error(f"Pre-flight failed: {e}")
        return result

    try:
        tx_hash = chain.w3.eth.send_raw_transaction(signed["raw_transaction"])
        result["broadcasted"] = True
        result["rpc_tx_hash"] = tx_hash.hex()
        logger.info(f"Transaction broadcasted: {tx_hash.hex()}")
    except Exception as e:
        result["broadcast_error"] = str(e)
        logger.error(f"Broadcast failed: {e}")

    return result
