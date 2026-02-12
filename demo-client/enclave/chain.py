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


"""
==============================================================================
NOTE: Transaction helpers intentionally removed
==============================================================================

The KMS design guarantees that enclave nodes NEVER submit on-chain
transactions — all state changes are driven by NovaAppRegistry callbacks.

Earlier versions of this module included generic transaction-building and
broadcast helpers adapted from the Nova app-template.  They were unused in
this project and posed a risk of accidental misuse, so they have been
removed for clarity and to reinforce the "read-only chain access" invariant.
"""
