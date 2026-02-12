"""
=============================================================================
NovaAppRegistry Python Wrapper (nova_registry.py)
=============================================================================

Read-only helpers for querying the NovaAppRegistry contract.
Used by nova-kms-client to resolve KMS operator instances.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, List, Optional

from abi_helpers import abi_type_to_eth_abi_str as _abi_type_to_eth_abi_str
from abi_helpers import decode_outputs as _decode_outputs

from web3 import Web3

from chain import get_chain
from config import NOVA_APP_REGISTRY_ADDRESS, REGISTRY_CACHE_TTL_SECONDS

logger = logging.getLogger("nova-kms.nova_registry")


# =============================================================================
# Enums (mirror Solidity)
# =============================================================================

class AppStatus(IntEnum):
    ACTIVE = 0
    INACTIVE = 1
    REVOKED = 2


class VersionStatus(IntEnum):
    ENROLLED = 0
    DEPRECATED = 1
    REVOKED = 2


class InstanceStatus(IntEnum):
    ACTIVE = 0
    STOPPED = 1
    FAILED = 2


# =============================================================================
# Data classes
# =============================================================================

@dataclass
class App:
    app_id: int
    owner: str
    tee_arch: bytes
    dapp_contract: str
    metadata_uri: str
    latest_version_id: int
    created_at: int
    status: AppStatus


@dataclass
class AppVersion:
    version_id: int
    version_name: str
    code_measurement: bytes
    image_uri: str
    audit_url: str
    audit_hash: str
    github_run_id: str
    status: VersionStatus
    enrolled_at: int
    enrolled_by: str


@dataclass
class RuntimeInstance:
    instance_id: int
    app_id: int
    version_id: int
    operator: str
    instance_url: str
    tee_pubkey: bytes
    tee_wallet_address: str
    zk_verified: bool
    status: InstanceStatus
    registered_at: int


# =============================================================================
# ABI Definition
# =============================================================================

_NOVA_REGISTRY_ABI = [
    {
        "inputs": [{"internalType": "uint256", "name": "appId", "type": "uint256"}],
        "name": "getApp",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "id", "type": "uint256"},
                    {"internalType": "address", "name": "owner", "type": "address"},
                    {"internalType": "bytes32", "name": "teeArch", "type": "bytes32"},
                    {"internalType": "address", "name": "dappContract", "type": "address"},
                    {"internalType": "string", "name": "metadataUri", "type": "string"},
                    {"internalType": "uint256", "name": "latestVersionId", "type": "uint256"},
                    {"internalType": "uint256", "name": "createdAt", "type": "uint256"},
                    {"internalType": "enum AppStatus", "name": "status", "type": "uint8"},
                ],
                "internalType": "struct App",
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "appId", "type": "uint256"},
            {"internalType": "uint256", "name": "versionId", "type": "uint256"},
        ],
        "name": "getVersion",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "id", "type": "uint256"},
                    {"internalType": "string", "name": "versionName", "type": "string"},
                    {"internalType": "bytes32", "name": "codeMeasurement", "type": "bytes32"},
                    {"internalType": "string", "name": "imageUri", "type": "string"},
                    {"internalType": "string", "name": "auditUrl", "type": "string"},
                    {"internalType": "string", "name": "auditHash", "type": "string"},
                    {"internalType": "string", "name": "githubRunId", "type": "string"},
                    {"internalType": "enum VersionStatus", "name": "status", "type": "uint8"},
                    {"internalType": "uint256", "name": "enrolledAt", "type": "uint256"},
                    {"internalType": "address", "name": "enrolledBy", "type": "address"},
                ],
                "internalType": "struct AppVersion",
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "instanceId", "type": "uint256"}],
        "name": "getInstance",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "id", "type": "uint256"},
                    {"internalType": "uint256", "name": "appId", "type": "uint256"},
                    {"internalType": "uint256", "name": "versionId", "type": "uint256"},
                    {"internalType": "address", "name": "operator", "type": "address"},
                    {"internalType": "string", "name": "instanceUrl", "type": "string"},
                    {"internalType": "bytes", "name": "teePubkey", "type": "bytes"},
                    {"internalType": "address", "name": "teeWalletAddress", "type": "address"},
                    {"internalType": "bool", "name": "zkVerified", "type": "bool"},
                    {"internalType": "enum InstanceStatus", "name": "status", "type": "uint8"},
                    {"internalType": "uint256", "name": "registeredAt", "type": "uint256"},
                ],
                "internalType": "struct RuntimeInstance",
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "wallet", "type": "address"}],
        "name": "getInstanceByWallet",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "id", "type": "uint256"},
                    {"internalType": "uint256", "name": "appId", "type": "uint256"},
                    {"internalType": "uint256", "name": "versionId", "type": "uint256"},
                    {"internalType": "address", "name": "operator", "type": "address"},
                    {"internalType": "string", "name": "instanceUrl", "type": "string"},
                    {"internalType": "bytes", "name": "teePubkey", "type": "bytes"},
                    {"internalType": "address", "name": "teeWalletAddress", "type": "address"},
                    {"internalType": "bool", "name": "zkVerified", "type": "bool"},
                    {"internalType": "enum InstanceStatus", "name": "status", "type": "uint8"},
                    {"internalType": "uint256", "name": "registeredAt", "type": "uint256"},
                ],
                "internalType": "struct RuntimeInstance",
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "appId", "type": "uint256"},
            {"internalType": "uint256", "name": "versionId", "type": "uint256"},
        ],
        "name": "getInstancesForVersion",
        "outputs": [{"internalType": "uint256[]", "name": "", "type": "uint256[]"}],
        "stateMutability": "view",
        "type": "function",
    },
]


# _abi_type_to_eth_abi_str and _decode_outputs imported from abi_helpers above.


# =============================================================================
# Public API
# =============================================================================

class NovaRegistry:
    """Read-only wrapper for the NovaAppRegistry proxy contract."""

    def __init__(self, address: Optional[str] = None):
        self.address = address or NOVA_APP_REGISTRY_ADDRESS
        if not self.address:
            raise ValueError("NOVA_APP_REGISTRY_ADDRESS not configured")
        
        self.chain = get_chain()
        # Initialize Web3 Contract object for encoding/decoding
        self.contract = self.chain.w3.eth.contract(
            address=Web3.to_checksum_address(self.address),
            abi=_NOVA_REGISTRY_ABI
        )

    def _call(self, fn_name: str, args: list) -> Any:
        """
        Execute a read-only registry call using eth_call_finalized.
        Encodes calldata using web3.py and decodes the result.
        """
        # 1. Encode calldata (web3 7.x)
        fn = self.contract.get_function_by_name(fn_name)(*args)
        calldata = fn._encode_transaction_data()
        
        # 2. Perform finalized call (raw bytes)
        # Prefer finalized reads where available for stronger consistency.
        raw_result = self.chain.eth_call_finalized(self.address, calldata)
        
        # 3. Decode result (web3 7.x: decode via ABI)
        decoded = _decode_outputs(getattr(fn, "abi", {}), raw_result)
        # web3.py returns a tuple of outputs. If the function returns a single
        # value (including a struct), that value is wrapped in a 1-tuple.
        if isinstance(decoded, (list, tuple)) and len(decoded) == 1:
            value = decoded[0]
            outputs = (getattr(fn, "abi", {}) or {}).get("outputs") or []
            if outputs and outputs[0].get("type", "").endswith("[]") and isinstance(value, tuple):
                return list(value)
            return value
        return decoded

    def get_app(self, app_id: int) -> App:
        # returns (id, owner, teeArch, dappContract, metadataUri, latestVersionId, createdAt, status)
        result = self._call("getApp", [app_id])
        # result is a list/tuple or a dict depending on web3 version/strictness, 
        # usually a list of values if returned as a struct in tuple form.
        # Ensure we map correctly to App dataclass
        # web3.py usually returns structs as tuples/lists
        
        # Unpack tuple assuming order matches ABI
        return App(
            app_id=result[0],
            owner=result[1],
            tee_arch=result[2],
            dapp_contract=result[3],
            metadata_uri=result[4],
            latest_version_id=result[5],
            created_at=result[6],
            status=AppStatus(result[7]),
        )

    def get_version(self, app_id: int, version_id: int) -> AppVersion:
        result = self._call("getVersion", [app_id, version_id])
        return AppVersion(
            version_id=result[0],
            version_name=result[1],
            code_measurement=result[2],
            image_uri=result[3],
            audit_url=result[4],
            audit_hash=result[5],
            github_run_id=result[6],
            status=VersionStatus(result[7]),
            enrolled_at=result[8],
            enrolled_by=result[9],
        )

    def get_instance(self, instance_id: int) -> RuntimeInstance:
        result = self._call("getInstance", [instance_id])
        return RuntimeInstance(
            instance_id=result[0],
            app_id=result[1],
            version_id=result[2],
            operator=result[3],
            instance_url=result[4],
            tee_pubkey=result[5],
            tee_wallet_address=result[6],
            zk_verified=result[7],
            status=InstanceStatus(result[8]),
            registered_at=result[9],
        )

    def get_instance_by_wallet(self, wallet: str) -> RuntimeInstance:
        result = self._call("getInstanceByWallet", [Web3.to_checksum_address(wallet)])
        return RuntimeInstance(
            instance_id=result[0],
            app_id=result[1],
            version_id=result[2],
            operator=result[3],
            instance_url=result[4],
            tee_pubkey=result[5],
            tee_wallet_address=result[6],
            zk_verified=result[7],
            status=InstanceStatus(result[8]),
            registered_at=result[9],
        )

    def get_instances_for_version(self, app_id: int, version_id: int) -> List[int]:
        result = self._call("getInstancesForVersion", [app_id, version_id])
        # result is list of uint256
        return result
