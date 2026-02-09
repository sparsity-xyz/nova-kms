"""
=============================================================================
NovaAppRegistry Python Wrapper (nova_registry.py)
=============================================================================

Read-only helpers for querying the NovaAppRegistry contract.
Used by auth.py to verify requesting app instances.

Includes a CachedNovaRegistry wrapper that adds TTL-based caching to
reduce on-chain RPC calls during high-frequency API requests.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

from web3 import Web3

from chain import function_selector, encode_uint256, encode_address, get_chain
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
        # 1. Encode calldata
        calldata = self.contract.encodeABI(fn_name=fn_name, args=args)
        
        # 2. Perform finalized call (raw bytes)
        # Prefer finalized reads where available for stronger consistency.
        raw_result = self.chain.eth_call_finalized(self.address, calldata)
        
        # 3. Decode result
        decoded = self.contract.decode_function_result(fn_name, raw_result)
        # web3.py returns a tuple of outputs. If the function returns a single
        # value (including a struct), that value is wrapped in a 1-tuple.
        if isinstance(decoded, (list, tuple)) and len(decoded) == 1:
            return decoded[0]
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


# =============================================================================
# Cached wrapper
# =============================================================================

class CachedNovaRegistry:
    """
    TTL-based caching wrapper around NovaRegistry.

    Caches results of get_app, get_version, get_instance_by_wallet to
    reduce on-chain RPC calls.  Cache entries expire after
    REGISTRY_CACHE_TTL_SECONDS.

    Implements the same public API as NovaRegistry so it can be used as a
    drop-in replacement.
    """

    def __init__(self, inner: Optional[NovaRegistry] = None, ttl: Optional[int] = None):
        self._inner = inner or NovaRegistry()
        self._ttl = ttl if ttl is not None else REGISTRY_CACHE_TTL_SECONDS
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    # Proxy attributes
    @property
    def address(self):
        return self._inner.address

    def _get_cached(self, key: str):
        with self._lock:
            entry = self._cache.get(key)
            if entry and (time.time() - entry[0]) < self._ttl:
                return entry[1]
        return None

    def _set_cached(self, key: str, value):
        with self._lock:
            self._cache[key] = (time.time(), value)

    def invalidate(self, key: Optional[str] = None):
        """Clear a specific cache entry or the entire cache."""
        with self._lock:
            if key:
                self._cache.pop(key, None)
            else:
                self._cache.clear()

    def get_app(self, app_id: int) -> App:
        cache_key = f"app:{app_id}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached
        result = self._inner.get_app(app_id)
        self._set_cached(cache_key, result)
        return result

    def get_version(self, app_id: int, version_id: int) -> AppVersion:
        cache_key = f"version:{app_id}:{version_id}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached
        result = self._inner.get_version(app_id, version_id)
        self._set_cached(cache_key, result)
        return result

    def get_instance(self, instance_id: int) -> RuntimeInstance:
        cache_key = f"instance:{instance_id}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached
        result = self._inner.get_instance(instance_id)
        self._set_cached(cache_key, result)
        return result

    def get_instance_by_wallet(self, wallet: str) -> RuntimeInstance:
        cache_key = f"wallet:{wallet.lower()}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached
        result = self._inner.get_instance_by_wallet(wallet)
        self._set_cached(cache_key, result)
        return result

    def get_instances_for_version(self, app_id: int, version_id: int) -> List[int]:
        # Not cached — typically not called in hot paths
        return self._inner.get_instances_for_version(app_id, version_id)
