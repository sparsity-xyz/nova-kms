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
# ABI Selectors
# =============================================================================

_GET_APP = function_selector("getApp(uint256)")
_GET_VERSION = function_selector("getVersion(uint256,uint256)")
_GET_INSTANCE = function_selector("getInstance(uint256)")
_GET_INSTANCE_BY_WALLET = function_selector("getInstanceByWallet(address)")
_GET_INSTANCES_FOR_VERSION = function_selector("getInstancesForVersion(uint256,uint256)")


# =============================================================================
# ABI decoding helpers
# =============================================================================

def _decode_uint(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 32], "big")


def _decode_address(data: bytes, offset: int) -> str:
    return Web3.to_checksum_address("0x" + data[offset + 12 : offset + 32].hex())


def _decode_bool(data: bytes, offset: int) -> bool:
    return _decode_uint(data, offset) != 0


def _decode_bytes32(data: bytes, offset: int) -> bytes:
    return bytes(data[offset : offset + 32])


def _decode_bytes(data: bytes, base: int, ptr_offset: int) -> bytes:
    """Decode a dynamic `bytes` field from ABI-encoded data."""
    ptr = _decode_uint(data, base + ptr_offset)
    abs_offset = base + ptr
    length = _decode_uint(data, abs_offset)
    return bytes(data[abs_offset + 32 : abs_offset + 32 + length])


def _decode_string(data: bytes, base: int, ptr_offset: int) -> str:
    return _decode_bytes(data, base, ptr_offset).decode("utf-8", errors="replace")


# =============================================================================
# Decoders for each struct
# =============================================================================

def _decode_app(data: bytes) -> App:
    """Decode ABI-encoded App struct (returned from getApp)."""
    # The struct is returned as a tuple inside an outer offset pointer.
    base = _decode_uint(data, 0)  # offset to tuple start
    return App(
        app_id=_decode_uint(data, base + 0 * 32),
        owner=_decode_address(data, base + 1 * 32),
        tee_arch=_decode_bytes32(data, base + 2 * 32),
        dapp_contract=_decode_address(data, base + 3 * 32),
        metadata_uri=_decode_string(data, base, 4 * 32),
        latest_version_id=_decode_uint(data, base + 5 * 32),
        created_at=_decode_uint(data, base + 6 * 32),
        status=AppStatus(_decode_uint(data, base + 7 * 32)),
    )


def _decode_version(data: bytes) -> AppVersion:
    base = _decode_uint(data, 0)
    return AppVersion(
        version_id=_decode_uint(data, base + 0 * 32),
        version_name=_decode_string(data, base, 1 * 32),
        code_measurement=_decode_bytes32(data, base + 2 * 32),
        image_uri=_decode_string(data, base, 3 * 32),
        audit_url=_decode_string(data, base, 4 * 32),
        audit_hash=_decode_string(data, base, 5 * 32),
        github_run_id=_decode_string(data, base, 6 * 32),
        status=VersionStatus(_decode_uint(data, base + 7 * 32)),
        enrolled_at=_decode_uint(data, base + 8 * 32),
        enrolled_by=_decode_address(data, base + 9 * 32),
    )


def _decode_instance(data: bytes) -> RuntimeInstance:
    base = _decode_uint(data, 0)
    return RuntimeInstance(
        instance_id=_decode_uint(data, base + 0 * 32),
        app_id=_decode_uint(data, base + 1 * 32),
        version_id=_decode_uint(data, base + 2 * 32),
        operator=_decode_address(data, base + 3 * 32),
        instance_url=_decode_string(data, base, 4 * 32),
        tee_pubkey=_decode_bytes(data, base, 5 * 32),
        tee_wallet_address=_decode_address(data, base + 6 * 32),
        zk_verified=_decode_bool(data, base + 7 * 32),
        status=InstanceStatus(_decode_uint(data, base + 8 * 32)),
        registered_at=_decode_uint(data, base + 9 * 32),
    )


# =============================================================================
# Public API
# =============================================================================

class NovaRegistry:
    """Read-only wrapper for the NovaAppRegistry proxy contract."""

    def __init__(self, address: Optional[str] = None):
        self.address = address or NOVA_APP_REGISTRY_ADDRESS
        if not self.address:
            raise ValueError("NOVA_APP_REGISTRY_ADDRESS not configured")

    def _call(self, data: str) -> bytes:
        """
        Low-level helper for read-only registry calls.

        Uses eth_call_finalized to protect against short-lived reorgs spoofing
        App / Version / Instance state. Falls back to latest if the RPC node
        does not support historical calls.
        """
        chain = get_chain()
        # Prefer finalized reads where available for stronger consistency.
        return chain.eth_call_finalized(self.address, data)

    def get_app(self, app_id: int) -> App:
        data = _GET_APP + encode_uint256(app_id)
        raw = self._call(data)
        return _decode_app(raw)

    def get_version(self, app_id: int, version_id: int) -> AppVersion:
        data = _GET_VERSION + encode_uint256(app_id) + encode_uint256(version_id)
        raw = self._call(data)
        return _decode_version(raw)

    def get_instance(self, instance_id: int) -> RuntimeInstance:
        data = _GET_INSTANCE + encode_uint256(instance_id)
        raw = self._call(data)
        return _decode_instance(raw)

    def get_instance_by_wallet(self, wallet: str) -> RuntimeInstance:
        data = _GET_INSTANCE_BY_WALLET + encode_address(wallet)
        raw = self._call(data)
        return _decode_instance(raw)

    def get_instances_for_version(self, app_id: int, version_id: int) -> List[int]:
        data = _GET_INSTANCES_FOR_VERSION + encode_uint256(app_id) + encode_uint256(version_id)
        raw = self._call(data)
        # Returns uint256[]
        offset = _decode_uint(raw, 0)
        length = _decode_uint(raw, offset)
        return [_decode_uint(raw, offset + 32 + i * 32) for i in range(length)]


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
