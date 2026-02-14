"""
=============================================================================
In-Memory Data Store (data_store.py)
=============================================================================

Non-persistent key-value store with vector-clock versioning, per-app
namespace isolation, TTL expiration, and LRU eviction.

See architecture.md §4 for the design.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import config

logger = logging.getLogger("nova-kms.data_store")



class DecryptionError(Exception):
    """Raised when data decryption fails."""
    pass


class DataKeyUnavailableError(RuntimeError):
    """Raised when per-app encryption keys are required but unavailable."""
    pass


# =============================================================================
# Vector Clock
# =============================================================================

class VectorClock:
    """Lamport-style vector clock for distributed consistency."""

    __slots__ = ("clock",)

    def __init__(self, clock: Optional[Dict[str, int]] = None):
        self.clock: Dict[str, int] = dict(clock) if clock else {}

    def increment(self, node_id: str) -> None:
        self.clock[node_id] = self.clock.get(node_id, 0) + 1

    def merge(self, other: VectorClock) -> None:
        for nid, cnt in other.clock.items():
            self.clock[nid] = max(self.clock.get(nid, 0), cnt)

    def happened_before(self, other: VectorClock) -> bool:
        """Return True if self causally happened-before other (strictly)."""
        if not self.clock:
            return bool(other.clock)
        all_keys = set(self.clock) | set(other.clock)
        le = all(self.clock.get(k, 0) <= other.clock.get(k, 0) for k in all_keys)
        lt = any(self.clock.get(k, 0) < other.clock.get(k, 0) for k in all_keys)
        return le and lt

    def is_concurrent(self, other: VectorClock) -> bool:
        """True if neither clock happened-before the other."""
        return not self.happened_before(other) and not other.happened_before(self)

    def to_dict(self) -> Dict[str, int]:
        return dict(self.clock)

    @classmethod
    def from_dict(cls, d: Dict[str, int]) -> VectorClock:
        return cls(d)

    def __repr__(self) -> str:
        return f"VectorClock({self.clock})"


# =============================================================================
# Data Record
# =============================================================================

@dataclass
class DataRecord:
    key: str
    value: Optional[bytes]
    version: VectorClock
    updated_at_ms: int
    tombstone: bool = False
    ttl_ms: int = 0  # 0 = no expiry

    @property
    def is_expired(self) -> bool:
        if self.ttl_ms <= 0:
            return False
        return (time.time() * 1000) > (self.updated_at_ms + self.ttl_ms)

    def value_size(self) -> int:
        return len(self.value) if self.value else 0

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value.hex() if self.value else None,
            "version": self.version.to_dict(),
            "updated_at_ms": self.updated_at_ms,
            "tombstone": self.tombstone,
            "ttl_ms": self.ttl_ms,
        }

    @classmethod
    def from_dict(cls, d: dict) -> DataRecord:
        return cls(
            key=d["key"],
            value=bytes.fromhex(d["value"]) if d.get("value") else None,
            version=VectorClock.from_dict(d.get("version", {})),
            updated_at_ms=d.get("updated_at_ms", 0),
            tombstone=d.get("tombstone", False),
            ttl_ms=d.get("ttl_ms", 0),
        )


# =============================================================================
# Namespace (per-App storage)
# =============================================================================

class _Namespace:
    """Thread-safe KV namespace for a single app_id."""

    def __init__(self, app_id: int, key_callback=None):
        self.app_id = app_id
        self.records: Dict[str, DataRecord] = {}
        self._lock = threading.Lock()
        self._total_bytes = 0
        self._key_callback = key_callback
        self._cached_key: Optional[bytes] = None

    def _get_key(self) -> Optional[bytes]:
        """Fetch/cache the per-app data encryption key."""
        if self._cached_key:
            return self._cached_key
        if self._key_callback:
            try:
                self._cached_key = self._key_callback(self.app_id)
                return self._cached_key
            except Exception as exc:
                logger.error(f"Failed to derive data key for app {self.app_id}: {exc}")
        return None

    def _encrypt(self, value: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os
        key = self._get_key()
        if not key:
            raise DataKeyUnavailableError(f"Encryption key unavailable for app {self.app_id}")
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, value, None)

    def _decrypt(self, ciphertext: bytes) -> Optional[bytes]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if not ciphertext:
            return None
        key = self._get_key()
        if not key:
            raise DataKeyUnavailableError(f"Decryption key unavailable for app {self.app_id}")
        try:
            aesgcm = AESGCM(key)
            nonce = ciphertext[:12]
            return aesgcm.decrypt(nonce, ciphertext[12:], None)
        except Exception as exc:
            logger.error(f"Decryption failed for app {self.app_id}: {exc}")
            raise DecryptionError(f"Decryption failed for app {self.app_id}") from exc

    def get(self, key: str) -> Optional[DataRecord]:
        with self._lock:
            rec = self.records.get(key)
            if rec is None:
                return None
            if rec.tombstone or rec.is_expired:
                return None
            
            # Decrypt value for the caller.
            # Low fix: propagate DecryptionError instead of silently returning
            # None, so callers (API layer) can distinguish "key not found" from
            # "data corrupted / key unavailable" and respond appropriately.
            decrypted_value = self._decrypt(rec.value) if rec.value else None
            return DataRecord(
                key=rec.key,
                value=decrypted_value,
                version=rec.version,
                updated_at_ms=rec.updated_at_ms,
                tombstone=rec.tombstone,
                ttl_ms=rec.ttl_ms
            )

    def put(
        self,
        key: str,
        value: bytes,
        node_id: str,
        ttl_ms: int = 0,
    ) -> DataRecord:
        if len(value) > config.MAX_VALUE_SIZE:
            raise ValueError(f"Value size {len(value)} exceeds MAX_VALUE_SIZE ({config.MAX_VALUE_SIZE})")

        with self._lock:
            old = self.records.get(key)
            vc = VectorClock(old.version.clock if old else {})
            vc.increment(node_id)

            encrypted_value = self._encrypt(value)
            new_size = len(encrypted_value)
            old_size = old.value_size() if old and not old.tombstone else 0
            projected = self._total_bytes - old_size + new_size
            if projected > config.MAX_APP_STORAGE:
                self._evict_lru(projected - config.MAX_APP_STORAGE)

            rec = DataRecord(
                key=key,
                value=encrypted_value,
                version=vc,
                updated_at_ms=int(time.time() * 1000),
                tombstone=False,
                ttl_ms=ttl_ms if ttl_ms else config.DEFAULT_TTL_MS,
            )
            self._total_bytes += new_size - old_size
            self.records[key] = rec
            
            # Return record with original plaintext value
            return DataRecord(
                key=rec.key,
                value=value,
                version=rec.version,
                updated_at_ms=rec.updated_at_ms,
                tombstone=rec.tombstone,
                ttl_ms=rec.ttl_ms
            )

    def delete(self, key: str, node_id: str) -> Optional[DataRecord]:
        with self._lock:
            old = self.records.get(key)
            if old is None:
                return None
            vc = VectorClock(old.version.clock)
            vc.increment(node_id)
            rec = DataRecord(
                key=key,
                value=None,
                version=vc,
                updated_at_ms=int(time.time() * 1000),
                tombstone=True,
                ttl_ms=0,
            )
            self._total_bytes -= old.value_size() if not old.tombstone else 0
            self.records[key] = rec
            return rec

    def keys(self) -> List[str]:
        with self._lock:
            return [
                k for k, r in self.records.items()
                if not r.tombstone and not r.is_expired
            ]

    def merge_record(self, incoming: DataRecord) -> bool:
        """
        Merge an incoming record (from sync).  Returns True if the local
        store was updated.

        Conflict resolution: LWW (Last-Writer-Wins by updated_at_ms).
        Rejects records with timestamps too far from local time (clock skew
        protection).
        """
        with self._lock:
            # Basic bounds checks (defense-in-depth regardless of mode)
            if incoming.value is not None:
                # incoming.value is stored encrypted; allow modest overhead.
                if len(incoming.value) > (config.MAX_VALUE_SIZE + 128):
                    logger.warning(
                        f"Rejecting record '{incoming.key}': value too large ({len(incoming.value)} bytes)"
                    )
                    return False

            # In production, reject obviously invalid ciphertext and optionally probe-decrypt.
            if config.IN_ENCLAVE and incoming.value is not None and not incoming.tombstone:
                # Format is: 12-byte nonce + AESGCM(ciphertext||tag). Tag is 16 bytes.
                if len(incoming.value) < (12 + 16):
                    logger.warning(
                        f"Rejecting record '{incoming.key}': ciphertext too short ({len(incoming.value)} bytes)"
                    )
                    return False
                key = self._get_key()
                if not key:
                    logger.warning(
                        f"Rejecting record '{incoming.key}': encryption key unavailable for validation"
                    )
                    return False
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                    aesgcm = AESGCM(key)
                    nonce = incoming.value[:12]
                    _ = aesgcm.decrypt(nonce, incoming.value[12:], None)
                except Exception as exc:
                    logger.warning(
                        f"Rejecting record '{incoming.key}': ciphertext failed validation ({exc})"
                    )
                    return False

            # Clock skew protection: reject records with implausible timestamps
            now_ms = int(time.time() * 1000)
            skew = abs(incoming.updated_at_ms - now_ms)
            if config.MAX_CLOCK_SKEW_MS > 0 and skew > config.MAX_CLOCK_SKEW_MS:
                logger.warning(
                    f"Rejecting record '{incoming.key}': clock skew {skew}ms "
                    f"exceeds MAX_CLOCK_SKEW_MS ({config.MAX_CLOCK_SKEW_MS}ms)"
                )
                return False

            existing = self.records.get(incoming.key)
            if existing is None:
                self.records[incoming.key] = incoming
                self._total_bytes += incoming.value_size()
                return True

            # If incoming happened-after existing, accept
            if existing.version.happened_before(incoming.version):
                self._total_bytes += incoming.value_size() - existing.value_size()
                self.records[incoming.key] = incoming
                return True

            # Concurrent → LWW
            if existing.version.is_concurrent(incoming.version):
                if incoming.updated_at_ms > existing.updated_at_ms:
                    self._total_bytes += incoming.value_size() - existing.value_size()
                    self.records[incoming.key] = incoming
                    return True

            return False

    def get_deltas_since(self, since_ms: int) -> List[DataRecord]:
        """Return records updated after *since_ms*."""
        with self._lock:
            return [
                r for r in self.records.values()
                if r.updated_at_ms > since_ms
            ]

    def snapshot(self) -> List[DataRecord]:
        """Return all non-expired records (including tombstones for sync)."""
        with self._lock:
            return list(self.records.values())

    # ------------------------------------------------------------------

    def _evict_lru(self, bytes_to_free: int) -> None:
        """Evict oldest (by updated_at_ms) non-tombstone records until quota is met."""
        freed = 0
        candidates = sorted(
            ((k, r) for k, r in self.records.items() if not r.tombstone),
            key=lambda x: x[1].updated_at_ms,
        )
        for key, rec in candidates:
            old_size = rec.value_size()  # capture size BEFORE clearing
            rec.tombstone = True
            rec.value = None
            self._total_bytes -= old_size
            freed += old_size
            if freed >= bytes_to_free:
                break


# =============================================================================
# DataStore (top-level, all namespaces)
# =============================================================================

class DataStore:
    """
    Thread-safe in-memory data store partitioned by app_id.
    Non-persistent — all data lives only in enclave memory.
    """

    def __init__(self, node_id: str, key_callback=None):
        self.node_id = node_id
        self._namespaces: Dict[int, _Namespace] = {}
        self._lock = threading.Lock()
        self._key_callback = key_callback

    def _ns(self, app_id: int) -> _Namespace:
        with self._lock:
            if app_id not in self._namespaces:
                self._namespaces[app_id] = _Namespace(app_id, key_callback=self._key_callback)
            return self._namespaces[app_id]

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def get(self, app_id: int, key: str) -> Optional[DataRecord]:
        return self._ns(app_id).get(key)

    def put(self, app_id: int, key: str, value: bytes, ttl_ms: int = 0) -> DataRecord:
        return self._ns(app_id).put(key, value, self.node_id, ttl_ms)

    def delete(self, app_id: int, key: str) -> Optional[DataRecord]:
        return self._ns(app_id).delete(key, self.node_id)

    def keys(self, app_id: int) -> List[str]:
        return self._ns(app_id).keys()

    # ------------------------------------------------------------------
    # Sync
    # ------------------------------------------------------------------

    def merge_record(self, app_id: int, record: DataRecord) -> bool:
        """
        Merge a record from a peer. Note that record.value is already 
        encrypted if coming from a peer with the same master secret.
        """
        return self._ns(app_id).merge_record(record)

    def get_deltas_since(self, since_ms: int) -> Dict[int, List[DataRecord]]:
        """
        Return deltas across all namespaces. Values returned here are 
        ENCRYPTED from the internal records.
        """
        with self._lock:
            ns_ids = list(self._namespaces.keys())
        result: Dict[int, List[DataRecord]] = {}
        for app_id in ns_ids:
            deltas = self._ns(app_id).get_deltas_since(since_ms)
            if deltas:
                result[app_id] = deltas
        return result

    def full_snapshot(self) -> Dict[int, List[DataRecord]]:
        """Values returned here are ENCRYPTED."""
        with self._lock:
            ns_ids = list(self._namespaces.keys())
        return {
            app_id: self._ns(app_id).snapshot()
            for app_id in ns_ids
        }

    def merge_snapshot(self, snapshot: Dict[int, List[dict]]) -> int:
        """Merge a full snapshot received from a peer.  Returns count of merged records."""
        merged = 0
        for app_id_str, records in snapshot.items():
            app_id = int(app_id_str)
            for rec_dict in records:
                rec = DataRecord.from_dict(rec_dict)
                if self.merge_record(app_id, rec):
                    merged += 1
        return merged

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            ns_ids = list(self._namespaces.keys())
        total_keys = 0
        total_bytes = 0
        for app_id in ns_ids:
            ns = self._ns(app_id)
            total_keys += len(ns.keys())
            total_bytes += ns._total_bytes
        return {
            "namespaces": len(ns_ids),
            "total_keys": total_keys,
            "total_bytes": total_bytes,
        }
