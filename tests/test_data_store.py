"""
Tests for data_store.py — VectorClock, DataRecord, DataStore.

Covers:
  - VectorClock: increment, merge, happens-before, concurrent, serialization
  - DataRecord: TTL/expiry, serialization round-trip
  - DataStore CRUD: put/get, namespace isolation, delete, keys, value limits
  - Sync: merge_record LWW, deltas_since, snapshot, merge_snapshot
  - Encryption: in-memory encryption transparency, fail-closed in production
  - Eviction: LRU eviction decrements total_bytes
  - Clock skew protection: future/past/within-threshold
  - Stats
"""

import os
import time
import pytest
from unittest.mock import MagicMock

from data_store import DataRecord, DataStore, DataKeyUnavailableError, VectorClock
from kdf import MasterSecretManager


# =============================================================================
# VectorClock
# =============================================================================


class TestVectorClock:
    def test_increment(self):
        vc = VectorClock()
        vc.increment("node_a")
        assert vc.clock == {"node_a": 1}
        vc.increment("node_a")
        assert vc.clock == {"node_a": 2}

    def test_merge(self):
        a = VectorClock({"x": 3, "y": 1})
        b = VectorClock({"x": 1, "y": 5, "z": 2})
        a.merge(b)
        assert a.clock == {"x": 3, "y": 5, "z": 2}

    def test_happened_before(self):
        a = VectorClock({"x": 1})
        b = VectorClock({"x": 2})
        assert a.happened_before(b)
        assert not b.happened_before(a)

    def test_concurrent(self):
        a = VectorClock({"x": 2, "y": 1})
        b = VectorClock({"x": 1, "y": 2})
        assert a.is_concurrent(b)
        assert b.is_concurrent(a)

    def test_identical_not_happened_before(self):
        a = VectorClock({"x": 1})
        b = VectorClock({"x": 1})
        assert not a.happened_before(b)
        assert not b.happened_before(a)

    def test_empty_happened_before_non_empty(self):
        a = VectorClock()
        b = VectorClock({"x": 1})
        assert a.happened_before(b)
        assert not b.happened_before(a)

    def test_empty_clocks_not_happened_before(self):
        a = VectorClock()
        b = VectorClock()
        assert not a.happened_before(b)

    def test_serialization(self):
        vc = VectorClock({"a": 3, "b": 7})
        d = vc.to_dict()
        vc2 = VectorClock.from_dict(d)
        assert vc2.clock == vc.clock

    def test_repr(self):
        vc = VectorClock({"a": 1})
        assert "a" in repr(vc)


# =============================================================================
# DataRecord
# =============================================================================


class TestDataRecord:
    def test_expired(self):
        rec = DataRecord(
            key="k", value=b"v", version=VectorClock(),
            updated_at_ms=int(time.time() * 1000) - 5000,
            ttl_ms=1000,
        )
        assert rec.is_expired

    def test_not_expired(self):
        rec = DataRecord(
            key="k", value=b"v", version=VectorClock(),
            updated_at_ms=int(time.time() * 1000),
            ttl_ms=60_000,
        )
        assert not rec.is_expired

    def test_no_ttl_never_expires(self):
        rec = DataRecord(
            key="k", value=b"v", version=VectorClock(),
            updated_at_ms=0, ttl_ms=0,
        )
        assert not rec.is_expired

    def test_round_trip(self):
        rec = DataRecord(
            key="test", value=b"\xde\xad",
            version=VectorClock({"n1": 5}),
            updated_at_ms=123456, tombstone=False, ttl_ms=1000,
        )
        d = rec.to_dict()
        rec2 = DataRecord.from_dict(d)
        assert rec2.key == rec.key
        assert rec2.value == rec.value
        assert rec2.version.clock == rec.version.clock
        assert rec2.ttl_ms == rec.ttl_ms

    def test_value_size_with_value(self):
        rec = DataRecord(key="k", value=b"hello", version=VectorClock(), updated_at_ms=0)
        assert rec.value_size() == 5

    def test_value_size_none(self):
        rec = DataRecord(key="k", value=None, version=VectorClock(), updated_at_ms=0)
        assert rec.value_size() == 0

    def test_tombstone_round_trip(self):
        rec = DataRecord(
            key="del", value=None, version=VectorClock({"n": 1}),
            updated_at_ms=100, tombstone=True, ttl_ms=0,
        )
        d = rec.to_dict()
        rec2 = DataRecord.from_dict(d)
        assert rec2.tombstone is True
        assert rec2.value is None


# =============================================================================
# DataStore CRUD (plaintext fallback for unit tests)
# =============================================================================


class TestDataStore:
    """Basic CRUD tests with encryption bypassed via monkeypatching."""

    @pytest.fixture(autouse=True)
    def _mock_encryption(self, monkeypatch):
        # Mock DataStore encryption to bypass key management
        from data_store import _Namespace
        monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
        monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)

    def test_put_and_get(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "mykey", b"hello")
        rec = ds.get(1, "mykey")
        assert rec is not None
        assert rec.value == b"hello"

    def test_namespace_isolation(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "key", b"app1")
        ds.put(2, "key", b"app2")
        assert ds.get(1, "key").value == b"app1"
        assert ds.get(2, "key").value == b"app2"

    def test_delete(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "key", b"val")
        ds.delete(1, "key")
        assert ds.get(1, "key") is None

    def test_delete_nonexistent_returns_none(self):
        ds = DataStore(node_id="node1")
        assert ds.delete(1, "no_such_key") is None

    def test_keys(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "a", b"1")
        ds.put(1, "b", b"2")
        ds.put(1, "c", b"3")
        ds.delete(1, "b")
        assert sorted(ds.keys(1)) == ["a", "c"]

    def test_get_nonexistent_returns_none(self):
        ds = DataStore(node_id="node1")
        assert ds.get(1, "nope") is None

    def test_value_too_large(self):
        import config
        ds = DataStore(node_id="node1")
        big = b"x" * (config.MAX_VALUE_SIZE + 1)
        with pytest.raises(ValueError, match="MAX_VALUE_SIZE"):
            ds.put(1, "big", big)

    def test_put_overwrites(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "k", b"v1")
        ds.put(1, "k", b"v2")
        assert ds.get(1, "k").value == b"v2"

    def test_stats(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "a", b"hello")
        ds.put(2, "b", b"world")
        stats = ds.stats()
        assert stats["namespaces"] == 2
        assert stats["total_keys"] == 2
        assert stats["total_bytes"] == 10


# =============================================================================
# Sync operations
# =============================================================================


class TestSyncOperations:
    @pytest.fixture(autouse=True)
    def _mock_encryption(self, monkeypatch):
        from data_store import _Namespace
        monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
        monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)
        
        import config
        monkeypatch.setattr(config, "IN_ENCLAVE", False)

    def test_merge_record_lww(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "key", b"original")

        incoming = DataRecord(
            key="key", value=b"peer_value",
            version=VectorClock({"node2": 1}),
            updated_at_ms=int(time.time() * 1000) + 3_000,
            tombstone=False,
        )
        merged = ds.merge_record(1, incoming)
        assert merged
        assert ds.get(1, "key").value == b"peer_value"

    def test_merge_record_older_rejected(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "key", b"newer")

        incoming = DataRecord(
            key="key", value=b"older",
            version=VectorClock({"node2": 1}),
            updated_at_ms=int(time.time() * 1000) - 60_000,  # far past
            tombstone=False,
        )
        merged = ds.merge_record(1, incoming)
        assert not merged

    def test_deltas_since(self):
        ds = DataStore(node_id="node1")
        before = int(time.time() * 1000)
        time.sleep(0.01)
        ds.put(1, "a", b"1")
        ds.put(2, "b", b"2")
        deltas = ds.get_deltas_since(before)
        assert 1 in deltas
        assert 2 in deltas

    def test_snapshot_merge(self):
        ds1 = DataStore(node_id="node1")
        ds1.put(10, "x", b"val_x")
        ds1.put(10, "y", b"val_y")

        snapshot = ds1.full_snapshot()
        serialized = {
            str(k): [r.to_dict() for r in recs]
            for k, recs in snapshot.items()
        }

        ds2 = DataStore(node_id="node2")
        merged = ds2.merge_snapshot(serialized)
        assert merged == 2
        assert ds2.get(10, "x").value == b"val_x"

    def test_full_snapshot_returns_all(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "a", b"1")
        ds.put(2, "b", b"2")
        snap = ds.full_snapshot()
        assert 1 in snap
        assert 2 in snap


# =============================================================================
# Encryption
# =============================================================================


class TestEncryption:
    def test_in_memory_encryption_transparency(self):
        """Values are encrypted in memory but transparently decrypted via get()."""
        msm = MasterSecretManager()
        msm.initialize_from_peer(os.urandom(32))

        def key_callback(app_id):
            return msm.derive(app_id, "data_key")

        ds = DataStore(node_id="test-node", key_callback=key_callback)
        app_id = 123
        plaintext = b"super-sensitive-data"

        ds.put(app_id, "my-secret", plaintext)
        rec = ds.get(app_id, "my-secret")
        assert rec.value == plaintext

        # Internal record should be encrypted
        ns = ds._ns(app_id)
        internal_rec = ns.records["my-secret"]
        assert internal_rec.value != plaintext
        # 12-byte nonce + ciphertext + 16-byte tag
        assert len(internal_rec.value) == len(plaintext) + 12 + 16

    def test_fail_closed_without_key_in_production(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "IN_ENCLAVE", True)

        ds = DataStore(node_id="node1")
        with pytest.raises(DataKeyUnavailableError):
            ds.put(1, "k", b"v")

    def test_different_apps_different_keys(self):
        """Records for different apps cannot be cross-decrypted."""
        msm = MasterSecretManager()
        msm.initialize_from_peer(os.urandom(32))

        def key_callback(app_id):
            return msm.derive(app_id, "data_key")

        ds = DataStore(node_id="n", key_callback=key_callback)
        ds.put(1, "key", b"app1_data")
        ds.put(2, "key", b"app2_data")
        assert ds.get(1, "key").value == b"app1_data"
        assert ds.get(2, "key").value == b"app2_data"


# =============================================================================
# Eviction
# =============================================================================


class TestEviction:
    @pytest.fixture(autouse=True)
    def _mock_encryption(self, monkeypatch):
        from data_store import _Namespace
        monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
        monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)

    def test_eviction_decrements_total_bytes(self):
        """Regression: _evict_lru must properly decrement _total_bytes."""
        ds = DataStore(node_id="node1")
        ns = ds._ns(1)

        ds.put(1, "a", b"x" * 100)
        ds.put(1, "b", b"y" * 200)
        ds.put(1, "c", b"z" * 300)

        total_before = ns._total_bytes
        assert total_before == 600

        with ns._lock:
            ns._evict_lru(250)

        assert ns._total_bytes < total_before
        assert ns._total_bytes <= 350


# =============================================================================
# Tombstone compaction
# =============================================================================


class TestTombstoneCompaction:
    @pytest.fixture(autouse=True)
    def _mock_encryption(self, monkeypatch):
        from data_store import _Namespace
        monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
        monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)

    def test_expired_tombstones_are_compacted(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "TOMBSTONE_RETENTION_MS", 1000)
        monkeypatch.setattr(config, "MAX_TOMBSTONES_PER_APP", 1000)

        ds = DataStore(node_id="node1")
        ds.put(1, "old", b"v1")
        ds.delete(1, "old")

        ns = ds._ns(1)
        with ns._lock:
            ns.records["old"].updated_at_ms = int(time.time() * 1000) - 10_000

        ds.put(1, "new", b"v2")
        ds.delete(1, "new")

        assert "old" not in ns.records
        assert "new" in ns.records and ns.records["new"].tombstone

    def test_tombstones_are_bounded_by_count_cap(self, monkeypatch):
        import config
        monkeypatch.setattr(config, "TOMBSTONE_RETENTION_MS", 10_000_000)
        monkeypatch.setattr(config, "MAX_TOMBSTONES_PER_APP", 2)

        ds = DataStore(node_id="node1")
        for key in ("a", "b", "c"):
            ds.put(1, key, b"v")
            ds.delete(1, key)
            time.sleep(0.002)

        ns = ds._ns(1)
        tombstones = [k for k, rec in ns.records.items() if rec.tombstone]
        assert len(tombstones) <= 2
        assert "a" not in tombstones


# =============================================================================
# Clock Skew Protection
# =============================================================================


class TestClockSkewProtection:
    @pytest.fixture(autouse=True)
    def _mock_encryption(self, monkeypatch):
        from data_store import _Namespace
        monkeypatch.setattr(_Namespace, "_encrypt", lambda self, v: v)
        monkeypatch.setattr(_Namespace, "_decrypt", lambda self, c: c)
        
        import config
        monkeypatch.setattr(config, "IN_ENCLAVE", False)
        monkeypatch.setattr(config, "MAX_CLOCK_SKEW_MS", 60_000)

    def test_rejects_far_future_timestamp(self):
        ds = DataStore(node_id="node1")
        far_future = int(time.time() * 1000) + 120_000

        incoming = DataRecord(
            key="key1", value=b"data",
            version=VectorClock({"node2": 1}),
            updated_at_ms=far_future, tombstone=False,
        )
        assert ds.merge_record(1, incoming) is False

    def test_accepts_far_past_timestamp(self):
        ds = DataStore(node_id="node1")
        far_past = int(time.time() * 1000) - (24 * 3600 * 1000) # 24 hours ago

        incoming = DataRecord(
            key="key2", value=b"old_data",
            version=VectorClock({"node2": 1}),
            updated_at_ms=far_past, tombstone=False,
        )
        assert ds.merge_record(1, incoming) is True
        assert ds.get(1, "key2").value == b"old_data"

    def test_accepts_within_skew_threshold(self):
        ds = DataStore(node_id="node1")
        within_range = int(time.time() * 1000) + 5_000

        incoming = DataRecord(
            key="key3", value=b"ok_data",
            version=VectorClock({"node2": 1}),
            updated_at_ms=within_range, tombstone=False,
        )
        assert ds.merge_record(1, incoming) is True
        assert ds.get(1, "key3").value == b"ok_data"
