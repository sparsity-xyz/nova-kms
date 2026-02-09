"""
Tests for data_store.py — VectorClock, DataRecord, and DataStore.
"""

import time
import pytest

from data_store import DataRecord, DataStore, VectorClock


# =============================================================================
# VectorClock tests
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
        # Identical clocks: neither happened-before the other
        assert not a.happened_before(b)
        assert not b.happened_before(a)

    def test_serialization(self):
        vc = VectorClock({"a": 3, "b": 7})
        d = vc.to_dict()
        vc2 = VectorClock.from_dict(d)
        assert vc2.clock == vc.clock


# =============================================================================
# DataRecord tests
# =============================================================================


class TestDataRecord:
    def test_expired(self):
        rec = DataRecord(
            key="k",
            value=b"v",
            version=VectorClock(),
            updated_at_ms=int(time.time() * 1000) - 5000,
            ttl_ms=1000,  # expired 4 seconds ago
        )
        assert rec.is_expired

    def test_not_expired(self):
        rec = DataRecord(
            key="k",
            value=b"v",
            version=VectorClock(),
            updated_at_ms=int(time.time() * 1000),
            ttl_ms=60_000,
        )
        assert not rec.is_expired

    def test_no_ttl_never_expires(self):
        rec = DataRecord(
            key="k",
            value=b"v",
            version=VectorClock(),
            updated_at_ms=0,
            ttl_ms=0,
        )
        assert not rec.is_expired

    def test_round_trip(self):
        rec = DataRecord(
            key="test",
            value=b"\xde\xad",
            version=VectorClock({"n1": 5}),
            updated_at_ms=123456,
            tombstone=False,
            ttl_ms=1000,
        )
        d = rec.to_dict()
        rec2 = DataRecord.from_dict(d)
        assert rec2.key == rec.key
        assert rec2.value == rec.value
        assert rec2.version.clock == rec.version.clock
        assert rec2.ttl_ms == rec.ttl_ms


# =============================================================================
# DataStore tests
# =============================================================================


class TestDataStore:
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

    def test_keys(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "a", b"1")
        ds.put(1, "b", b"2")
        ds.put(1, "c", b"3")
        ds.delete(1, "b")
        assert sorted(ds.keys(1)) == ["a", "c"]

    def test_value_too_large(self):
        ds = DataStore(node_id="node1")
        import config
        big = b"x" * (config.MAX_VALUE_SIZE + 1)
        with pytest.raises(ValueError, match="MAX_VALUE_SIZE"):
            ds.put(1, "big", big)

    def test_merge_record_lww(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "key", b"original")

        # Simulate an incoming concurrent record with a later timestamp
        incoming = DataRecord(
            key="key",
            value=b"peer_value",
            version=VectorClock({"node2": 1}),
            updated_at_ms=int(time.time() * 1000) + 10_000,
            tombstone=False,
        )
        merged = ds.merge_record(1, incoming)
        assert merged
        assert ds.get(1, "key").value == b"peer_value"

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

    def test_stats(self):
        ds = DataStore(node_id="node1")
        ds.put(1, "a", b"hello")
        ds.put(2, "b", b"world")
        stats = ds.stats()
        assert stats["namespaces"] == 2
        assert stats["total_keys"] == 2
        assert stats["total_bytes"] == 10

    def test_fail_closed_without_key_in_production(self, monkeypatch):
        import config
        from data_store import DataKeyUnavailableError

        monkeypatch.setattr(config, "IN_ENCLAVE", True)
        monkeypatch.setattr(config, "ALLOW_PLAINTEXT_FALLBACK", False)

        ds = DataStore(node_id="node1")
        with pytest.raises(DataKeyUnavailableError):
            ds.put(1, "k", b"v")
