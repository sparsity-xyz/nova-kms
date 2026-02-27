use crate::models::{DataRecord, VCComparison, VectorClock};
use lru::LruCache;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Namespace {
    pub app_id: u64,
    records: LruCache<String, DataRecord>,
    current_size: usize,
    max_size: usize,
    tombstone_retention_ms: u64,
    max_tombstones: usize,
}

impl Namespace {
    pub fn new(
        app_id: u64,
        max_size: usize,
        tombstone_retention_ms: u64,
        max_tombstones: usize,
    ) -> Self {
        Self {
            app_id,
            records: LruCache::unbounded(),
            current_size: 0,
            max_size,
            tombstone_retention_ms,
            max_tombstones,
        }
    }

    pub fn get(&mut self, key: &str, current_time: u64) -> Option<DataRecord> {
        self.cleanup(current_time);
        if let Some(record) = self.records.get(key) {
            if record.tombstone || record.is_expired(current_time) {
                return None;
            }
            return Some(record.clone());
        }
        None
    }

    pub fn keys(&mut self, current_time: u64) -> Vec<String> {
        self.cleanup(current_time);
        self.records
            .iter()
            .filter_map(|(k, v)| {
                if !v.tombstone && !v.is_expired(current_time) {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn put(&mut self, key: &str, record: DataRecord) {
        let size = record.approximate_size();
        if let Some(old) = self.records.put(key.to_string(), record) {
            self.current_size = self.current_size.saturating_sub(old.approximate_size());
        }
        self.current_size += size;
        self.evict_if_needed();
    }

    pub fn delete(&mut self, key: &str, node_id: &str, current_time: u64) -> Option<DataRecord> {
        self.cleanup(current_time);
        let existing = self.records.get(key).cloned()?;
        if existing.tombstone || existing.is_expired(current_time) {
            return None;
        }

        let mut vc = existing.version.clone();
        vc.increment(node_id);
        let tombstone = DataRecord {
            key: key.to_string(),
            encrypted_value: Vec::new(),
            version: vc,
            updated_at_ms: current_time,
            tombstone: true,
            ttl_ms: 0,
        };
        self.put(key, tombstone.clone());
        Some(tombstone)
    }

    pub fn merge_record(&mut self, new_record: DataRecord) -> bool {
        let size = new_record.approximate_size();
        let key = new_record.key.clone();

        if let Some(existing) = self.records.get(&key).cloned() {
            match existing.version.compare(&new_record.version) {
                VCComparison::HappenedBefore => {
                    let old_size = existing.approximate_size();
                    self.records.put(key, new_record);
                    self.current_size = self.current_size + size - old_size;
                    self.evict_if_needed();
                    true
                }
                VCComparison::Concurrent => {
                    if new_record.updated_at_ms > existing.updated_at_ms {
                        let old_size = existing.approximate_size();
                        let mut merged = new_record.clone();
                        merged.version = VectorClock::merge(&existing.version, &new_record.version);
                        self.records.put(key, merged);
                        self.current_size = self.current_size + size - old_size;
                        self.evict_if_needed();
                        true
                    } else if new_record.updated_at_ms == existing.updated_at_ms
                        && new_record.encrypted_value > existing.encrypted_value
                    {
                        let old_size = existing.approximate_size();
                        let mut merged = new_record.clone();
                        merged.version = VectorClock::merge(&existing.version, &new_record.version);
                        self.records.put(key, merged);
                        self.current_size = self.current_size + size - old_size;
                        self.evict_if_needed();
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            }
        } else {
            self.records.put(key, new_record);
            self.current_size += size;
            self.evict_if_needed();
            true
        }
    }

    pub fn get_deltas_since(&mut self, since_ms: u64, current_time: u64) -> Vec<DataRecord> {
        self.cleanup(current_time);
        self.records
            .iter()
            .filter_map(|(_, record)| {
                if record.updated_at_ms > since_ms {
                    Some(record.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn snapshot(&mut self, current_time: u64) -> Vec<DataRecord> {
        self.cleanup(current_time);
        self.records.iter().map(|(_, v)| v.clone()).collect()
    }

    pub fn total_bytes(&self) -> usize {
        self.current_size
    }

    fn cleanup(&mut self, current_time: u64) {
        let mut keys_to_remove = Vec::new();
        for (k, v) in self.records.iter() {
            if v.is_expired(current_time) {
                keys_to_remove.push(k.clone());
                continue;
            }
            if v.tombstone
                && self.tombstone_retention_ms > 0
                && current_time.saturating_sub(v.updated_at_ms) >= self.tombstone_retention_ms
            {
                keys_to_remove.push(k.clone());
            }
        }
        for k in keys_to_remove {
            if let Some(v) = self.records.pop(&k) {
                self.current_size = self.current_size.saturating_sub(v.approximate_size());
            }
        }

        if self.max_tombstones > 0 {
            let mut tombstones: Vec<(String, u64)> = self
                .records
                .iter()
                .filter_map(|(k, v)| {
                    if v.tombstone {
                        Some((k.clone(), v.updated_at_ms))
                    } else {
                        None
                    }
                })
                .collect();
            let overflow = tombstones.len().saturating_sub(self.max_tombstones);
            if overflow > 0 {
                tombstones.sort_by_key(|(k, ts)| (*ts, k.clone()));
                for (k, _) in tombstones.into_iter().take(overflow) {
                    self.records.pop(&k);
                }
            }
        }
    }

    fn evict_if_needed(&mut self) {
        while self.current_size > self.max_size {
            let candidate_key = self
                .records
                .iter()
                .find_map(|(k, v)| if !v.tombstone { Some(k.clone()) } else { None });
            let Some(key) = candidate_key else {
                break;
            };
            if let Some(v) = self.records.pop(&key) {
                self.current_size = self.current_size.saturating_sub(v.approximate_size());
            } else {
                break;
            }
        }
    }
}

pub struct DataStore {
    namespaces: RwLock<HashMap<u64, Arc<RwLock<Namespace>>>>,
    max_app_storage_bytes: usize,
    tombstone_retention_ms: u64,
    max_tombstones_per_app: usize,
}

impl DataStore {
    pub fn new(
        max_app_storage_bytes: usize,
        tombstone_retention_ms: u64,
        max_tombstones_per_app: usize,
    ) -> Self {
        Self {
            namespaces: RwLock::new(HashMap::new()),
            max_app_storage_bytes,
            tombstone_retention_ms,
            max_tombstones_per_app,
        }
    }

    pub async fn get_namespace(&self, app_id: u64) -> Arc<RwLock<Namespace>> {
        let mut map = self.namespaces.write().await;
        let ns = map.entry(app_id).or_insert_with(|| {
            Arc::new(RwLock::new(Namespace::new(
                app_id,
                self.max_app_storage_bytes,
                self.tombstone_retention_ms,
                self.max_tombstones_per_app,
            )))
        });
        ns.clone()
    }

    pub async fn keys(&self, app_id: u64, current_time: u64) -> Vec<String> {
        let ns = self.get_namespace(app_id).await;
        ns.write().await.keys(current_time)
    }

    pub async fn get_deltas_since(
        &self,
        since_ms: u64,
        current_time: u64,
    ) -> HashMap<u64, Vec<DataRecord>> {
        let map = self.namespaces.read().await;
        let namespaces: Vec<(u64, Arc<RwLock<Namespace>>)> =
            map.iter().map(|(k, v)| (*k, v.clone())).collect();
        drop(map);

        let mut out = HashMap::new();
        for (app_id, ns) in namespaces {
            let mut w = ns.write().await;
            let deltas = w.get_deltas_since(since_ms, current_time);
            if !deltas.is_empty() {
                out.insert(app_id, deltas);
            }
        }
        out
    }

    pub async fn full_snapshot(&self, current_time: u64) -> HashMap<u64, Vec<DataRecord>> {
        let map = self.namespaces.read().await;
        let namespaces: Vec<(u64, Arc<RwLock<Namespace>>)> =
            map.iter().map(|(k, v)| (*k, v.clone())).collect();
        drop(map);

        let mut out = HashMap::new();
        for (app_id, ns) in namespaces {
            let mut w = ns.write().await;
            out.insert(app_id, w.snapshot(current_time));
        }
        out
    }

    pub async fn merge_record(&self, app_id: u64, record: DataRecord) -> bool {
        let ns = self.get_namespace(app_id).await;
        ns.write().await.merge_record(record)
    }

    pub async fn stats(&self, current_time: u64) -> (usize, usize, usize) {
        let map = self.namespaces.read().await;
        let namespaces: Vec<Arc<RwLock<Namespace>>> = map.values().cloned().collect();
        drop(map);

        let mut total_keys = 0usize;
        let mut total_bytes = 0usize;
        for ns in namespaces {
            let mut w = ns.write().await;
            total_keys += w.keys(current_time).len();
            total_bytes += w.total_bytes();
        }
        (self.namespaces.read().await.len(), total_keys, total_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(key: &str, value: &[u8], ts: u64, node: &str) -> DataRecord {
        let mut vc = VectorClock::new();
        vc.increment(node);
        DataRecord {
            key: key.to_string(),
            encrypted_value: value.to_vec(),
            version: vc,
            updated_at_ms: ts,
            tombstone: false,
            ttl_ms: 0,
        }
    }

    #[test]
    fn test_delete_missing_returns_none() {
        let mut ns = Namespace::new(1, 1024, 10_000, 100);
        assert!(ns.delete("missing", "n1", 10).is_none());
    }

    #[test]
    fn test_tombstone_not_deleted_immediately() {
        let mut ns = Namespace::new(1, 1024, 10_000, 100);
        ns.put("k", record("k", b"abc", 1, "n1"));
        let tomb = ns.delete("k", "n1", 100).unwrap();
        assert!(tomb.tombstone);
        assert!(ns.records.get("k").unwrap().tombstone);
        ns.cleanup(101);
        assert!(ns.records.get("k").is_some());
    }

    #[test]
    fn test_concurrent_same_timestamp_uses_value_tiebreak() {
        let mut ns = Namespace::new(1, 1024 * 1024, 10_000, 100);
        let mut old = record("k", b"\x01", 100, "n1");
        let mut new = record("k", b"\x02", 100, "n2");
        old.version = VectorClock {
            clocks: [("a".to_string(), 1)].into(),
        };
        new.version = VectorClock {
            clocks: [("b".to_string(), 1)].into(),
        };
        ns.put("k", old.clone());
        assert!(ns.merge_record(new.clone()));
        assert_eq!(ns.records.get("k").unwrap().encrypted_value, vec![0x02]);
    }
}
