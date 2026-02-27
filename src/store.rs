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
}

impl Namespace {
    pub fn new(app_id: u64, max_size: usize) -> Self {
        Self {
            app_id,
            records: LruCache::unbounded(),
            current_size: 0,
            max_size,
        }
    }

    pub fn get(&mut self, key: &str, current_time: u64) -> Option<DataRecord> {
        self.evict_if_needed();
        self.cleanup_tombstones(current_time);

        if let Some(record) = self.records.get(key) {
            if record.is_expired(current_time) {
                // Return None but don't delete immediately - let cleanup handle it
                return None;
            }
            return Some(record.clone());
        }
        None
    }

    pub fn put(&mut self, key: &str, record: DataRecord) {
        let size = record.approximate_size();
        if let Some(old) = self.records.put(key.to_string(), record) {
            self.current_size -= old.approximate_size();
        }
        self.current_size += size;
        self.evict_if_needed();
    }

    pub fn delete(&mut self, key: &str, node_id: &str, current_time: u64) {
        self.evict_if_needed();

        let mut vc = VectorClock::new();
        if let Some(ext) = self.records.get(key) {
            vc = ext.version.clone();
        }
        vc.increment(node_id);

        let record = DataRecord {
            key: key.to_string(),
            encrypted_value: Vec::new(),
            version: vc,
            updated_at_ms: current_time,
            tombstone: true,
            ttl_ms: None, // Tombstones persist indefinitely unless garbage collected
        };

        self.put(key, record);
    }

    pub fn merge_record(&mut self, new_record: DataRecord) -> bool {
        let size = new_record.approximate_size();
        let key = new_record.key.clone();

        if let Some(existing) = self.records.get(&key) {
            let cmp = existing.version.compare(&new_record.version);
            match cmp {
                VCComparison::HappenedBefore => {
                    // new replaces existing
                    let old_size = existing.approximate_size();
                    self.records.put(key, new_record);
                    self.current_size = self.current_size + size - old_size;
                    self.evict_if_needed();
                    true
                }
                VCComparison::Concurrent => {
                    // LWW tie-breaker using updated_at_ms
                    if new_record.updated_at_ms > existing.updated_at_ms {
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
                _ => false, // existing is newer or equal
            }
        } else {
            self.records.put(key, new_record);
            self.current_size += size;
            self.evict_if_needed();
            true
        }
    }

    pub fn promote(&mut self, key: &str) {
        self.records.promote(key);
    }

    fn evict_if_needed(&mut self) {
        while self.current_size > self.max_size && !self.records.is_empty() {
            if let Some((_, rec)) = self.records.pop_lru() {
                self.current_size -= rec.approximate_size();
            }
        }
    }

    pub fn get_snapshot(&self) -> Vec<DataRecord> {
        self.records.iter().map(|(_, v)| v.clone()).collect()
    }

    pub fn cleanup_tombstones(&mut self, cutoff_time: u64) {
        let mut keys_to_remove = Vec::new();
        for (k, v) in self.records.iter() {
            if (v.tombstone && v.updated_at_ms < cutoff_time) || v.is_expired(cutoff_time) {
                keys_to_remove.push(k.clone());
            }
        }
        for k in keys_to_remove {
            if let Some(v) = self.records.pop(&k) {
                self.current_size -= v.approximate_size();
            }
        }
    }
}

pub struct DataStore {
    namespaces: RwLock<HashMap<u64, Arc<RwLock<Namespace>>>>,
    max_app_storage_bytes: usize,
}

impl DataStore {
    pub fn new(max_app_storage_bytes: usize) -> Self {
        Self {
            namespaces: RwLock::new(HashMap::new()),
            max_app_storage_bytes,
        }
    }

    pub async fn get_namespace(&self, app_id: u64) -> Arc<RwLock<Namespace>> {
        let mut map = self.namespaces.write().await;
        let ns = map.entry(app_id).or_insert_with(|| {
            Arc::new(RwLock::new(Namespace::new(
                app_id,
                self.max_app_storage_bytes,
            )))
        });
        ns.clone()
    }
}
