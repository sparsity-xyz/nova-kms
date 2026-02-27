use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct VectorClock {
    pub clocks: BTreeMap<String, u64>,
}

#[derive(Debug, PartialEq)]
pub enum VCComparison {
    Equal,
    HappenedBefore,
    HappenedAfter,
    Concurrent,
}

impl VectorClock {
    pub fn new() -> Self {
        Self {
            clocks: BTreeMap::new(),
        }
    }

    pub fn increment(&mut self, node_id: &str) {
        *self.clocks.entry(node_id.to_string()).or_insert(0) += 1;
    }

    pub fn get(&self, node_id: &str) -> u64 {
        *self.clocks.get(node_id).unwrap_or(&0)
    }

    pub fn compare(&self, other: &VectorClock) -> VCComparison {
        let mut self_is_less = false;
        let mut self_is_greater = false;

        let all_keys: BTreeSet<String> = self
            .clocks
            .keys()
            .cloned()
            .chain(other.clocks.keys().cloned())
            .collect();

        for k in all_keys {
            let v1 = self.get(&k);
            let v2 = other.get(&k);

            match v1.cmp(&v2) {
                std::cmp::Ordering::Less => self_is_less = true,
                std::cmp::Ordering::Greater => self_is_greater = true,
                std::cmp::Ordering::Equal => {}
            }
        }

        if !self_is_less && !self_is_greater {
            VCComparison::Equal
        } else if self_is_less && !self_is_greater {
            VCComparison::HappenedBefore
        } else if !self_is_less && self_is_greater {
            VCComparison::HappenedAfter
        } else {
            VCComparison::Concurrent
        }
    }

    pub fn merge(v1: &VectorClock, v2: &VectorClock) -> VectorClock {
        let mut merged = VectorClock::new();
        let all_keys: BTreeSet<String> = v1
            .clocks
            .keys()
            .cloned()
            .chain(v2.clocks.keys().cloned())
            .collect();
        for k in all_keys {
            merged
                .clocks
                .insert(k.clone(), std::cmp::max(v1.get(&k), v2.get(&k)));
        }
        merged
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRecord {
    pub key: String,
    pub encrypted_value: Vec<u8>,
    pub version: VectorClock,
    pub updated_at_ms: u64,
    pub tombstone: bool,
    pub ttl_ms: u64, // 0 = no expiry
}

impl DataRecord {
    pub fn approximate_size(&self) -> usize {
        if self.tombstone {
            0
        } else {
            self.encrypted_value.len()
        }
    }

    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        self.ttl_ms > 0 && current_time_ms > self.updated_at_ms + self.ttl_ms
    }

    pub fn to_sync_value(&self) -> Value {
        json!({
            "key": self.key,
            "value": if self.tombstone { Value::Null } else { Value::String(hex::encode(&self.encrypted_value)) },
            "version": self.version.clocks,
            "updated_at_ms": self.updated_at_ms,
            "tombstone": self.tombstone,
            "ttl_ms": self.ttl_ms,
        })
    }

    pub fn from_sync_value(v: &Value) -> Option<Self> {
        let obj = v.as_object()?;
        Self::from_sync_map(obj)
    }

    pub fn from_sync_map(obj: &Map<String, Value>) -> Option<Self> {
        let key = obj.get("key")?.as_str()?.to_string();
        let tombstone = obj
            .get("tombstone")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let encrypted_value = if tombstone {
            Vec::new()
        } else {
            let hex_val = obj.get("value")?.as_str()?;
            hex::decode(hex_val.strip_prefix("0x").unwrap_or(hex_val)).ok()?
        };

        let mut version = VectorClock::new();
        if let Some(ver_obj) = obj.get("version").and_then(|v| v.as_object()) {
            for (k, v) in ver_obj {
                if let Some(count) = v.as_u64() {
                    version.clocks.insert(k.clone(), count);
                }
            }
        }

        Some(Self {
            key,
            encrypted_value,
            version,
            updated_at_ms: obj
                .get("updated_at_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            tombstone,
            ttl_ms: obj.get("ttl_ms").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_clock_increment() {
        let mut vc = VectorClock::new();
        vc.increment("nodeA");
        assert_eq!(vc.get("nodeA"), 1);
        vc.increment("nodeA");
        assert_eq!(vc.get("nodeA"), 2);
        assert_eq!(vc.get("nodeB"), 0);
    }

    #[test]
    fn test_vector_clock_compare() {
        let mut vc1 = VectorClock::new();
        vc1.increment("nodeA");

        let mut vc2 = VectorClock::new();
        vc2.increment("nodeA");
        vc2.increment("nodeA");

        assert_eq!(vc1.compare(&vc2), VCComparison::HappenedBefore);
        assert_eq!(vc2.compare(&vc1), VCComparison::HappenedAfter);

        let mut vc3 = VectorClock::new();
        vc3.increment("nodeB");
        assert_eq!(vc1.compare(&vc3), VCComparison::Concurrent);
    }

    #[test]
    fn test_sync_record_roundtrip() {
        let mut vc = VectorClock::new();
        vc.increment("n1");
        let rec = DataRecord {
            key: "k".to_string(),
            encrypted_value: vec![1, 2, 3],
            version: vc,
            updated_at_ms: 10,
            tombstone: false,
            ttl_ms: 0,
        };
        let val = rec.to_sync_value();
        let parsed = DataRecord::from_sync_value(&val).unwrap();
        assert_eq!(parsed.key, "k");
        assert_eq!(parsed.encrypted_value, vec![1, 2, 3]);
    }
}
