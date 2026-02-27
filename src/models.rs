use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

        let all_keys = self.clocks.keys().chain(other.clocks.keys());

        for k in all_keys {
            let v1 = self.get(k);
            let v2 = other.get(k);

            if v1 < v2 {
                self_is_less = true;
            } else if v1 > v2 {
                self_is_greater = true;
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
        let all_keys = v1.clocks.keys().chain(v2.clocks.keys());
        for k in all_keys {
            merged
                .clocks
                .insert(k.clone(), std::cmp::max(v1.get(k), v2.get(k)));
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
    pub ttl_ms: Option<u64>,
}

impl DataRecord {
    pub fn approximate_size(&self) -> usize {
        self.encrypted_value.len() + 128 // overhead estimation
    }

    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        if let Some(ttl) = self.ttl_ms {
            current_time_ms > self.updated_at_ms + ttl
        } else {
            false
        }
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
    fn test_vector_clock_merge() {
        let mut vc1 = VectorClock::new();
        vc1.increment("nodeA");
        vc1.increment("nodeB");

        let mut vc2 = VectorClock::new();
        vc2.increment("nodeA");
        vc2.increment("nodeA");
        vc2.increment("nodeC");

        let merged = VectorClock::merge(&vc1, &vc2);
        assert_eq!(merged.get("nodeA"), 2);
        assert_eq!(merged.get("nodeB"), 1);
        assert_eq!(merged.get("nodeC"), 1);
    }
}
