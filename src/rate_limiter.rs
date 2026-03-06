use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

/// Simple in-memory token bucket rate limiter keyed by caller identity.
///
/// Mirrors the Python implementation used by the legacy KMS node:
/// - capacity = `rate_per_minute`
/// - refill rate = `rate_per_minute / 60` tokens per second
pub struct TokenBucket {
    rate_per_minute: u64,
    max_tokens: f64,
    buckets: RwLock<HashMap<String, BucketState>>,
}

impl TokenBucket {
    pub fn new(rate_per_minute: u64) -> Self {
        Self {
            rate_per_minute,
            max_tokens: rate_per_minute as f64,
            buckets: RwLock::new(HashMap::new()),
        }
    }

    pub async fn allow(&self, key: &str) -> bool {
        if self.rate_per_minute == 0 {
            return true;
        }

        let now = Instant::now();
        let refill_per_second = self.rate_per_minute as f64 / 60.0;
        let key = key.to_string();

        let mut buckets = self.buckets.write().await;
        let entry = buckets.entry(key).or_insert_with(|| BucketState {
            tokens: self.max_tokens,
            last_refill: now,
        });

        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            entry.tokens = (entry.tokens + elapsed * refill_per_second).min(self.max_tokens);
            entry.last_refill = now;
        }

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub async fn cleanup(&self, max_age_seconds: u64) {
        let now = Instant::now();
        let mut buckets = self.buckets.write().await;
        buckets
            .retain(|_, state| now.duration_since(state.last_refill).as_secs() <= max_age_seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::TokenBucket;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_token_bucket_allows_then_limits() {
        let limiter = TokenBucket::new(1);
        assert!(limiter.allow("127.0.0.1").await);
        assert!(!limiter.allow("127.0.0.1").await);
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let limiter = TokenBucket::new(60); // 1 token per second refill
        assert!(limiter.allow("client-a").await);
        assert!(limiter.allow("client-a").await);
        sleep(Duration::from_millis(1200)).await;
        assert!(limiter.allow("client-a").await);
    }
}
