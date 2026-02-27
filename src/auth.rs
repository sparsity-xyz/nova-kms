use alloy::primitives::{Address, Signature};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::KmsError;
use crate::registry::RegistryClient;

#[derive(Debug, Clone)]
pub struct AppIdentity {
    pub app_id: u64,
    pub instance_id: u64,
    pub tee_pubkey: Vec<u8>,
    pub tee_wallet_address: Address,
}

pub struct NonceStore {
    cache: RwLock<LruCache<String, u64>>,
}

impl NonceStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: RwLock::new(LruCache::new(NonZeroUsize::new(capacity).unwrap())),
        }
    }

    pub async fn check_and_store(&self, nonce: &str, current_time: u64, ttl: u64) -> bool {
        let mut cache = self.cache.write().await;

        let mut expired = Vec::new();
        for (k, v) in cache.iter() {
            if current_time > *v + ttl {
                expired.push(k.clone());
            }
        }
        for k in expired {
            cache.pop(&k);
        }

        if cache.contains(nonce) {
            return false;
        }

        cache.put(nonce.to_string(), current_time);
        true
    }
}

pub async fn authenticate_app(
    headers: &axum::http::HeaderMap,
    config: &Config,
    registry: &RegistryClient,
    nonce_store: &NonceStore,
) -> Result<AppIdentity, KmsError> {
    if !config.in_enclave {
        let wallet_str = headers
            .get("x-tee-wallet")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                KmsError::Unauthorized("Missing x-tee-wallet header in dev mode".to_string())
            })?;

        let wallet = Address::from_str(wallet_str)
            .map_err(|_| KmsError::Unauthorized("Invalid x-tee-wallet format".to_string()))?;

        let instance = registry
            .nova_registry
            .getInstanceByWallet(wallet)
            .call()
            .await
            .map_err(|e| KmsError::InternalError(format!("Registry error: {}", e)))?
            ._0;

        // Note: Using try_into for BigInt -> u64
        let uint_app_id = instance.appId.try_into().unwrap_or(0);
        let uint_instance_id = instance.id.try_into().unwrap_or(0);

        if uint_instance_id == 0 {
            return Err(KmsError::Unauthorized(
                "Instance not found in registry".to_string(),
            ));
        }

        return Ok(AppIdentity {
            app_id: uint_app_id,
            instance_id: uint_instance_id,
            tee_pubkey: instance.teePubkey.to_vec(),
            tee_wallet_address: instance.teeWalletAddress,
        });
    }

    let nonce = headers
        .get("t-nonce")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized("Missing t-nonce".to_string()))?;
    let timestamp_str = headers
        .get("t-timestamp")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized("Missing t-timestamp".to_string()))?;
    let signature_str = headers
        .get("t-signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized("Missing t-signature".to_string()))?;
    let requester_url = headers
        .get("t-requester-url")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized("Missing t-requester-url".to_string()))?;

    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| KmsError::Unauthorized("Invalid timestamp format".to_string()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now > timestamp + config.pop_timeout_seconds || timestamp > now + 30 {
        return Err(KmsError::Unauthorized(
            "Timestamp expired or too far in future".to_string(),
        ));
    }

    if !nonce_store
        .check_and_store(nonce, now, config.pop_timeout_seconds)
        .await
    {
        return Err(KmsError::Unauthorized("Nonce reused".to_string()));
    }

    let payload = format!("nova-kms-auth:{}:{}:{}", nonce, timestamp, requester_url);

    let signature = Signature::from_str(signature_str)
        .map_err(|_| KmsError::Unauthorized("Invalid signature format".to_string()))?;

    let recovered_address = signature
        .recover_address_from_msg(payload.as_bytes())
        .map_err(|_| {
            KmsError::Unauthorized("Failed to recover address from signature".to_string())
        })?;

    let instance = registry
        .nova_registry
        .getInstanceByWallet(recovered_address)
        .call()
        .await
        .map_err(|e| KmsError::InternalError(format!("Registry error: {}", e)))?
        ._0;

    let uint_instance_id = instance.id.try_into().unwrap_or(0);
    let uint_app_id = instance.appId.try_into().unwrap_or(0);

    if uint_instance_id == 0 {
        return Err(KmsError::Unauthorized(
            "Instance not found in registry".to_string(),
        ));
    }

    if instance.status != 0 {
        return Err(KmsError::Unauthorized("Instance is not ACTIVE".to_string()));
    }

    let app = registry
        .nova_registry
        .getApp(instance.appId)
        .call()
        .await
        .map_err(|e| KmsError::InternalError(format!("Registry error: {}", e)))?
        ._0;

    if app.status != 0 {
        return Err(KmsError::Unauthorized("App is not ACTIVE".to_string()));
    }

    Ok(AppIdentity {
        app_id: uint_app_id,
        instance_id: uint_instance_id,
        tee_pubkey: instance.teePubkey.to_vec(),
        tee_wallet_address: instance.teeWalletAddress,
    })
}
