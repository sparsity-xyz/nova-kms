use alloy::primitives::{Address, Signature};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use base64::Engine as _;
use lru::LruCache;
use ring::rand::{SecureRandom, SystemRandom};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::KmsError;
use crate::odyn::OdynClient;
use crate::registry::CachedNovaRegistry;

#[derive(Debug, Clone)]
pub struct AppIdentity {
    pub app_id: u64,
    pub version_id: u64,
    pub instance_id: u64,
    pub tee_pubkey: Vec<u8>,
    pub tee_wallet: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KmsPeerIdentity {
    pub tee_wallet: String,
    pub signature: String,
}

pub struct NonceStore {
    issued: RwLock<LruCache<String, u64>>,
    ttl_seconds: u64,
}

impl NonceStore {
    pub fn new(capacity: usize, ttl_seconds: u64) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            issued: RwLock::new(LruCache::new(cap)),
            ttl_seconds,
        }
    }

    pub async fn issue_nonce(&self) -> Result<String, KmsError> {
        let mut nonce_bytes = [0u8; 16];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| KmsError::InternalError("Failed to generate nonce".to_string()))?;
        let nonce = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
        let now = now_secs();
        let mut cache = self.issued.write().await;
        Self::cleanup_expired_locked(&mut cache, now);
        cache.put(nonce.clone(), now + self.ttl_seconds);
        Ok(nonce)
    }

    pub async fn validate_and_consume(&self, nonce: &str) -> bool {
        let now = now_secs();
        let mut cache = self.issued.write().await;
        Self::cleanup_expired_locked(&mut cache, now);
        match cache.pop(nonce) {
            Some(expiry) => expiry >= now,
            None => false,
        }
    }

    fn cleanup_expired_locked(cache: &mut LruCache<String, u64>, now: u64) {
        let expired: Vec<String> = cache
            .iter()
            .filter_map(|(nonce, expiry)| {
                if *expiry < now {
                    Some(nonce.clone())
                } else {
                    None
                }
            })
            .collect();
        for nonce in expired {
            cache.pop(&nonce);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn canonical_wallet(wallet: &str) -> Result<String, KmsError> {
    let trimmed = wallet.trim();
    let addr = Address::from_str(trimmed)
        .map_err(|_| KmsError::Unauthorized("Invalid wallet address".to_string()))?;
    Ok(format!("0x{}", hex::encode(addr.as_slice())))
}

fn parse_u64_header(headers: &axum::http::HeaderMap, key: &str) -> Result<u64, KmsError> {
    let v = headers
        .get(key)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized(format!("Missing {}", key)))?;
    v.parse::<u64>()
        .map_err(|_| KmsError::Unauthorized(format!("Invalid {}", key)))
}

fn require_fresh_timestamp(timestamp: u64, max_age_seconds: u64) -> Result<(), KmsError> {
    let now = now_secs();
    let diff = now.abs_diff(timestamp);
    if diff > max_age_seconds {
        return Err(KmsError::Unauthorized("Stale timestamp".to_string()));
    }
    Ok(())
}

pub fn recover_wallet_from_signature(message: &str, signature: &str) -> Result<String, KmsError> {
    let sig = Signature::from_str(signature)
        .map_err(|_| KmsError::Unauthorized("Invalid signature format".to_string()))?;
    let recovered = sig
        .recover_address_from_msg(message.as_bytes())
        .map_err(|_| KmsError::Unauthorized("Invalid signature".to_string()))?;
    Ok(format!("0x{}", hex::encode(recovered.as_slice())))
}

pub fn verify_wallet_signature(wallet: &str, message: &str, signature: &str) -> bool {
    match (
        canonical_wallet(wallet),
        recover_wallet_from_signature(message, signature),
    ) {
        (Ok(expected), Ok(recovered)) => expected == recovered,
        _ => false,
    }
}

async fn lookup_and_authorize_instance(
    registry: &CachedNovaRegistry,
    wallet: &str,
) -> Result<(u64, u64, u64, Vec<u8>, String), KmsError> {
    let instance = registry.get_instance_by_wallet(wallet).await?;

    let instance_id = instance.instance_id;
    let app_id = instance.app_id;
    let version_id = instance.version_id;
    if instance_id == 0 {
        return Err(KmsError::Unauthorized("Instance not found".to_string()));
    }
    if instance.status != 0 {
        return Err(KmsError::Unauthorized("Instance not active".to_string()));
    }
    if !instance.zk_verified {
        return Err(KmsError::Unauthorized(
            "Instance not zkVerified".to_string(),
        ));
    }

    let app = registry.get_app(app_id).await?;
    if app.status != 0 {
        return Err(KmsError::Unauthorized("App not active".to_string()));
    }

    let version = registry.get_version(app_id, version_id).await?;
    // ENROLLED=0, DEPRECATED=1, REVOKED=2
    if version.status == 2 {
        return Err(KmsError::Unauthorized("Version revoked".to_string()));
    }
    if version.status != 0 && version.status != 1 {
        return Err(KmsError::Unauthorized(
            "Version not enrolled or deprecated".to_string(),
        ));
    }

    Ok((
        app_id,
        version_id,
        instance_id,
        instance.tee_pubkey,
        instance.tee_wallet_address,
    ))
}

pub async fn authenticate_app(
    headers: &axum::http::HeaderMap,
    config: &Config,
    registry: &CachedNovaRegistry,
    nonce_store: &NonceStore,
) -> Result<AppIdentity, KmsError> {
    let app_sig = headers
        .get("x-app-signature")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let app_nonce = headers
        .get("x-app-nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let app_ts = headers
        .get("x-app-timestamp")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if let (Some(signature), Some(nonce), Some(ts_str)) = (app_sig, app_nonce, app_ts) {
        let ts = ts_str
            .parse::<u64>()
            .map_err(|_| KmsError::Unauthorized("Invalid x-app-timestamp".to_string()))?;
        require_fresh_timestamp(ts, config.pop_timeout_seconds)?;

        if !nonce_store.validate_and_consume(&nonce).await {
            return Err(KmsError::Unauthorized(
                "Invalid or expired nonce".to_string(),
            ));
        }

        let recipient_wallet = canonical_wallet(&config.node_wallet)?;
        let message = format!("NovaKMS:AppAuth:{}:{}:{}", nonce, recipient_wallet, ts);
        let recovered_wallet = recover_wallet_from_signature(&message, &signature)?;

        if let Some(wallet_header) = headers.get("x-app-wallet").and_then(|v| v.to_str().ok()) {
            let hinted = canonical_wallet(wallet_header)?;
            if hinted != recovered_wallet {
                return Err(KmsError::Unauthorized(
                    "App wallet header does not match signature".to_string(),
                ));
            }
        }

        let (app_id, version_id, instance_id, tee_pubkey, tee_wallet) =
            lookup_and_authorize_instance(registry, &recovered_wallet).await?;

        return Ok(AppIdentity {
            app_id,
            version_id,
            instance_id,
            tee_pubkey,
            tee_wallet,
            signature: Some(signature),
        });
    }

    if config.in_enclave {
        return Err(KmsError::Unauthorized(
            "Missing PoP authentication headers".to_string(),
        ));
    }

    // Dev fallback: x-tee-wallet header.
    let wallet = headers
        .get("x-tee-wallet")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized("Missing x-tee-wallet header".to_string()))?;
    let wallet = canonical_wallet(wallet)?;
    let (app_id, version_id, instance_id, tee_pubkey, tee_wallet) =
        lookup_and_authorize_instance(registry, &wallet).await?;
    Ok(AppIdentity {
        app_id,
        version_id,
        instance_id,
        tee_pubkey,
        tee_wallet,
        signature: None,
    })
}

pub async fn authenticate_kms_peer(
    headers: &axum::http::HeaderMap,
    config: &Config,
    nonce_store: &NonceStore,
    recipient_wallet: &str,
) -> Result<KmsPeerIdentity, KmsError> {
    let signature = headers
        .get("x-kms-signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized("Missing x-kms-signature".to_string()))?;
    let timestamp = parse_u64_header(headers, "x-kms-timestamp")?;
    let nonce = headers
        .get("x-kms-nonce")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized("Missing x-kms-nonce".to_string()))?;
    let wallet_header = headers
        .get("x-kms-wallet")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string);

    require_fresh_timestamp(timestamp, config.pop_timeout_seconds)?;
    if !nonce_store.validate_and_consume(nonce).await {
        return Err(KmsError::Unauthorized(
            "Invalid or expired nonce".to_string(),
        ));
    }

    let recipient = canonical_wallet(recipient_wallet)?;
    let msg = format!("NovaKMS:Auth:{}:{}:{}", nonce, recipient, timestamp);
    let recovered_wallet = recover_wallet_from_signature(&msg, signature)?;

    if let Some(header_wallet) = wallet_header {
        let hinted = canonical_wallet(&header_wallet)?;
        if hinted != recovered_wallet {
            return Err(KmsError::Unauthorized(
                "KMS wallet header does not match signature".to_string(),
            ));
        }
    }

    Ok(KmsPeerIdentity {
        tee_wallet: recovered_wallet,
        signature: signature.to_string(),
    })
}

pub async fn sign_message_for_node(
    config: &Config,
    odyn: &OdynClient,
    message: &str,
) -> Result<(String, String), KmsError> {
    if config.in_enclave {
        let signed = odyn.sign_message(message, false).await?;
        return Ok((signed.signature, canonical_wallet(&signed.address)?));
    }

    let signer = dev_private_key_signer(config)?;
    let sig = signer
        .sign_message(message.as_bytes())
        .await
        .map_err(|_| KmsError::InternalError("Failed to sign message".to_string()))?;
    let wallet = format!("0x{}", hex::encode(signer.address().as_slice()));
    Ok((format!("0x{}", hex::encode(sig.as_bytes())), wallet))
}

pub async fn current_node_signing_wallet(
    config: &Config,
    odyn: &OdynClient,
) -> Result<String, KmsError> {
    if config.in_enclave {
        return canonical_wallet(&odyn.eth_address().await?);
    }
    let signer = dev_private_key_signer(config)?;
    Ok(format!("0x{}", hex::encode(signer.address().as_slice())))
}

fn dev_private_key_signer(config: &Config) -> Result<PrivateKeySigner, KmsError> {
    let pk = config.node_private_key.clone().ok_or_else(|| {
        KmsError::ServiceUnavailable(
            "NODE_PRIVATE_KEY is required for dev message signing".to_string(),
        )
    })?;
    PrivateKeySigner::from_str(pk.trim_start_matches("0x"))
        .map_err(|_| KmsError::ServiceUnavailable("Invalid NODE_PRIVATE_KEY".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;

    #[tokio::test]
    async fn test_nonce_issue_and_consume() {
        let store = NonceStore::new(128, 120);
        let nonce = store.issue_nonce().await.unwrap();
        assert!(store.validate_and_consume(&nonce).await);
        assert!(!store.validate_and_consume(&nonce).await);
    }

    #[test]
    fn test_canonical_wallet_format() {
        let w = canonical_wallet("0xA000000000000000000000000000000000000000").unwrap();
        assert_eq!(w, "0xa000000000000000000000000000000000000000");
    }

    #[tokio::test]
    async fn test_verify_wallet_signature_roundtrip() {
        let signer = PrivateKeySigner::from_str(
            "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f90c23f2d25f4f53f8",
        )
        .unwrap();
        let wallet = format!("0x{}", hex::encode(signer.address().as_slice()));
        let message = "NovaKMS:Auth:test:0x1111111111111111111111111111111111111111:1";
        let sig = signer.sign_message(message.as_bytes()).await.unwrap();
        let sig_hex = format!("0x{}", hex::encode(sig.as_bytes()));
        assert!(verify_wallet_signature(&wallet, message, &sig_hex));
        assert!(!verify_wallet_signature(
            "0x0000000000000000000000000000000000000000",
            message,
            &sig_hex
        ));
    }
}
