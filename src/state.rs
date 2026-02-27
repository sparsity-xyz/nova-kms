use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};

use crate::auth::{NonceStore, canonical_wallet};
use crate::config::Config;
use crate::crypto::{MasterSecretManager, derive_sync_key};
use crate::error::KmsError;
use crate::odyn::OdynClient;
use crate::rate_limiter::TokenBucket;
use crate::registry::{CachedNovaRegistry, RegistryClient};
use crate::store::DataStore;
use crate::sync::PeerCache;

const STARTUP_ODYN_WALLET_RETRY_ATTEMPTS: usize = 3;
const STARTUP_ODYN_WALLET_RETRY_DELAY_MS: u64 = 1_000;

async fn fetch_odyn_wallet_with_retry(odyn: &OdynClient) -> Result<String, KmsError> {
    let attempts = STARTUP_ODYN_WALLET_RETRY_ATTEMPTS.max(1);
    let mut attempt = 1usize;
    loop {
        match odyn.eth_address().await {
            Ok(wallet) => return Ok(wallet),
            Err(err) => {
                if attempt >= attempts {
                    return Err(err);
                }
                tracing::warn!(
                    "Odyn wallet query failed at startup (attempt {}/{}): {}. Retrying in {}ms",
                    attempt,
                    attempts,
                    err,
                    STARTUP_ODYN_WALLET_RETRY_DELAY_MS
                );
                sleep(Duration::from_millis(STARTUP_ODYN_WALLET_RETRY_DELAY_MS)).await;
                attempt += 1;
            }
        }
    }
}

/// Global application state shared across all route handlers.
pub struct AppState {
    pub config: Config,
    pub store: DataStore,
    pub odyn: OdynClient,
    pub registry: RegistryClient,
    pub app_registry_cache: CachedNovaRegistry,
    pub nonce_store: NonceStore,
    pub nonce_rate_limiter: TokenBucket,
    pub peer_cache: Arc<PeerCache>,
    pub master_secret: MasterSecretManager,
    pub sync_key: Option<[u8; 32]>,
    pub is_operator: bool,
    pub service_available: bool,
    pub service_unavailable_reason: String,
    pub last_push_ms: u64,
    pub startup_time: u64,
}

impl AppState {
    pub async fn new(mut config: Config) -> Self {
        if let Ok(wallet) = canonical_wallet(&config.node_wallet) {
            config.node_wallet = wallet;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let max_app_storage = config.max_app_storage_bytes;
        let tombstone_retention_ms = config.tombstone_retention_ms;
        let max_tombstones_per_app = config.max_tombstones_per_app;
        let nonce_store = NonceStore::new(config.max_nonces, config.pop_timeout_seconds);
        let nonce_rate_limiter = TokenBucket::new(config.nonce_rate_limit_per_minute);
        let odyn = OdynClient::new(config.in_enclave);

        // Keep node wallet bound to the signing identity currently exposed by Odyn.
        // This mirrors the Python startup path and avoids PoP recipient mismatches.
        if config.in_enclave {
            match fetch_odyn_wallet_with_retry(&odyn).await {
                Ok(wallet) => match canonical_wallet(&wallet) {
                    Ok(canonical) => {
                        config.node_wallet = canonical;
                    }
                    Err(err) => {
                        tracing::warn!("Failed to canonicalize Odyn wallet '{}': {}", wallet, err);
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        "Failed to read Odyn wallet at startup; falling back to configured NODE_WALLET: {}",
                        err
                    );
                }
            }
        }

        let registry = RegistryClient::new(
            &config.node_url,
            &config.nova_app_registry_address,
            &config.kms_registry_address,
        )
        .expect("failed to create registry client");
        let app_registry_cache =
            CachedNovaRegistry::new(registry.clone(), config.registry_cache_ttl_seconds);

        let master_secret = MasterSecretManager::new();
        let mut sync_key = None;
        let service_available = false;
        let unavailable_reason = "initializing".to_string();

        let decoded_master_secret = config.master_secret_hex.clone().and_then(|hex_secret| {
            let bytes = hex::decode(hex_secret.trim_start_matches("0x")).ok()?;
            if bytes.len() == 32 { Some(bytes) } else { None }
        });
        if let Some(bytes) = decoded_master_secret {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            master_secret.initialize_generated(arr).await;
            sync_key = Some(derive_sync_key(&crate::crypto::MasterSecret { bytes: arr }));
        }

        Self {
            config,
            store: DataStore::new(
                max_app_storage,
                tombstone_retention_ms,
                max_tombstones_per_app,
            ),
            odyn,
            registry,
            app_registry_cache,
            nonce_store,
            nonce_rate_limiter,
            peer_cache: Arc::new(PeerCache::new()),
            master_secret,
            sync_key,
            is_operator: false,
            service_available,
            service_unavailable_reason: unavailable_reason,
            last_push_ms: 0,
            startup_time: now,
        }
    }
}

pub type SharedState = Arc<RwLock<AppState>>;
