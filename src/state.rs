use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::NonceStore;
use crate::config::Config;
use crate::crypto::MasterSecretManager;
use crate::odyn::OdynClient;
use crate::registry::RegistryClient;
use crate::store::DataStore;

/// Global application state shared across all route handlers
pub struct AppState {
    pub config: Config,
    pub store: DataStore,
    pub odyn: OdynClient,
    pub registry: RegistryClient,
    pub nonce_store: NonceStore,
    pub master_secret: MasterSecretManager,
    pub startup_time: u64,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let max_app_storage = config.max_app_storage_bytes;
        let nonce_store = NonceStore::new(10000);
        let odyn = OdynClient::new(config.in_enclave);
        let registry = RegistryClient::new(
            &config.node_url,
            &config.nova_app_registry_address,
            &config.kms_registry_address,
        )
        .unwrap();

        Self {
            config,
            store: DataStore::new(max_app_storage),
            odyn,
            registry,
            nonce_store,
            master_secret: MasterSecretManager::new(),
            startup_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

pub type SharedState = Arc<RwLock<AppState>>;
