use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub in_enclave: bool,
    pub log_level: String,

    // Contract Addresses
    pub nova_app_registry_address: String,
    pub kms_registry_address: String,

    // Network & Sync
    pub kms_app_id: u64,
    pub node_url: String, // RPC for Web3
    pub node_wallet: String,
    pub sync_interval_seconds: u64,
    pub peer_refresh_interval_seconds: u64,

    // Storage Engine Limits
    pub max_app_storage_bytes: usize,
    pub max_kv_value_size_bytes: usize,

    // Security & Auth
    pub pop_timeout_seconds: u64,

    // Rate Limiting
    pub rate_limit_per_minute: u64,
    pub nonce_rate_limit_per_minute: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            in_enclave: false,
            log_level: "INFO".to_string(),
            nova_app_registry_address: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8".to_string(),
            kms_registry_address: "0x6a28D24c9AEcdceC9B021ee6960FdDE592796af7".to_string(),
            kms_app_id: 49,
            node_url: "http://127.0.0.1:18545".to_string(),
            node_wallet: "0x0A00000000000000000000000000000000000000".to_string(),
            sync_interval_seconds: 5,
            peer_refresh_interval_seconds: 60,
            max_app_storage_bytes: 10 * 1024 * 1024, // 10MB
            max_kv_value_size_bytes: 1024 * 1024,    // 1MB
            pop_timeout_seconds: 300,                // 5 mins
            rate_limit_per_minute: 120,
            nonce_rate_limit_per_minute: 30,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, Box<figment::Error>> {
        Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file("NovaKms.toml"))
            .merge(Env::raw())
            .extract()
            .map_err(Box::new)
    }
}
