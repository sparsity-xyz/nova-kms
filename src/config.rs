use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub in_enclave: bool,
    pub log_level: String,
    pub bind_addr: String,

    // Contract Addresses
    pub nova_app_registry_address: String,
    pub kms_registry_address: String,

    // Network & Sync
    pub kms_app_id: u64,
    pub node_url: String, // RPC for chain calls
    pub node_instance_url: String,
    pub node_wallet: String,
    pub node_private_key: Option<String>,
    #[serde(alias = "PEER_REFRESH_INTERVAL_SECONDS")]
    pub kms_node_tick_seconds: u64,
    #[serde(alias = "SYNC_INTERVAL_SECONDS")]
    pub data_sync_interval_seconds: u64,
    pub peer_cache_ttl_seconds: u64,
    pub registry_cache_ttl_seconds: u64,
    pub peer_blacklist_duration_seconds: u64,

    // Storage Engine Limits
    pub max_app_storage_bytes: usize,
    pub max_kv_value_size_bytes: usize,
    pub tombstone_retention_ms: u64,
    pub max_tombstones_per_app: usize,

    // Security & Auth
    pub pop_timeout_seconds: u64,
    pub max_nonces: usize,
    pub max_request_body_bytes: usize,
    pub max_sync_payload_bytes: usize,
    pub max_clock_skew_ms: u64,
    pub allow_plaintext_dev: bool,
    pub master_secret_hex: Option<String>,

    // Rate Limiting
    pub rate_limit_per_minute: u64,
    pub nonce_rate_limit_per_minute: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            in_enclave: true,
            log_level: "INFO".to_string(),
            bind_addr: "0.0.0.0:8000".to_string(),
            nova_app_registry_address: "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8".to_string(),
            kms_registry_address: "0x6a28D24c9AEcdceC9B021ee6960FdDE592796af7".to_string(),
            kms_app_id: 49,
            node_url: "http://127.0.0.1:18545".to_string(),
            node_instance_url: "".to_string(),
            node_wallet: "0x0A00000000000000000000000000000000000000".to_string(),
            node_private_key: None,
            kms_node_tick_seconds: 60,
            data_sync_interval_seconds: 10,
            peer_cache_ttl_seconds: 180,
            registry_cache_ttl_seconds: 180,
            peer_blacklist_duration_seconds: 600,
            max_app_storage_bytes: 10 * 1024 * 1024, // 10MB
            max_kv_value_size_bytes: 1024 * 1024,    // 1MB
            tombstone_retention_ms: 24 * 60 * 60 * 1000,
            max_tombstones_per_app: 10_000,
            pop_timeout_seconds: 120,
            max_nonces: 4096,
            max_request_body_bytes: 2 * 1024 * 1024,
            max_sync_payload_bytes: 50 * 1024 * 1024,
            max_clock_skew_ms: 5_000,
            allow_plaintext_dev: false,
            master_secret_hex: None,
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

    pub fn allow_plaintext_fallback(&self) -> bool {
        !self.in_enclave && self.allow_plaintext_dev
    }
}
