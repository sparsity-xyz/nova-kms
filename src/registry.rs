use alloy::primitives::{Address, U256, keccak256};
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy::sol;
use alloy::transports::http::{Client, Http};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::future::IntoFuture;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::{Duration, timeout};

use crate::error::KmsError;
use crate::odyn::OdynClient;

sol! {
    #[sol(rpc)]
    contract INovaAppRegistry {
        struct App {
            uint256 id;
            address owner;
            bytes32 teeArch;
            address dappContract;
            string metadataUri;
            uint256 latestVersionId;
            uint256 createdAt;
            uint8 status;
            address appWallet;
        }

        struct AppVersion {
            uint256 id;
            string versionName;
            bytes32 codeMeasurement;
            string imageUri;
            string auditUrl;
            string auditHash;
            string githubRunId;
            uint8 status;
            uint256 enrolledAt;
            address enrolledBy;
        }

        struct RuntimeInstance {
            uint256 id;
            uint256 appId;
            uint256 versionId;
            address operator;
            string instanceUrl;
            bytes teePubkey;
            address teeWalletAddress;
            bool zkVerified;
            uint8 status;
            uint256 registeredAt;
        }

        function getApp(uint256 appId) external view returns (App memory);
        function getVersion(uint256 appId, uint256 versionId) external view returns (AppVersion memory);
        function getInstanceByWallet(address wallet) external view returns (RuntimeInstance memory);
        function getActiveInstances(uint256 appId) external view returns (address[] memory);
    }

    #[sol(rpc)]
    contract IKMSRegistry {
        function getOperators() external view returns (address[] memory);
        function isOperator(address account) external view returns (bool);
        function masterSecretHash() external view returns (bytes32);
        function setMasterSecretHash(bytes32 newHash) external;
    }
}

#[derive(Debug, Clone)]
pub struct AppInfo {
    pub app_id: u64,
    pub status: u8,
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub version_id: u64,
    pub status: u8,
}

#[derive(Debug, Clone)]
pub struct RuntimeInstanceInfo {
    pub instance_id: u64,
    pub app_id: u64,
    pub version_id: u64,
    pub operator: String,
    pub instance_url: String,
    pub tee_pubkey: Vec<u8>,
    pub tee_wallet_address: String,
    pub zk_verified: bool,
    pub status: u8,
    pub registered_at: u64,
}

#[derive(Clone)]
pub struct RegistryClient {
    pub nova_registry:
        INovaAppRegistry::INovaAppRegistryInstance<Http<Client>, RootProvider<Http<Client>>>,
    pub kms_registry: IKMSRegistry::IKMSRegistryInstance<Http<Client>, RootProvider<Http<Client>>>,
    rpc_url: String,
    kms_registry_address: String,
    http: reqwest::Client,
}

const LOCAL_RPC_TIMEOUT: Duration = Duration::from_secs(5);

async fn with_timeout<T, I, E>(op: &str, fut: I) -> Result<T, KmsError>
where
    I: IntoFuture<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    match timeout(LOCAL_RPC_TIMEOUT, fut.into_future()).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(KmsError::InternalError(format!("{} error: {}", op, e))),
        Err(_) => Err(KmsError::InternalError(format!(
            "{} timed out after {}s",
            op,
            LOCAL_RPC_TIMEOUT.as_secs()
        ))),
    }
}

impl RegistryClient {
    pub fn new(
        rpc_url: &str,
        nova_address: &str,
        kms_address: &str,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let url = reqwest::Url::parse(rpc_url)?;
        let provider = ProviderBuilder::new().on_http(url);

        let nova_addr = Address::from_str(nova_address)?;
        let kms_addr = Address::from_str(kms_address)?;

        let nova_registry = INovaAppRegistry::new(nova_addr, provider.clone());
        let kms_registry = IKMSRegistry::new(kms_addr, provider);

        Ok(Self {
            nova_registry,
            kms_registry,
            rpc_url: rpc_url.to_string(),
            kms_registry_address: format!("0x{}", hex::encode(kms_addr.as_slice())),
            http: reqwest::Client::builder()
                .timeout(LOCAL_RPC_TIMEOUT)
                .build()?,
        })
    }

    pub async fn get_active_instances(&self, app_id: u64) -> Result<Vec<String>, KmsError> {
        let wallets = with_timeout(
            "Registry getActiveInstances",
            self.nova_registry
                .getActiveInstances(U256::from(app_id))
                .call(),
        )
        .await?
        ._0;
        Ok(wallets
            .iter()
            .map(|w| format!("0x{}", hex::encode(w.as_slice())))
            .collect())
    }

    pub async fn get_instance_by_wallet(
        &self,
        wallet: &str,
    ) -> Result<RuntimeInstanceInfo, KmsError> {
        let addr = Address::from_str(wallet)
            .map_err(|_| KmsError::Unauthorized("Invalid wallet address".to_string()))?;
        let instance = with_timeout(
            "Registry getInstanceByWallet",
            self.nova_registry.getInstanceByWallet(addr).call(),
        )
        .await?
        ._0;

        Ok(RuntimeInstanceInfo {
            instance_id: instance.id.try_into().unwrap_or(0),
            app_id: instance.appId.try_into().unwrap_or(0),
            version_id: instance.versionId.try_into().unwrap_or(0),
            operator: format!("0x{}", hex::encode(instance.operator.as_slice())),
            instance_url: instance.instanceUrl,
            tee_pubkey: instance.teePubkey.to_vec(),
            tee_wallet_address: format!("0x{}", hex::encode(instance.teeWalletAddress.as_slice())),
            zk_verified: instance.zkVerified,
            status: instance.status,
            registered_at: instance.registeredAt.try_into().unwrap_or(0),
        })
    }

    pub async fn get_app(&self, app_id: u64) -> Result<AppInfo, KmsError> {
        let app = with_timeout(
            "Registry getApp",
            self.nova_registry.getApp(U256::from(app_id)).call(),
        )
        .await?
        ._0;
        Ok(AppInfo {
            app_id: app.id.try_into().unwrap_or(0),
            status: app.status,
        })
    }

    pub async fn get_version(&self, app_id: u64, version_id: u64) -> Result<VersionInfo, KmsError> {
        let version = with_timeout(
            "Registry getVersion",
            self.nova_registry
                .getVersion(U256::from(app_id), U256::from(version_id))
                .call(),
        )
        .await?
        ._0;
        Ok(VersionInfo {
            version_id: version.id.try_into().unwrap_or(0),
            status: version.status,
        })
    }

    pub async fn get_master_secret_hash(&self) -> Result<[u8; 32], KmsError> {
        let hash = with_timeout(
            "Registry masterSecretHash",
            self.kms_registry.masterSecretHash().call(),
        )
        .await?
        ._0;
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_slice());
        Ok(out)
    }

    pub async fn set_master_secret_hash(
        &self,
        odyn: &OdynClient,
        setter_wallet: &str,
        secret_hash: [u8; 32],
    ) -> Result<String, KmsError> {
        let setter = Address::from_str(setter_wallet)
            .map_err(|_| KmsError::ValidationError("Invalid setter wallet".to_string()))?;
        let setter_wallet = format!("0x{}", hex::encode(setter.as_slice()));

        let chain_id = parse_u256_hex(
            self.rpc_call("eth_chainId", json!([]))
                .await?
                .as_str()
                .ok_or_else(|| {
                    KmsError::InternalError("Invalid eth_chainId response".to_string())
                })?,
        )?;
        let nonce = parse_u256_hex(
            self.rpc_call("eth_getTransactionCount", json!([setter_wallet, "latest"]))
                .await?
                .as_str()
                .ok_or_else(|| {
                    KmsError::InternalError("Invalid eth_getTransactionCount response".to_string())
                })?,
        )?;
        let priority_fee = parse_u256_hex(
            self.rpc_call("eth_maxPriorityFeePerGas", json!([]))
                .await?
                .as_str()
                .ok_or_else(|| {
                    KmsError::InternalError("Invalid eth_maxPriorityFeePerGas response".to_string())
                })?,
        )?;
        let latest_block = self
            .rpc_call("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let base_fee_hex = latest_block
            .get("baseFeePerGas")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KmsError::InternalError("Missing baseFeePerGas".to_string()))?;
        let base_fee = parse_u256_hex(base_fee_hex)?;
        let max_fee = base_fee.saturating_mul(U256::from(2u64)) + priority_fee;

        let tx = json!({
            "chainId": to_rpc_hex(chain_id),
            "type": "0x2",
            "from": setter_wallet,
            "to": self.kms_registry_address,
            "nonce": to_rpc_hex(nonce),
            "data": set_master_secret_hash_calldata(secret_hash),
            "value": "0x0",
            "maxPriorityFeePerGas": to_rpc_hex(priority_fee),
            "maxFeePerGas": to_rpc_hex(max_fee),
            "gas": "0x493e0",
        });

        let sign_res = odyn.sign_tx(tx).await?;
        let raw_tx = extract_raw_tx(&sign_res).ok_or_else(|| {
            KmsError::InternalError(format!(
                "Odyn sign_tx returned unexpected payload: {}",
                sign_res
            ))
        })?;

        let sent = self
            .rpc_call("eth_sendRawTransaction", json!([raw_tx]))
            .await?;
        sent.as_str().map(str::to_string).ok_or_else(|| {
            KmsError::InternalError("Invalid eth_sendRawTransaction result".to_string())
        })
    }

    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, KmsError> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await
            .map_err(|e| {
                KmsError::InternalError(format!("RPC {} request failed: {}", method, e))
            })?;
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| KmsError::InternalError(format!("RPC {} decode failed: {}", method, e)))?;
        if !status.is_success() {
            return Err(KmsError::InternalError(format!(
                "RPC {} HTTP {}: {}",
                method, status, body
            )));
        }
        if let Some(err) = body.get("error") {
            return Err(KmsError::InternalError(format!(
                "RPC {} returned error: {}",
                method, err
            )));
        }
        body.get("result")
            .cloned()
            .ok_or_else(|| KmsError::InternalError(format!("RPC {} missing result", method)))
    }
}

#[derive(Clone, Debug)]
struct TimedEntry<T> {
    expires_at: u64,
    value: T,
}

pub struct CachedNovaRegistry {
    inner: RegistryClient,
    ttl_seconds: u64,
    not_found_instance_ttl_seconds: u64,
    app_cache: RwLock<HashMap<u64, TimedEntry<AppInfo>>>,
    version_cache: RwLock<HashMap<(u64, u64), TimedEntry<VersionInfo>>>,
    wallet_cache: RwLock<HashMap<String, TimedEntry<RuntimeInstanceInfo>>>,
    active_instances_cache: RwLock<HashMap<u64, TimedEntry<Vec<String>>>>,
}

impl CachedNovaRegistry {
    pub const DEFAULT_NOT_FOUND_INSTANCE_TTL_SECONDS: u64 = 10;

    pub fn new(inner: RegistryClient, ttl_seconds: u64) -> Self {
        let ttl = ttl_seconds.max(1);
        Self {
            inner,
            ttl_seconds: ttl,
            not_found_instance_ttl_seconds: ttl.min(Self::DEFAULT_NOT_FOUND_INSTANCE_TTL_SECONDS),
            app_cache: RwLock::new(HashMap::new()),
            version_cache: RwLock::new(HashMap::new()),
            wallet_cache: RwLock::new(HashMap::new()),
            active_instances_cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn invalidate_all(&self) {
        self.app_cache.write().await.clear();
        self.version_cache.write().await.clear();
        self.wallet_cache.write().await.clear();
        self.active_instances_cache.write().await.clear();
    }

    pub async fn get_app(&self, app_id: u64) -> Result<AppInfo, KmsError> {
        let now = now_secs();
        match self.app_cache.read().await.get(&app_id).cloned() {
            Some(cached) if now <= cached.expires_at => return Ok(cached.value),
            _ => {}
        }
        self.app_cache.write().await.remove(&app_id);

        let fetched = self.inner.get_app(app_id).await?;
        self.app_cache.write().await.insert(
            app_id,
            TimedEntry {
                expires_at: now + self.ttl_seconds,
                value: fetched.clone(),
            },
        );
        Ok(fetched)
    }

    pub async fn get_version(&self, app_id: u64, version_id: u64) -> Result<VersionInfo, KmsError> {
        let key = (app_id, version_id);
        let now = now_secs();
        match self.version_cache.read().await.get(&key).cloned() {
            Some(cached) if now <= cached.expires_at => return Ok(cached.value),
            _ => {}
        }
        self.version_cache.write().await.remove(&key);

        let fetched = self.inner.get_version(app_id, version_id).await?;
        self.version_cache.write().await.insert(
            key,
            TimedEntry {
                expires_at: now + self.ttl_seconds,
                value: fetched.clone(),
            },
        );
        Ok(fetched)
    }

    pub async fn get_instance_by_wallet(
        &self,
        wallet: &str,
    ) -> Result<RuntimeInstanceInfo, KmsError> {
        let key = wallet.to_lowercase();
        let now = now_secs();
        match self.wallet_cache.read().await.get(&key).cloned() {
            Some(cached) if now <= cached.expires_at => return Ok(cached.value),
            _ => {}
        }
        self.wallet_cache.write().await.remove(&key);

        let fetched = self.inner.get_instance_by_wallet(wallet).await?;
        let ttl = if fetched.instance_id == 0 {
            self.not_found_instance_ttl_seconds
        } else {
            self.ttl_seconds
        };
        self.wallet_cache.write().await.insert(
            key,
            TimedEntry {
                expires_at: now + ttl,
                value: fetched.clone(),
            },
        );
        Ok(fetched)
    }

    pub async fn get_active_instances(&self, app_id: u64) -> Result<Vec<String>, KmsError> {
        let now = now_secs();
        match self
            .active_instances_cache
            .read()
            .await
            .get(&app_id)
            .cloned()
        {
            Some(cached) if now <= cached.expires_at => return Ok(cached.value),
            _ => {}
        }
        self.active_instances_cache.write().await.remove(&app_id);

        let fetched = self.inner.get_active_instances(app_id).await?;
        self.active_instances_cache.write().await.insert(
            app_id,
            TimedEntry {
                expires_at: now + self.ttl_seconds,
                value: fetched.clone(),
            },
        );
        Ok(fetched)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn set_master_secret_hash_calldata(secret_hash: [u8; 32]) -> String {
    let selector = &keccak256("setMasterSecretHash(bytes32)".as_bytes())[0..4];
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(selector);
    data.extend_from_slice(&secret_hash);
    format!("0x{}", hex::encode(data))
}

fn parse_u256_hex(input: &str) -> Result<U256, KmsError> {
    let raw = input.trim().trim_start_matches("0x");
    U256::from_str_radix(raw, 16)
        .map_err(|e| KmsError::InternalError(format!("Invalid hex number {}: {}", input, e)))
}

fn to_rpc_hex(v: U256) -> String {
    format!("0x{:x}", v)
}

fn extract_raw_tx(value: &Value) -> Option<String> {
    let direct_keys = [
        "raw_transaction",
        "rawTransaction",
        "signed_tx",
        "signedTx",
        "tx",
        "transaction",
    ];
    for key in direct_keys {
        match value.get(key).and_then(|v| v.as_str()) {
            Some(v) if v.starts_with("0x") => return Some(v.to_string()),
            _ => {}
        }
    }
    let nested = value.get("payload")?;
    for key in direct_keys {
        match nested.get(key).and_then(|v| v.as_str()) {
            Some(v) if v.starts_with("0x") => return Some(v.to_string()),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_master_secret_hash_calldata_shape() {
        let data = set_master_secret_hash_calldata([0x11; 32]);
        assert!(data.starts_with("0x"));
        // 4-byte selector + 32-byte arg
        assert_eq!(data.len(), 2 + 36 * 2);
    }

    #[test]
    fn test_extract_raw_tx_variants() {
        let direct = json!({"rawTransaction":"0xabc"});
        assert_eq!(extract_raw_tx(&direct), Some("0xabc".to_string()));
        let nested = json!({"payload":{"signed_tx":"0xdef"}});
        assert_eq!(extract_raw_tx(&nested), Some("0xdef".to_string()));
        let invalid = json!({"payload":{"signed_tx":"def"}});
        assert_eq!(extract_raw_tx(&invalid), None);
    }

    #[tokio::test]
    async fn test_cached_wallet_hit_without_network() {
        let client = RegistryClient::new(
            "http://127.0.0.1:8545",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        )
        .unwrap();
        let cache = CachedNovaRegistry::new(client, 180);
        cache.wallet_cache.write().await.insert(
            "0xabc".to_string(),
            TimedEntry {
                expires_at: now_secs() + 180,
                value: RuntimeInstanceInfo {
                    instance_id: 1,
                    app_id: 49,
                    version_id: 1,
                    operator: "0x1".to_string(),
                    instance_url: "https://kms.test".to_string(),
                    tee_pubkey: vec![1, 2, 3],
                    tee_wallet_address: "0xabc".to_string(),
                    zk_verified: true,
                    status: 0,
                    registered_at: 1,
                },
            },
        );

        let out = cache.get_instance_by_wallet("0xABC").await.unwrap();
        assert_eq!(out.instance_id, 1);
        assert_eq!(out.tee_wallet_address, "0xabc");
    }
}
