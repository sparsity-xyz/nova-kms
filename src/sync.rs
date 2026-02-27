use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use reqwest::Url;

use crate::registry::RegistryClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub tee_wallet_address: String,
    pub node_url: String,
    pub tee_pubkey: String,
    pub app_id: u64,
    pub operator: String,
    pub status: u8,
    pub zk_verified: bool,
    pub version_id: u64,
    pub instance_id: u64,
    pub registered_at: u64,
}

pub struct PeerCache {
    peers: RwLock<Vec<Peer>>,
    blacklist: RwLock<HashMap<String, u64>>,
    last_refresh: RwLock<u64>,
}

impl PeerCache {
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(Vec::new()),
            blacklist: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(0),
        }
    }

    pub async fn blacklist_peer(&self, wallet: &str, duration_secs: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut b = self.blacklist.write().await;
        b.insert(wallet.to_lowercase(), now + duration_secs);
    }

    pub async fn is_blacklisted(&self, wallet: &str) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let b = self.blacklist.read().await;
        if let Some(exp) = b.get(&wallet.to_lowercase()) {
            if now < *exp {
                return true;
            }
        }
        false
    }

    pub async fn get_peers(&self, exclude_wallet: Option<&str>) -> Vec<Peer> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let p = self.peers.read().await;
        let b = self.blacklist.read().await;

        p.iter()
            .filter(|peer| {
                if let Some(exc) = exclude_wallet {
                    if peer.tee_wallet_address.eq_ignore_ascii_case(exc) {
                        return false;
                    }
                }
                if let Some(exp) = b.get(&peer.tee_wallet_address) {
                    if now < *exp {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    pub async fn get_tee_pubkey_by_wallet(&self, wallet: &str) -> Option<String> {
        let p = self.peers.read().await;
        p.iter()
            .find(|peer| peer.tee_wallet_address.eq_ignore_ascii_case(wallet))
            .map(|peer| peer.tee_pubkey.clone())
    }

    pub async fn refresh(&self, registry: &RegistryClient, kms_app_id: u64) -> Result<(), Box<dyn std::error::Error>> {
        let active_instances = registry.nova_registry.getActiveInstances(alloy::primitives::U256::from(kms_app_id)).call().await?._0;
        
        let mut new_peers = Vec::new();

        for wallet in active_instances {
            let instance = match registry.nova_registry.getInstanceByWallet(wallet).call().await {
                Ok(res) => res._0,
                Err(_) => continue,
            };

            if instance.status != 0 {
                continue; // Not active
            }

            if !instance.zkVerified {
                continue;
            }

            if let Ok(url) = Url::parse(&instance.instanceUrl) {
                if url.scheme() != "http" && url.scheme() != "https" {
                    continue;
                }

                let pubkey_hex = hex::encode(&instance.teePubkey);
                
                new_peers.push(Peer {
                    tee_wallet_address: wallet.to_checksum(None).to_lowercase(),
                    node_url: instance.instanceUrl,
                    tee_pubkey: pubkey_hex,
                    app_id: instance.appId.try_into().unwrap_or(0),
                    operator: instance.operator.to_checksum(None).to_lowercase(),
                    status: instance.status,
                    zk_verified: instance.zkVerified,
                    version_id: instance.versionId.try_into().unwrap_or(0),
                    instance_id: instance.id.try_into().unwrap_or(0),
                    registered_at: instance.registeredAt.try_into().unwrap_or(0),
                });
            }
        }

        let mut p = self.peers.write().await;
        *p = new_peers;
        
        let mut lr = self.last_refresh.write().await;
        *lr = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        Ok(())
    }
}
