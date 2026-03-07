use alloy::primitives::keccak256;
use base64::Engine as _;
use p384::pkcs8::EncodePublicKey;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};

use crate::auth::{canonical_wallet, sign_message_for_node, verify_wallet_signature};
use crate::crypto::{
    MasterSecretManager, SealedMasterSecretEnvelope, decrypt_data, derive_data_key,
    derive_sync_key, random_secret_32, unseal_master_secret,
};
use crate::error::KmsError;
use crate::models::DataRecord;
use crate::state::SharedState;

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
    pub status_reachable: Option<bool>,
    pub status_http_code: Option<u16>,
    pub status_probe_ms: Option<u64>,
    pub status_checked_at_ms: Option<u64>,
}

pub struct PeerCache {
    peers: RwLock<Vec<Peer>>,
    blacklist: RwLock<HashMap<String, u64>>,
    last_refresh: RwLock<u64>,
}

impl Default for PeerCache {
    fn default() -> Self {
        Self::new()
    }
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
        let now = now_secs();
        let mut b = self.blacklist.write().await;
        let wallet_key = wallet.to_lowercase();
        b.insert(wallet_key.clone(), now + duration_secs);
        drop(b);

        let mut peers = self.peers.write().await;
        peers.retain(|p| p.tee_wallet_address.to_lowercase() != wallet_key);
    }

    pub async fn get_peers(&self, exclude_wallet: Option<&str>) -> Vec<Peer> {
        let now = now_secs();
        let peers_snapshot = self.peers.read().await.clone();
        let blacklist_snapshot = self.blacklist.read().await.clone();

        peers_snapshot
            .into_iter()
            .filter(|peer| {
                if exclude_wallet
                    .map(|exc| peer.tee_wallet_address.eq_ignore_ascii_case(exc))
                    .unwrap_or(false)
                {
                    return false;
                }
                if blacklist_snapshot
                    .get(&peer.tee_wallet_address.to_lowercase())
                    .map(|exp| now < *exp)
                    .unwrap_or(false)
                {
                    return false;
                }
                true
            })
            .collect()
    }

    pub async fn get_peer_by_wallet(&self, wallet: &str) -> Option<Peer> {
        let now = now_secs();
        let wallet_key = wallet.to_lowercase();
        let is_blacklisted = self
            .blacklist
            .read()
            .await
            .get(&wallet_key)
            .map(|exp| now < *exp)
            .unwrap_or(false);
        if is_blacklisted {
            return None;
        }
        let p = self.peers.read().await;
        p.iter()
            .find(|peer| peer.tee_wallet_address.eq_ignore_ascii_case(wallet))
            .cloned()
    }

    pub async fn get_wallet_by_url(&self, node_url: &str) -> Option<String> {
        let base = node_url.trim_end_matches('/');
        let p = self.peers.read().await;
        p.iter()
            .find(|peer| peer.node_url.trim_end_matches('/') == base)
            .map(|peer| peer.tee_wallet_address.clone())
    }

    pub async fn get_tee_pubkey_by_wallet(&self, wallet: &str) -> Option<String> {
        self.get_peer_by_wallet(wallet).await.map(|p| p.tee_pubkey)
    }

    pub async fn is_stale(&self, ttl_seconds: u64) -> bool {
        let last = *self.last_refresh.read().await;
        now_secs().saturating_sub(last) > ttl_seconds
    }

    pub async fn refresh_from_chain(&self, state: &SharedState) -> Result<usize, KmsError> {
        let (kms_app_id, in_enclave, registry) = {
            let s = state.read().await;
            (s.config.kms_app_id, s.config.in_enclave, s.registry.clone())
        };

        let active_instances = registry.get_active_instances(kms_app_id).await?;
        tracing::debug!(
            "Peer discovery for app {} returned {} active wallets from registry",
            kms_app_id,
            active_instances.len()
        );

        let mut new_peers = Vec::new();
        for wallet in active_instances {
            let instance = match registry.get_instance_by_wallet(&wallet).await {
                Ok(res) => res,
                Err(_) => continue,
            };
            if instance.status != 0 || !instance.zk_verified {
                continue;
            }
            // ENROLLED=0, DEPRECATED=1, REVOKED=2
            let version = match registry
                .get_version(instance.app_id, instance.version_id)
                .await
            {
                Ok(v) => v,
                Err(_) => continue,
            };
            if version.status != 0 && version.status != 1 {
                continue;
            }

            if let Err(err) = validate_peer_url(&instance.instance_url, in_enclave) {
                tracing::warn!(
                    "Skipping peer {} due to invalid URL '{}': {}",
                    wallet,
                    instance.instance_url,
                    err
                );
                continue;
            }

            let mut peer = Peer {
                tee_wallet_address: instance.tee_wallet_address,
                node_url: instance.instance_url,
                tee_pubkey: hex::encode(&instance.tee_pubkey),
                app_id: instance.app_id,
                operator: instance.operator,
                status: instance.status,
                zk_verified: instance.zk_verified,
                version_id: instance.version_id,
                instance_id: instance.instance_id,
                registered_at: instance.registered_at,
                status_reachable: None,
                status_http_code: None,
                status_probe_ms: None,
                status_checked_at_ms: None,
            };
            if in_enclave {
                let probe = probe_status_endpoint(&peer.node_url).await;
                peer.status_reachable = Some(probe.status_reachable);
                peer.status_http_code = probe.status_http_code;
                peer.status_probe_ms = Some(probe.status_probe_ms);
                peer.status_checked_at_ms = Some(probe.status_checked_at_ms);
            }
            new_peers.push(peer);
        }

        let peer_count = new_peers.len();
        {
            let mut p = self.peers.write().await;
            *p = new_peers;
        }
        *self.last_refresh.write().await = now_secs();
        tracing::info!("Peer cache refreshed: {} active KMS instances", peer_count);
        Ok(peer_count)
    }

    pub async fn verify_kms_peer(&self, wallet: &str, kms_app_id: u64) -> Result<Peer, KmsError> {
        let Some(peer) = self.get_peer_by_wallet(wallet).await else {
            return Err(KmsError::Forbidden(format!(
                "Peer {} not found in PeerCache",
                wallet
            )));
        };
        if peer.status != 0 {
            return Err(KmsError::Forbidden("Peer instance not ACTIVE".to_string()));
        }
        if !peer.zk_verified {
            return Err(KmsError::Forbidden("Peer not zk-verified".to_string()));
        }
        if peer.app_id != kms_app_id {
            return Err(KmsError::Forbidden("Peer app_id mismatch".to_string()));
        }
        if peer.tee_pubkey.is_empty() {
            return Err(KmsError::Forbidden("Peer tee_pubkey missing".to_string()));
        }
        Ok(peer)
    }
}

struct StatusProbe {
    status_reachable: bool,
    status_http_code: Option<u16>,
    status_probe_ms: u64,
    status_checked_at_ms: u64,
}

fn validate_peer_url(node_url: &str, in_enclave: bool) -> Result<(), KmsError> {
    let parsed = Url::parse(node_url).map_err(|e| {
        KmsError::ValidationError(format!("Invalid peer URL '{}': {}", node_url, e))
    })?;

    let scheme = parsed.scheme();
    let scheme_allowed = if in_enclave {
        scheme == "https"
    } else {
        scheme == "https" || scheme == "http"
    };
    if !scheme_allowed {
        return Err(KmsError::ValidationError(format!(
            "Peer URL scheme '{}' not allowed",
            scheme
        )));
    }
    if parsed.host_str().is_none() {
        return Err(KmsError::ValidationError(
            "Peer URL has no hostname".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(KmsError::ValidationError(
            "Peer URL with embedded credentials is not allowed".to_string(),
        ));
    }
    Ok(())
}

async fn probe_status_endpoint(node_url: &str) -> StatusProbe {
    let checked_at_ms = now_ms();
    let start = now_ms();
    let status_url = format!("{}/status", node_url.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(v) => v,
        Err(_) => {
            return StatusProbe {
                status_reachable: false,
                status_http_code: None,
                status_probe_ms: 0,
                status_checked_at_ms: checked_at_ms,
            };
        }
    };

    match client.get(status_url).send().await {
        Ok(resp) => StatusProbe {
            status_reachable: resp.status().is_success(),
            status_http_code: Some(resp.status().as_u16()),
            status_probe_ms: now_ms().saturating_sub(start),
            status_checked_at_ms: checked_at_ms,
        },
        Err(_) => StatusProbe {
            status_reachable: false,
            status_http_code: None,
            status_probe_ms: now_ms().saturating_sub(start),
            status_checked_at_ms: checked_at_ms,
        },
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn sort_json_value(v: &Value) -> Value {
    match v {
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_value).collect()),
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                if let Some(inner) = map.get(&k) {
                    out.insert(k, sort_json_value(inner));
                }
            }
            Value::Object(out)
        }
        _ => v.clone(),
    }
}

pub fn canonical_json(v: &Value) -> Result<String, KmsError> {
    let sorted = sort_json_value(v);
    serde_json::to_string(&sorted)
        .map_err(|e| KmsError::InternalError(format!("JSON encode failed: {}", e)))
}

pub fn hmac_hex(sync_key: &[u8; 32], payload: &[u8]) -> String {
    hex::encode(crate::crypto::generate_hmac_sha256(sync_key, payload))
}

pub fn verify_hmac_hex(sync_key: &[u8; 32], payload: &[u8], signature_hex: &str) -> bool {
    if let Ok(sig) = hex::decode(signature_hex) {
        crate::crypto::verify_hmac_sha256(sync_key, payload, &sig).is_ok()
    } else {
        false
    }
}

fn sync_record_to_value(record: &DataRecord) -> Value {
    json!({
        "key": record.key,
        "value": if record.tombstone { Value::Null } else { Value::String(hex::encode(&record.encrypted_value)) },
        "version": record.version.clocks,
        "updated_at_ms": record.updated_at_ms,
        "tombstone": record.tombstone,
        "ttl_ms": record.ttl_ms,
    })
}

pub fn serialize_deltas(deltas: &HashMap<u64, Vec<DataRecord>>) -> Value {
    let mut map = Map::new();
    for (app_id, records) in deltas {
        map.insert(
            app_id.to_string(),
            Value::Array(records.iter().map(sync_record_to_value).collect()),
        );
    }
    Value::Object(map)
}

const INIT_RETRY_ATTEMPTS: usize = 5;
const INIT_RETRY_BASE_DELAY_MS: u64 = 500;
const INIT_RETRY_MAX_DELAY_MS: u64 = 5_000;

fn retry_delay_for_attempt(attempt: usize) -> Duration {
    let exp = attempt.saturating_sub(1).min(6) as u32;
    let ms = INIT_RETRY_BASE_DELAY_MS
        .saturating_mul(1u64 << exp)
        .min(INIT_RETRY_MAX_DELAY_MS);
    Duration::from_millis(ms)
}

async fn retry_init_op<T, F, Fut>(label: &str, mut op: F) -> Result<T, KmsError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, KmsError>>,
{
    let attempts = INIT_RETRY_ATTEMPTS.max(1);
    let mut attempt = 1usize;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(err) => {
                if attempt >= attempts {
                    return Err(err);
                }
                let delay = retry_delay_for_attempt(attempt);
                tracing::warn!(
                    "{} failed on attempt {}/{}: {}. Retrying in {}ms",
                    label,
                    attempt,
                    attempts,
                    err,
                    delay.as_millis()
                );
                sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

pub async fn refresh_peers_if_needed(state: &SharedState) -> Result<(), KmsError> {
    let (ttl, peer_cache) = {
        let s = state.read().await;
        (s.config.peer_cache_ttl_seconds, Arc::clone(&s.peer_cache))
    };
    if ttl == 0 || !peer_cache.is_stale(ttl).await {
        return Ok(());
    }
    retry_init_op("Peer cache refresh", || async {
        peer_cache.refresh_from_chain(state).await
    })
    .await?;
    Ok(())
}

async fn local_master_secret_hash(state: &SharedState) -> Option<[u8; 32]> {
    let master_secret = {
        let s = state.read().await;
        Arc::clone(&s.master_secret)
    };
    let secret = master_secret.get_secret().await.ok()?;
    let hash = keccak256(secret.bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_slice());
    Some(out)
}

async fn current_sync_key(state: &SharedState) -> Result<Option<[u8; 32]>, KmsError> {
    let (cached_sync_key, master_secret) = {
        let s = state.read().await;
        (s.sync_key, Arc::clone(&s.master_secret))
    };
    if let Some(sync_key) = cached_sync_key {
        return Ok(Some(sync_key));
    }
    if !master_secret.is_initialized().await {
        return Ok(None);
    }

    let sync_key = master_secret.get_sync_key().await?;
    let mut s = state.write().await;
    if s.sync_key.is_none() {
        s.sync_key = Some(sync_key);
    }
    Ok(s.sync_key)
}

async fn set_service_availability(state: &SharedState, available: bool, reason: &str) {
    let (changed, new_reason) = {
        let mut s = state.write().await;
        let previous_available = s.service_available;
        let previous_reason = s.service_unavailable_reason.clone();
        s.service_available = available;
        if available {
            s.service_unavailable_reason.clear();
        } else {
            s.service_unavailable_reason = reason.to_string();
        }
        let changed = previous_available != s.service_available
            || previous_reason != s.service_unavailable_reason;
        (changed, s.service_unavailable_reason.clone())
    };

    if changed {
        if available {
            tracing::info!("Service availability changed: available");
        } else {
            tracing::warn!("Service availability changed: unavailable ({})", new_reason);
        }
    }
}

pub async fn node_tick(state: &SharedState) -> Result<(), KmsError> {
    let (peer_cache, odyn, in_enclave) = {
        let s = state.read().await;
        (
            Arc::clone(&s.peer_cache),
            s.odyn.clone(),
            s.config.in_enclave,
        )
    };
    if in_enclave {
        match retry_init_op("Odyn eth_address", || async { odyn.eth_address().await }).await {
            Ok(wallet) => match canonical_wallet(&wallet) {
                Ok(canonical) => {
                    let mut s = state.write().await;
                    if s.config.node_wallet != canonical {
                        tracing::info!(
                            "Updating node wallet from Odyn at runtime: {} -> {}",
                            s.config.node_wallet,
                            canonical
                        );
                        s.config.node_wallet = canonical;
                    }
                }
                Err(err) => {
                    tracing::warn!("Failed to canonicalize Odyn wallet '{}': {}", wallet, err);
                }
            },
            Err(err) => {
                tracing::warn!(
                    "Failed to read Odyn wallet in node_tick after retries: {}",
                    err
                );
            }
        }
    }

    let peer_refresh_result = retry_init_op("Peer cache refresh", || async {
        peer_cache.refresh_from_chain(state).await
    })
    .await;
    if let Err(err) = &peer_refresh_result {
        tracing::warn!("Peer cache refresh failed in node_tick: {}", err);
    }

    let node_wallet = {
        let s = state.read().await;
        s.config.node_wallet.clone()
    };
    let peers = peer_cache.get_peers(None).await;

    if peer_refresh_result.is_err() && peers.is_empty() {
        let mut s = state.write().await;
        s.is_operator = false;
        s.service_available = false;
        s.service_unavailable_reason = "peer cache refresh failed".to_string();
        return Ok(());
    }

    let self_wallet = node_wallet.to_lowercase();
    let self_in_membership = peers
        .iter()
        .any(|p| p.tee_wallet_address.eq_ignore_ascii_case(&self_wallet));
    if !self_in_membership {
        tracing::warn!(
            "Node wallet {} not present in current KMS peer membership ({} peers cached)",
            self_wallet,
            peers.len()
        );
        let mut s = state.write().await;
        s.is_operator = false;
        s.service_available = false;
        s.service_unavailable_reason = "self not in KMS node list".to_string();
        return Ok(());
    }

    let own_peer = peers
        .iter()
        .find(|p| p.tee_wallet_address.eq_ignore_ascii_case(&self_wallet))
        .cloned();

    {
        let mut s = state.write().await;
        s.is_operator = true;
        match own_peer.as_ref() {
            Some(peer) if s.config.node_instance_url.trim().is_empty() => {
                s.config.node_instance_url = peer.node_url.clone();
            }
            _ => {}
        }
    }

    if let Some(own_peer) = own_peer {
        let local_pubkey_hex = match retry_init_op("Odyn encryption public key", || async {
            odyn.get_encryption_public_key_der().await
        })
        .await
        {
            Ok(pubkey) => hex::encode(pubkey),
            Err(err) => {
                tracing::warn!("Failed to read local teePubkey after retries: {}", err);
                set_service_availability(state, false, "cannot read local teePubkey").await;
                return Ok(());
            }
        };
        if !own_peer.tee_pubkey.eq_ignore_ascii_case(&local_pubkey_hex) {
            tracing::warn!(
                "Local teePubkey does not match NovaAppRegistry for self wallet {}",
                self_wallet
            );
            set_service_availability(state, false, "local teePubkey mismatch with registry").await;
            return Ok(());
        }
    }

    let registry = {
        let s = state.read().await;
        s.registry.clone()
    };
    let chain_hash = match retry_init_op("Registry masterSecretHash", || async {
        registry.get_master_secret_hash().await
    })
    .await
    {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!("Failed to read masterSecretHash after retries: {}", err);
            set_service_availability(state, false, "cannot read master secret hash").await;
            return Ok(());
        }
    };

    let chain_hash_is_zero = chain_hash == [0u8; 32];
    if chain_hash_is_zero {
        tracing::info!("On-chain masterSecretHash is unset; attempting local initialization");
        let master_secret = {
            let s = state.read().await;
            Arc::clone(&s.master_secret)
        };
        let has_local_secret = master_secret.is_initialized().await;

        if !has_local_secret {
            let generated_secret = match retry_init_op("Odyn random bytes", || async {
                odyn.get_random_bytes().await
            })
            .await
            {
                Ok(random) => {
                    if random.len() < 32 {
                        return Err(KmsError::InternalError(
                            "Odyn returned insufficient random bytes".to_string(),
                        ));
                    }
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&random[..32]);
                    out
                }
                Err(err) if !in_enclave => {
                    tracing::warn!("Odyn RNG unavailable in dev mode, falling back: {}", err);
                    random_secret_32()?
                }
                Err(err) => {
                    tracing::warn!("Failed to get Odyn random bytes after retries: {}", err);
                    set_service_availability(state, false, "cannot get random bytes from odyn")
                        .await;
                    return Ok(());
                }
            };
            master_secret.initialize_generated(generated_secret).await;
        }

        let Some(local_hash) = local_master_secret_hash(state).await else {
            set_service_availability(state, false, "local master secret hash unavailable").await;
            return Ok(());
        };

        let set_result = retry_init_op("Registry setMasterSecretHash", || async {
            registry
                .set_master_secret_hash(&odyn, &node_wallet, local_hash)
                .await
        })
        .await;
        match set_result {
            Ok(tx_hash) => {
                tracing::info!("Submitted setMasterSecretHash tx: {}", tx_hash);
                set_service_availability(state, false, "awaiting on-chain master secret hash")
                    .await;
            }
            Err(err) => {
                tracing::warn!("Failed to set masterSecretHash on-chain: {}", err);
                set_service_availability(state, false, "failed to set master secret hash").await;
            }
        }
        return Ok(());
    }

    if local_master_secret_hash(state).await != Some(chain_hash) {
        tracing::info!("Local master secret hash mismatch; attempting sync from peers");
        let synced = match attempt_master_secret_sync(state).await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!("Master secret sync failed: {}", err);
                false
            }
        };
        if !synced {
            set_service_availability(state, false, "master secret sync failed").await;
            return Ok(());
        }
        if local_master_secret_hash(state).await != Some(chain_hash) {
            set_service_availability(state, false, "synced master secret hash mismatch").await;
            return Ok(());
        }
    }

    let sync_key = match current_sync_key(state).await? {
        Some(sync_key) => sync_key,
        None => {
            set_service_availability(state, false, "master secret not initialized").await;
            return Ok(());
        }
    };

    {
        let mut s = state.write().await;
        s.sync_key = Some(sync_key);
    }
    set_service_availability(state, true, "").await;
    Ok(())
}

pub async fn sync_tick(state: &SharedState) -> Result<usize, KmsError> {
    let service_available = {
        let s = state.read().await;
        s.service_available
    };
    if !service_available {
        return Ok(0);
    }
    if current_sync_key(state).await?.is_none() {
        return Ok(0);
    }
    push_deltas(state).await
}

#[derive(Debug, Clone, Deserialize)]
struct NonceResponse {
    nonce: String,
}

fn normalize_hex_no_prefix(v: &str) -> String {
    v.strip_prefix("0x").unwrap_or(v).to_lowercase()
}

async fn encrypt_json_envelope(
    state: &SharedState,
    payload: &Value,
    receiver_tee_pubkey_hex: &str,
) -> Result<Value, KmsError> {
    let (odyn, plaintext) = {
        let s = state.read().await;
        let plaintext = canonical_json(payload)?;
        (s.odyn.clone(), plaintext)
    };

    let encrypted = odyn.encrypt(&plaintext, receiver_tee_pubkey_hex).await?;
    let sender_pubkey_hex = if encrypted.enclave_public_key.is_empty() {
        hex::encode(odyn.get_encryption_public_key_der().await?)
    } else {
        normalize_hex_no_prefix(&encrypted.enclave_public_key)
    };

    Ok(json!({
        "sender_tee_pubkey": sender_pubkey_hex,
        "nonce": normalize_hex_no_prefix(&encrypted.nonce),
        "encrypted_data": normalize_hex_no_prefix(&encrypted.encrypted_data),
    }))
}

async fn decrypt_json_envelope(state: &SharedState, envelope: &Value) -> Result<Value, KmsError> {
    let obj = envelope
        .as_object()
        .ok_or_else(|| KmsError::ValidationError("Invalid envelope".to_string()))?;
    let sender_pubkey = obj
        .get("sender_tee_pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing sender_tee_pubkey".to_string()))?;
    let nonce = obj
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing nonce".to_string()))?;
    let encrypted_data = obj
        .get("encrypted_data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing encrypted_data".to_string()))?;
    let odyn = {
        let s = state.read().await;
        s.odyn.clone()
    };
    let plaintext = odyn.decrypt(nonce, sender_pubkey, encrypted_data).await?;
    serde_json::from_str(&plaintext).map_err(|e| {
        KmsError::ValidationError(format!("Decrypted payload is not valid JSON: {}", e))
    })
}

fn is_envelope(v: &Value) -> bool {
    let Some(obj) = v.as_object() else {
        return false;
    };
    obj.contains_key("sender_tee_pubkey")
        && obj.contains_key("nonce")
        && obj.contains_key("encrypted_data")
}

pub async fn push_deltas(state: &SharedState) -> Result<usize, KmsError> {
    refresh_peers_if_needed(state).await?;
    let Some(sync_key) = current_sync_key(state).await? else {
        return Ok(0);
    };

    let (node_wallet, peer_cache, store, since, current) = {
        let mut s = state.write().await;
        if !s.service_available {
            return Ok(0);
        }
        let current = now_ms();
        let since = s.last_push_ms.saturating_sub(1);
        s.last_push_ms = current;
        (
            s.config.node_wallet.clone(),
            Arc::clone(&s.peer_cache),
            Arc::clone(&s.store),
            since,
            current,
        )
    };

    let deltas = store.get_deltas_between(since, current, current).await;
    if deltas.is_empty() {
        return Ok(0);
    }

    let app_count = deltas.len();
    let record_count = deltas.values().map(std::vec::Vec::len).sum::<usize>();
    for (app_id, records) in &deltas {
        for record in records {
            tracing::debug!(
                "Preparing delta record: app_id={} key='{}' updated_at_ms={}",
                app_id,
                record.key,
                record.updated_at_ms
            );
        }
    }
    let deltas_payload = serialize_deltas(&deltas);
    let peers = peer_cache.get_peers(Some(&node_wallet)).await;

    if peers.is_empty() {
        tracing::debug!(
            "Delta push skipped: {} records across {} apps but no peers available",
            record_count,
            app_count
        );
        return Ok(0);
    }
    let peer_count = peers.len();
    let peer_targets: Vec<String> = peers
        .iter()
        .map(|peer| format!("{}@{}", peer.tee_wallet_address, peer.node_url))
        .collect();

    tracing::info!(
        "Delta push: {} records across {} apps to {} peers (peers={:?})",
        record_count,
        app_count,
        peer_count,
        peer_targets
    );

    let body = json!({
        "type": "delta",
        "sender_wallet": node_wallet,
        "data": deltas_payload,
    });

    let mut success = 0usize;
    let mut remote_merged = 0usize;
    let mut zero_merge_peers = 0usize;
    for peer in peers {
        let peer_wallet = match canonical_wallet(&peer.tee_wallet_address) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let endpoint = format!("{}/sync", peer.node_url.trim_end_matches('/'));
        let base = peer.node_url.trim_end_matches('/').to_string();
        tracing::info!(
            "Delta push to {} at {}: sending {} record(s) across {} app(s)",
            peer_wallet,
            endpoint,
            record_count,
            app_count
        );

        // PoP nonce
        let nonce_resp = match reqwest::Client::new()
            .get(format!("{}/nonce", base))
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                tracing::debug!(
                    "Delta push to {} failed to fetch nonce: {}",
                    peer_wallet,
                    err
                );
                continue;
            }
        };
        if !nonce_resp.status().is_success() {
            tracing::debug!(
                "Delta push to {} failed: nonce endpoint returned {}",
                peer_wallet,
                nonce_resp.status()
            );
            continue;
        }
        let nonce_data: NonceResponse = match nonce_resp.json().await {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(
                    "Delta push to {} returned invalid nonce JSON: {}",
                    peer_wallet,
                    err
                );
                continue;
            }
        };
        if base64::engine::general_purpose::STANDARD
            .decode(nonce_data.nonce.as_bytes())
            .is_err()
        {
            tracing::debug!(
                "Delta push to {} failed: nonce was not valid base64",
                peer_wallet
            );
            continue;
        }

        let ts = now_secs();
        let message = format!("NovaKMS:Auth:{}:{}:{}", nonce_data.nonce, peer_wallet, ts);
        let (config, odyn) = {
            let s = state.read().await;
            (s.config.clone(), s.odyn.clone())
        };
        let (signature, signer_wallet) = match sign_message_for_node(&config, &odyn, &message).await
        {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "Delta push to {} failed to sign PoP message: {}",
                    peer_wallet,
                    err
                );
                continue;
            }
        };

        let envelope = match encrypt_json_envelope(state, &body, &peer.tee_pubkey).await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "Delta push to {} failed to encrypt payload: {}",
                    peer_wallet,
                    err
                );
                continue;
            }
        };
        let canonical = match canonical_json(&envelope) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "Delta push to {} failed to canonicalize envelope: {}",
                    peer_wallet,
                    err
                );
                continue;
            }
        };
        let sync_sig = hmac_hex(&sync_key, canonical.as_bytes());

        let response = match reqwest::Client::new()
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("x-kms-signature", signature.clone())
            .header("x-kms-wallet", signer_wallet)
            .header("x-kms-timestamp", ts.to_string())
            .header("x-kms-nonce", nonce_data.nonce)
            .header("x-sync-signature", sync_sig)
            .json(&envelope)
            .send()
            .await
        {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "Delta push to {} at {} failed during HTTP request: {}",
                    peer_wallet,
                    endpoint,
                    err
                );
                continue;
            }
        };
        if !response.status().is_success() {
            tracing::warn!(
                "Delta push to {} at {} returned HTTP {}",
                peer_wallet,
                endpoint,
                response.status()
            );
            continue;
        }

        let Some(resp_sig) = response.headers().get("x-kms-peer-signature") else {
            tracing::warn!(
                "Delta push to {} failed: missing X-KMS-Peer-Signature",
                peer_wallet
            );
            continue;
        };
        let Ok(resp_sig) = resp_sig.to_str() else {
            tracing::warn!(
                "Delta push to {} failed: invalid X-KMS-Peer-Signature header",
                peer_wallet
            );
            continue;
        };
        let expected = format!("NovaKMS:Response:{}:{}", signature, peer_wallet);
        if !verify_wallet_signature(&peer_wallet, &expected, resp_sig) {
            tracing::warn!(
                "Delta push to {} failed: invalid peer response signature",
                peer_wallet
            );
            continue;
        }

        let resp_json: Value = match response.json().await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    "Delta push to {} failed to decode response JSON: {}",
                    peer_wallet,
                    err
                );
                continue;
            }
        };
        let resp_body = if is_envelope(&resp_json) {
            match decrypt_json_envelope(state, &resp_json).await {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(
                        "Delta push to {} failed to decrypt response envelope: {}",
                        peer_wallet,
                        err
                    );
                    continue;
                }
            }
        } else {
            resp_json
        };

        let peer_total = resp_body.get("total").and_then(|v| v.as_u64());
        let peer_merged = resp_body.get("merged").and_then(|v| v.as_u64());
        let peer_skipped = resp_body.get("skipped").and_then(|v| v.as_u64());
        let peer_rejected = resp_body.get("rejected").and_then(|v| v.as_u64());
        let peer_skip_reasons = resp_body.get("skip_reasons").and_then(|v| v.as_object());
        if let Some(peer_merged) = peer_merged {
            remote_merged += peer_merged as usize;
            if peer_merged == 0 {
                zero_merge_peers += 1;
            }
            let has_extended_stats = peer_total.is_some()
                || peer_skipped.is_some()
                || peer_rejected.is_some()
                || peer_skip_reasons.is_some();
            if has_extended_stats {
                let total = peer_total
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let skipped = peer_skipped
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let rejected = peer_rejected
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let skip_reasons = peer_skip_reasons
                    .map(|m| format!("{:?}", m))
                    .unwrap_or_else(|| "unknown".to_string());
                tracing::info!(
                    "Delta push to {} acknowledged: total={} merged={} skipped={} rejected={} skip_reasons={}",
                    peer_wallet,
                    total,
                    peer_merged,
                    skipped,
                    rejected,
                    skip_reasons
                );
            } else {
                tracing::info!(
                    "Delta push to {} acknowledged: merged={} (peer omitted extended stats)",
                    peer_wallet,
                    peer_merged
                );
            }
        } else {
            tracing::info!(
                "Delta push to {} acknowledged without merge stats in response: body={}",
                peer_wallet,
                resp_body
            );
        }
        success += 1;
    }

    tracing::info!(
        "Delta push complete: {}/{} peers acknowledged, remote merged {} record(s), zero-merge peers={} (payload {} records across {} apps)",
        success,
        peer_count,
        remote_merged,
        zero_merge_peers,
        record_count,
        app_count
    );
    Ok(success)
}

async fn post_sync_request_to_peer(
    state: &SharedState,
    peer: &Peer,
    inner_payload: &Value,
    maybe_sync_key: Option<[u8; 32]>,
) -> Result<Value, KmsError> {
    let peer_wallet = canonical_wallet(&peer.tee_wallet_address)?;
    let base = peer.node_url.trim_end_matches('/').to_string();
    let endpoint = format!("{}/sync", base);
    let request_type = inner_payload
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    tracing::debug!(
        "Sending {} sync request to peer {} at {}",
        request_type,
        peer_wallet,
        endpoint
    );

    let nonce_resp = reqwest::Client::new()
        .get(format!("{}/nonce", base))
        .send()
        .await
        .map_err(|e| KmsError::InternalError(format!("Failed to fetch nonce: {}", e)))?;
    if !nonce_resp.status().is_success() {
        return Err(KmsError::ServiceUnavailable(format!(
            "Peer nonce endpoint returned {}",
            nonce_resp.status()
        )));
    }
    let nonce_data: NonceResponse = nonce_resp
        .json()
        .await
        .map_err(|e| KmsError::ValidationError(format!("Invalid nonce response: {}", e)))?;
    if base64::engine::general_purpose::STANDARD
        .decode(nonce_data.nonce.as_bytes())
        .is_err()
    {
        return Err(KmsError::ValidationError(
            "Peer nonce is not valid base64".to_string(),
        ));
    }

    let ts = now_secs();
    let message = format!("NovaKMS:Auth:{}:{}:{}", nonce_data.nonce, peer_wallet, ts);
    let (config, odyn) = {
        let s = state.read().await;
        (s.config.clone(), s.odyn.clone())
    };
    let (signature, signer_wallet) = sign_message_for_node(&config, &odyn, &message).await?;

    let envelope = encrypt_json_envelope(state, inner_payload, &peer.tee_pubkey).await?;
    let canonical = canonical_json(&envelope)?;

    let mut req = reqwest::Client::new()
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("x-kms-signature", signature.clone())
        .header("x-kms-wallet", signer_wallet)
        .header("x-kms-timestamp", ts.to_string())
        .header("x-kms-nonce", nonce_data.nonce)
        .json(&envelope);

    if let Some(sync_key) = maybe_sync_key {
        req = req.header(
            "x-sync-signature",
            hmac_hex(&sync_key, canonical.as_bytes()),
        );
    }

    let response = req
        .send()
        .await
        .map_err(|e| KmsError::InternalError(format!("Sync request failed: {}", e)))?;
    if !response.status().is_success() {
        return Err(KmsError::ServiceUnavailable(format!(
            "Peer sync endpoint returned {}",
            response.status()
        )));
    }

    let resp_sig = response
        .headers()
        .get("x-kms-peer-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            KmsError::Unauthorized("Missing X-KMS-Peer-Signature in sync response".to_string())
        })?;
    let expected = format!("NovaKMS:Response:{}:{}", signature, peer_wallet);
    if !verify_wallet_signature(&peer_wallet, &expected, resp_sig) {
        return Err(KmsError::Unauthorized(
            "Invalid peer response signature".to_string(),
        ));
    }

    let body: Value = response
        .json()
        .await
        .map_err(|e| KmsError::ValidationError(format!("Invalid sync response body: {}", e)))?;
    tracing::debug!(
        "{} sync request to peer {} completed successfully",
        request_type,
        peer_wallet
    );
    if is_envelope(&body) {
        decrypt_json_envelope(state, &body).await
    } else {
        Ok(body)
    }
}

pub async fn attempt_master_secret_sync(state: &SharedState) -> Result<bool, KmsError> {
    refresh_peers_if_needed(state).await?;
    let (node_wallet, peer_cache) = {
        let s = state.read().await;
        (s.config.node_wallet.clone(), Arc::clone(&s.peer_cache))
    };
    let peers = peer_cache.get_peers(Some(&node_wallet)).await;
    if peers.is_empty() {
        tracing::warn!("Master secret sync requested but no peers are available");
        return Ok(false);
    }

    tracing::info!("Attempting master secret sync from {} peer(s)", peers.len());

    let local_wallet = node_wallet;

    for peer in peers {
        tracing::info!(
            "Requesting master secret from peer {} at {}",
            peer.tee_wallet_address,
            peer.node_url
        );
        let local_secret = p384::SecretKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
        let local_pub_der = match local_secret.public_key().to_public_key_der() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let req_body = json!({
            "type": "master_secret_request",
            "sender_wallet": local_wallet,
            "ecdh_pubkey": hex::encode(local_pub_der.as_ref()),
        });

        let maybe_sync_key = current_sync_key(state).await?;
        let response =
            match post_sync_request_to_peer(state, &peer, &req_body, maybe_sync_key).await {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(
                        "Master secret request to peer {} failed: {}",
                        peer.tee_wallet_address,
                        err
                    );
                    continue;
                }
            };
        let sealed_val = response
            .get("sealed")
            .cloned()
            .or_else(|| response.get("data").and_then(|d| d.get("sealed")).cloned());
        let Some(sealed_val) = sealed_val else {
            continue;
        };
        let sealed: SealedMasterSecretEnvelope = match serde_json::from_value(sealed_val) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let secret = match unseal_master_secret(&sealed, &local_secret) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let sync_key = derive_sync_key(&crate::crypto::MasterSecret { bytes: secret });

        let master_secret = {
            let s = state.read().await;
            Arc::clone(&s.master_secret)
        };
        master_secret
            .initialize_synced(secret, Some(peer.node_url.clone()))
            .await;
        {
            let mut s = state.write().await;
            s.sync_key = Some(sync_key);
        }
        tracing::info!(
            "Master secret synced successfully from peer {}",
            peer.tee_wallet_address
        );

        // Pull snapshot right after getting the secret.
        let snapshot_req = json!({
            "type": "snapshot_request",
            "sender_wallet": local_wallet,
        });
        let snapshot_resp = post_sync_request_to_peer(state, &peer, &snapshot_req, Some(sync_key))
            .await
            .map_err(|err| {
                tracing::warn!(
                    "Snapshot request to peer {} failed after master secret sync: {}",
                    peer.tee_wallet_address,
                    err
                );
                err
            })
            .ok();
        let store = {
            let s = state.read().await;
            Arc::clone(&s.store)
        };
        let mut merged_records = 0usize;
        if let Some(data_obj) = snapshot_resp
            .as_ref()
            .and_then(|resp| resp.get("data"))
            .and_then(|v| v.as_object())
        {
            let records = parse_sync_data_object(data_obj);
            for (app_id, record) in records {
                if let Err(reason) = validate_incoming_record(state, app_id, &record).await {
                    tracing::warn!(
                        "Snapshot sync from peer {} rejected record: app_id={} key='{}' updated_at_ms={} reason={}",
                        peer.tee_wallet_address,
                        app_id,
                        record.key,
                        record.updated_at_ms,
                        reason
                    );
                    continue;
                }
                if store.merge_record(app_id, record).await {
                    merged_records += 1;
                }
            }
        }
        tracing::info!(
            "Snapshot sync from peer {} merged {} record(s)",
            peer.tee_wallet_address,
            merged_records
        );

        return Ok(true);
    }

    Ok(false)
}

fn parse_sync_data_object(data: &Map<String, Value>) -> Vec<(u64, DataRecord)> {
    let mut out = Vec::new();
    for (app_id_str, records_val) in data {
        let Ok(app_id) = app_id_str.parse::<u64>() else {
            continue;
        };
        let Some(records) = records_val.as_array() else {
            continue;
        };
        for rec in records {
            if let Some(parsed) = DataRecord::from_sync_value(rec) {
                out.push((app_id, parsed));
            }
        }
    }
    out
}

pub async fn validate_incoming_record_with_context(
    in_enclave: bool,
    max_value_size_bytes: usize,
    max_clock_skew_ms: u64,
    master_secret: &MasterSecretManager,
    app_id: u64,
    record: &DataRecord,
) -> Result<(), String> {
    if !record.tombstone {
        let max_with_overhead = max_value_size_bytes.saturating_add(128);
        if record.encrypted_value.len() > max_with_overhead {
            return Err(format!(
                "encrypted value too large ({} bytes)",
                record.encrypted_value.len()
            ));
        }

        if in_enclave {
            if record.encrypted_value.len() < (12 + 16) {
                return Err(format!(
                    "ciphertext too short ({} bytes)",
                    record.encrypted_value.len()
                ));
            }
            let secret = match master_secret.get_secret().await {
                Ok(v) => v,
                Err(err) => {
                    return Err(format!("master secret unavailable: {}", err));
                }
            };
            let data_key = derive_data_key(&secret, app_id);

            if decrypt_data(&record.encrypted_value, &data_key).is_err() {
                return Err("ciphertext failed validation".to_string());
            }
        }
    }

    if max_clock_skew_ms > 0 {
        let now = now_ms();
        if record.updated_at_ms > now.saturating_add(max_clock_skew_ms) {
            let delta_ms = record.updated_at_ms.saturating_sub(now);
            return Err(format!(
                "future timestamp {}ms exceeds limit (now={}ms + max_skew={}ms, delta={}ms)",
                record.updated_at_ms, now, max_clock_skew_ms, delta_ms
            ));
        }
    }

    Ok(())
}

pub async fn validate_incoming_record(
    state: &SharedState,
    app_id: u64,
    record: &DataRecord,
) -> Result<(), String> {
    let (in_enclave, max_value_size_bytes, max_clock_skew_ms, master_secret) = {
        let s = state.read().await;
        (
            s.config.in_enclave,
            s.config.max_kv_value_size_bytes,
            s.config.max_clock_skew_ms,
            Arc::clone(&s.master_secret),
        )
    };

    validate_incoming_record_with_context(
        in_enclave,
        max_value_size_bytes,
        max_clock_skew_ms,
        &master_secret,
        app_id,
        record,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::VectorClock;
    use crate::{config::Config, state::AppState};
    use axum::{Router, routing::get};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tokio::time::Duration;

    #[test]
    fn test_canonical_json_ordering() {
        let v = json!({"b":1,"a":{"d":1,"c":2}});
        let out = canonical_json(&v).unwrap();
        assert_eq!(out, r#"{"a":{"c":2,"d":1},"b":1}"#);
    }

    #[test]
    fn test_hmac_roundtrip() {
        let key = [0x11u8; 32];
        let payload = br#"{"k":"v"}"#;
        let sig = hmac_hex(&key, payload);
        assert!(verify_hmac_hex(&key, payload, &sig));
    }

    #[test]
    fn test_serialize_deltas_shape() {
        let mut vc = VectorClock::new();
        vc.increment("node-a");
        let rec = DataRecord {
            key: "k".to_string(),
            encrypted_value: vec![1, 2, 3],
            version: vc,
            updated_at_ms: 10,
            tombstone: false,
            ttl_ms: 0,
        };
        let mut deltas = HashMap::new();
        deltas.insert(49u64, vec![rec]);
        let out = serialize_deltas(&deltas);
        assert!(out.get("49").is_some());
        assert_eq!(out["49"][0]["key"], "k");
    }

    #[tokio::test]
    async fn test_blacklist_peer_removes_cached_entry() {
        let cache = PeerCache::new();
        let wallet = "0xa000000000000000000000000000000000000000".to_string();
        cache.peers.write().await.push(Peer {
            tee_wallet_address: wallet.clone(),
            node_url: "https://kms.example".to_string(),
            tee_pubkey: "abcd".to_string(),
            app_id: 49,
            operator: "0xb000000000000000000000000000000000000000".to_string(),
            status: 0,
            zk_verified: true,
            version_id: 1,
            instance_id: 1,
            registered_at: 1,
            status_reachable: None,
            status_http_code: None,
            status_probe_ms: None,
            status_checked_at_ms: None,
        });

        assert!(cache.get_peer_by_wallet(&wallet).await.is_some());
        cache.blacklist_peer(&wallet, 600).await;
        assert!(cache.get_peer_by_wallet(&wallet).await.is_none());
    }

    #[tokio::test]
    async fn test_node_tick_marks_unavailable_when_peer_refresh_fails() {
        let config = Config {
            in_enclave: false,
            node_url: "http://127.0.0.1:1".to_string(),
            node_wallet: "0xa000000000000000000000000000000000000000".to_string(),
            ..Config::default()
        };

        let state = Arc::new(RwLock::new(AppState::new(config).await));
        node_tick(&state).await.unwrap();

        let s = state.read().await;
        assert!(!s.is_operator);
        assert!(!s.service_available);
        assert_eq!(s.service_unavailable_reason, "peer cache refresh failed");
    }

    #[tokio::test]
    async fn test_sync_tick_skips_when_service_unavailable() {
        let config = Config {
            in_enclave: false,
            node_url: "http://127.0.0.1:1".to_string(),
            ..Config::default()
        };
        let state = Arc::new(RwLock::new(AppState::new(config).await));

        {
            let mut s = state.write().await;
            s.sync_key = Some([7u8; 32]);
            s.service_available = false;
        }

        let pushed = sync_tick(&state).await.unwrap();
        assert_eq!(pushed, 0);
    }

    #[tokio::test]
    async fn test_current_sync_key_derives_and_caches_from_master_secret() {
        let config = Config {
            in_enclave: false,
            node_url: "http://127.0.0.1:1".to_string(),
            ..Config::default()
        };
        let state = Arc::new(RwLock::new(AppState::new(config).await));
        let master_secret = {
            let s = state.read().await;
            Arc::clone(&s.master_secret)
        };
        let secret_bytes = [11u8; 32];
        master_secret.initialize_generated(secret_bytes).await;

        let sync_key = current_sync_key(&state).await.unwrap();
        let expected = derive_sync_key(&crate::crypto::MasterSecret {
            bytes: secret_bytes,
        });

        assert_eq!(sync_key, Some(expected));
        let s = state.read().await;
        assert_eq!(s.sync_key, Some(expected));
    }

    #[tokio::test]
    async fn test_probe_status_endpoint_captures_metadata() {
        let app = Router::new().route("/status", get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let probe = probe_status_endpoint(&format!("http://{}", addr)).await;
        assert!(probe.status_reachable);
        assert_eq!(probe.status_http_code, Some(200));
        assert!(probe.status_checked_at_ms > 0);

        handle.abort();
    }

    #[tokio::test]
    async fn test_validate_incoming_record_rejects_oversized_value() {
        let config = Config {
            in_enclave: false,
            node_url: "http://127.0.0.1:1".to_string(),
            max_kv_value_size_bytes: 16,
            ..Config::default()
        };
        let state = Arc::new(RwLock::new(AppState::new(config).await));

        let mut vc = VectorClock::new();
        vc.increment("node-a");
        let record = DataRecord {
            key: "big".to_string(),
            encrypted_value: vec![0x42; 200], // > max + overhead (16 + 128)
            version: vc,
            updated_at_ms: now_ms(),
            tombstone: false,
            ttl_ms: 0,
        };

        let err = validate_incoming_record(&state, 49, &record)
            .await
            .expect_err("oversized record should be rejected");
        assert!(err.contains("encrypted value too large"));
    }

    #[tokio::test]
    async fn test_validate_incoming_record_rejects_future_timestamp() {
        let config = Config {
            in_enclave: false,
            node_url: "http://127.0.0.1:1".to_string(),
            max_clock_skew_ms: 100,
            ..Config::default()
        };
        let state = Arc::new(RwLock::new(AppState::new(config).await));

        let mut vc = VectorClock::new();
        vc.increment("node-a");
        let record = DataRecord {
            key: "future".to_string(),
            encrypted_value: vec![],
            version: vc,
            updated_at_ms: now_ms().saturating_add(1_000),
            tombstone: true,
            ttl_ms: 0,
        };

        let err = validate_incoming_record(&state, 49, &record)
            .await
            .expect_err("future timestamp should be rejected");
        assert!(err.contains("future timestamp"));
    }

    #[tokio::test]
    async fn test_validate_incoming_record_rejects_short_ciphertext_in_enclave_mode() {
        let config = Config {
            in_enclave: false,
            node_url: "http://127.0.0.1:1".to_string(),
            ..Config::default()
        };
        let state = Arc::new(RwLock::new(AppState::new(config).await));
        {
            let mut s = state.write().await;
            s.config.in_enclave = true;
        }

        let mut vc = VectorClock::new();
        vc.increment("node-a");
        let record = DataRecord {
            key: "short-ct".to_string(),
            encrypted_value: vec![0u8; 20], // < 12 nonce + 16 tag
            version: vc,
            updated_at_ms: now_ms(),
            tombstone: false,
            ttl_ms: 0,
        };

        let err = validate_incoming_record(&state, 49, &record)
            .await
            .expect_err("short ciphertext should be rejected");
        assert!(err.contains("ciphertext too short"));
    }

    #[tokio::test]
    async fn test_validate_incoming_record_rejects_invalid_ciphertext_in_enclave_mode() {
        let config = Config {
            in_enclave: false,
            node_url: "http://127.0.0.1:1".to_string(),
            ..Config::default()
        };
        let state = Arc::new(RwLock::new(AppState::new(config).await));
        {
            let mut s = state.write().await;
            s.config.in_enclave = true;
            s.master_secret.initialize_generated([7u8; 32]).await;
        }

        let mut vc = VectorClock::new();
        vc.increment("node-a");
        let record = DataRecord {
            key: "bad-ct".to_string(),
            encrypted_value: vec![0u8; 40], // long enough shape, fails auth tag check
            version: vc,
            updated_at_ms: now_ms(),
            tombstone: false,
            ttl_ms: 0,
        };

        let err = validate_incoming_record(&state, 49, &record)
            .await
            .expect_err("invalid ciphertext should be rejected");
        assert!(err.contains("ciphertext failed validation"));
    }
}
