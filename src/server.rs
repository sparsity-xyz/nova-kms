use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    response::Response,
    routing::{delete, get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::auth::{
    authenticate_app, authenticate_kms_peer, current_node_signing_wallet, sign_message_for_node,
};
use crate::config::Config;
use crate::crypto::{
    MasterSecretManager, derive_app_key_extended, derive_data_key, seal_master_secret,
};
use crate::error::KmsError;
use crate::models::DataRecord;
use crate::odyn::OdynClient;
use crate::state::SharedState;
use crate::sync::{canonical_json, now_ms, validate_incoming_record_with_context, verify_hmac_hex};

pub fn app_router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(api_overview))
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        .route("/nonce", get(nonce_handler))
        .route("/nodes", get(nodes_handler))
        .route("/kms/derive", post(derive_key))
        .route("/kms/data", get(data_entry_get))
        .route("/kms/data", put(put_data))
        .route("/kms/data", delete(delete_data))
        .route("/kms/data/*key", get(get_data_by_path))
        .route("/sync", post(sync_handler))
        .with_state(state)
}

fn is_envelope(v: &Value) -> bool {
    let Some(obj) = v.as_object() else {
        return false;
    };
    obj.contains_key("sender_tee_pubkey")
        && obj.contains_key("nonce")
        && obj.contains_key("encrypted_data")
}

fn normalize_hex(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_lowercase()
}

fn ensure_service_available(
    service_available: bool,
    unavailable_reason: &str,
) -> Result<(), KmsError> {
    if service_available {
        return Ok(());
    }
    Err(KmsError::ServiceUnavailable(
        if unavailable_reason.is_empty() {
            "Service unavailable".to_string()
        } else {
            unavailable_reason.to_string()
        },
    ))
}

async fn decrypt_envelope_payload(
    odyn: &OdynClient,
    body: &Value,
    expected_sender_pubkey_hex: Option<&str>,
) -> Result<Value, KmsError> {
    let obj = body
        .as_object()
        .ok_or_else(|| KmsError::ValidationError("Invalid encrypted envelope".to_string()))?;
    let sender_pub = obj
        .get("sender_tee_pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing sender_tee_pubkey".to_string()))?;
    let mismatched_sender = expected_sender_pubkey_hex.is_some_and(|expected| {
        !expected.is_empty() && normalize_hex(expected) != normalize_hex(sender_pub)
    });
    if mismatched_sender {
        return Err(KmsError::Forbidden(
            "sender_tee_pubkey does not match on-chain registration".to_string(),
        ));
    }

    let nonce = obj
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing nonce".to_string()))?;
    let encrypted_data = obj
        .get("encrypted_data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing encrypted_data".to_string()))?;

    let plaintext = odyn.decrypt(nonce, sender_pub, encrypted_data).await?;
    serde_json::from_str(&plaintext)
        .map_err(|e| KmsError::ValidationError(format!("Invalid decrypted JSON: {}", e)))
}

async fn decode_payload(
    odyn: &OdynClient,
    body: &Value,
    expected_sender_pubkey_hex: Option<&str>,
) -> Result<Value, KmsError> {
    if is_envelope(body) {
        return decrypt_envelope_payload(odyn, body, expected_sender_pubkey_hex).await;
    }
    Err(KmsError::ValidationError(
        "Request must be E2E encrypted. Plaintext fallback is disabled.".to_string(),
    ))
}

async fn encrypt_payload(
    odyn: &OdynClient,
    payload: &Value,
    receiver_pubkey_hex: Option<&str>,
) -> Result<Value, KmsError> {
    let Some(receiver_pubkey_hex) = receiver_pubkey_hex else {
        return Err(KmsError::ValidationError(
            "Receiver teePubkey required for response encryption".to_string(),
        ));
    };
    if receiver_pubkey_hex.is_empty() {
        return Err(KmsError::ValidationError(
            "Receiver teePubkey required for response encryption".to_string(),
        ));
    }

    let plaintext = canonical_json(payload)?;
    let encrypted = odyn.encrypt(&plaintext, receiver_pubkey_hex).await?;
    let sender_pubkey = if encrypted.enclave_public_key.is_empty() {
        hex::encode(odyn.get_encryption_public_key_der().await?)
    } else {
        normalize_hex(&encrypted.enclave_public_key)
    };
    Ok(json!({
        "sender_tee_pubkey": sender_pubkey,
        "nonce": normalize_hex(&encrypted.nonce),
        "encrypted_data": normalize_hex(&encrypted.encrypted_data),
    }))
}

async fn verify_sync_request_hmac(
    headers: &HeaderMap,
    body: &Value,
    payload: &Value,
    sync_type: &str,
    master_secret: &MasterSecretManager,
) -> Result<(), KmsError> {
    if sync_type == "master_secret_request" {
        return Ok(());
    }

    let sync_key = master_secret.get_sync_key().await?;
    let sig = headers
        .get("x-sync-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| KmsError::Unauthorized("Missing HMAC signature".to_string()))?;
    let signed_payload = if is_envelope(body) { body } else { payload };
    let canonical = canonical_json(signed_payload)?;
    if !verify_hmac_hex(&sync_key, canonical.as_bytes(), sig) {
        return Err(KmsError::Unauthorized("Invalid HMAC signature".to_string()));
    }
    Ok(())
}

async fn maybe_add_app_response_signature(
    config: &Config,
    odyn: &OdynClient,
    client_sig: Option<&str>,
    response_headers: &mut HeaderMap,
) {
    if let Some(client_sig) = client_sig {
        let current_wallet = match current_node_signing_wallet(config, odyn).await {
            Ok(wallet) => wallet,
            Err(err) => {
                tracing::warn!(
                    "Failed to determine node wallet for app response signature: {}",
                    err
                );
                return;
            }
        };
        let msg = format!("NovaKMS:Response:{}:{}", client_sig, current_wallet);
        match sign_message_for_node(config, odyn, &msg).await {
            Ok((sig, _)) => {
                if let Ok(value) = sig.parse() {
                    response_headers.insert("X-KMS-Response-Signature", value);
                } else {
                    tracing::warn!("Failed to encode X-KMS-Response-Signature header");
                }
            }
            Err(err) => {
                tracing::warn!("Failed to sign app response: {}", err);
            }
        }
    }
}

async fn maybe_add_peer_response_signature(
    config: &Config,
    odyn: &OdynClient,
    caller_sig: &str,
    response_headers: &mut HeaderMap,
) {
    let current_wallet = match current_node_signing_wallet(config, odyn).await {
        Ok(wallet) => wallet,
        Err(err) => {
            tracing::warn!(
                "Failed to determine node wallet for peer response signature: {}",
                err
            );
            return;
        }
    };
    let msg = format!("NovaKMS:Response:{}:{}", caller_sig, current_wallet);
    match sign_message_for_node(config, odyn, &msg).await {
        Ok((sig, _)) => {
            if let Ok(value) = sig.parse() {
                response_headers.insert("X-KMS-Peer-Signature", value);
            } else {
                tracing::warn!("Failed to encode X-KMS-Peer-Signature header");
            }
        }
        Err(err) => {
            tracing::warn!("Failed to sign peer response: {}", err);
        }
    }
}

async fn api_overview() -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "service": "Nova KMS",
            "docs": {
                "openapi_json": "/openapi.json",
                "swagger_ui": "/docs",
                "redoc": "/redoc",
            },
            "auth": {
                "app_pop_headers": ["x-app-signature", "x-app-nonce", "x-app-timestamp", "x-app-wallet (optional)"],
                "dev_identity_headers": ["x-tee-wallet"],
                "mutual_response_header": "X-KMS-Response-Signature (optional)",
            },
            "endpoints": [
                {"method": "GET", "path": "/health", "auth": "none"},
                {"method": "GET", "path": "/status", "auth": "none"},
                {"method": "GET", "path": "/nonce", "auth": "none"},
                {"method": "GET", "path": "/nodes", "auth": "none"},
                {"method": "POST", "path": "/kms/derive", "auth": "app PoP"},
                {"method": "GET", "path": "/kms/data/{key}", "auth": "app PoP"},
                {"method": "PUT", "path": "/kms/data", "auth": "app PoP"},
                {"method": "DELETE", "path": "/kms/data", "auth": "app PoP"},
                {"method": "POST", "path": "/sync", "auth": "peer PoP + HMAC"},
            ]
        })),
    )
}

async fn health_handler() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"status": "healthy"})))
}

async fn status_handler(State(state): State<SharedState>) -> Result<impl IntoResponse, KmsError> {
    let mut response = json!({});
    let (
        peer_cache,
        node_wallet,
        node_url,
        kms_registry_address,
        kms_app_id,
        is_operator,
        service_available,
        master_secret,
        store,
        odyn,
    ) = {
        let s = state.read().await;
        (
            s.peer_cache.clone(),
            s.config.node_wallet.clone(),
            s.config.node_instance_url.clone(),
            s.config.kms_registry_address.clone(),
            s.config.kms_app_id,
            s.is_operator,
            s.service_available,
            s.master_secret.clone(),
            s.store.clone(),
            s.odyn.clone(),
        )
    };
    let peer_count = peer_cache.get_peers(None).await.len();
    let is_init = master_secret.is_initialized().await;
    let init_state = master_secret.init_state().await;
    let synced_from = master_secret.synced_from().await;
    let (total_namespaces, total_keys, total_bytes) = store.stats(now_ms()).await;
    let tee_pubkey_hex = match odyn.get_encryption_public_key_der().await {
        Ok(v) => hex::encode(v),
        Err(_) => String::new(),
    };

    response["node"] = json!({
        "tee_wallet": node_wallet,
        "tee_pubkey": tee_pubkey_hex,
        "node_url": node_url,
        "is_operator": is_operator,
        "service_available": service_available,
        "master_secret": {
            "state": init_state,
            "synced_from": synced_from,
        },
        "master_secret_initialized": is_init,
    });
    response["cluster"] = json!({
        "kms_app_id": kms_app_id,
        "registry_address": kms_registry_address,
        "total_instances": peer_count,
    });
    response["data_store"] = json!({
        "namespaces": total_namespaces,
        "total_keys": total_keys,
        "total_bytes": total_bytes,
    });
    Ok((StatusCode::OK, Json(response)))
}

async fn nonce_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<impl IntoResponse, KmsError> {
    let client_key = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| connect_info.map(|ci| ci.0.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let (nonce_rate_limiter, nonce_store) = {
        let s = state.read().await;
        (s.nonce_rate_limiter.clone(), s.nonce_store.clone())
    };
    if !nonce_rate_limiter.allow(&client_key).await {
        return Err(KmsError::RateLimitExceeded);
    }
    let nonce = nonce_store.issue_nonce().await?;
    Ok((StatusCode::OK, Json(json!({ "nonce": nonce }))))
}

async fn nodes_handler(State(state): State<SharedState>) -> Result<impl IntoResponse, KmsError> {
    let peer_cache = {
        let s = state.read().await;
        s.peer_cache.clone()
    };
    let peers = peer_cache.get_peers(None).await;

    let operators: Vec<Value> = peers
        .into_iter()
        .map(|p| {
            json!({
                "operator": p.tee_wallet_address,
                "instance": {
                    "instance_id": p.instance_id,
                    "app_id": p.app_id,
                    "version_id": p.version_id,
                    "operator": p.operator,
                    "instance_url": p.node_url,
                    "tee_wallet": p.tee_wallet_address,
                    "zk_verified": p.zk_verified,
                    "instance_status": {"value": p.status, "name": if p.status == 0 { "ACTIVE" } else { "NON_ACTIVE" }},
                    "registered_at": p.registered_at,
                },
                "connection": {
                    "in_peer_cache": true,
                    "cached_status": if p.status == 0 { "ACTIVE" } else { "NON_ACTIVE" },
                    "status_endpoint_reachable": p.status_reachable,
                    "status_endpoint_http_code": p.status_http_code,
                    "status_probe_ms": p.status_probe_ms,
                    "status_checked_at_ms": p.status_checked_at_ms,
                }
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(json!({"operators": operators, "count": operators.len()})),
    ))
}

async fn derive_key(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, KmsError> {
    let mut response_headers = HeaderMap::new();
    let (
        service_available,
        service_unavailable_reason,
        config,
        app_registry_cache,
        nonce_store,
        odyn,
        master_secret,
    ) = {
        let s = state.read().await;
        (
            s.service_available,
            s.service_unavailable_reason.clone(),
            s.config.clone(),
            s.app_registry_cache.clone(),
            s.nonce_store.clone(),
            s.odyn.clone(),
            s.master_secret.clone(),
        )
    };
    ensure_service_available(service_available, &service_unavailable_reason)?;
    let auth = authenticate_app(
        &headers,
        &config,
        app_registry_cache.as_ref(),
        nonce_store.as_ref(),
    )
    .await?;
    let expected_app_pubkey = hex::encode(&auth.tee_pubkey);
    let payload = decode_payload(&odyn, &body, Some(&expected_app_pubkey)).await?;

    let path = payload
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing 'path' field".to_string()))?;
    if path.is_empty() {
        return Err(KmsError::ValidationError(
            "Missing 'path' field".to_string(),
        ));
    }
    let context = match payload.get("context") {
        None => "",
        Some(v) => v
            .as_str()
            .ok_or_else(|| KmsError::ValidationError("'context' must be a string".to_string()))?,
    };
    let length = match payload.get("length") {
        None => 32usize,
        Some(v) if v.is_boolean() => {
            return Err(KmsError::ValidationError(
                "'length' must be an integer".to_string(),
            ));
        }
        Some(v) => {
            let parsed = if let Some(u) = v.as_u64() {
                Some(u as usize)
            } else if let Some(i) = v.as_i64() {
                if i >= 0 { Some(i as usize) } else { None }
            } else if let Some(s) = v.as_str() {
                s.parse::<usize>().ok()
            } else {
                None
            };
            parsed.ok_or_else(|| {
                KmsError::ValidationError("'length' must be an integer".to_string())
            })?
        }
    };
    if !(1..=1024).contains(&length) {
        return Err(KmsError::ValidationError(
            "'length' must be in range 1..1024".to_string(),
        ));
    }

    let master_secret = master_secret.get_secret().await?;
    let derived = derive_app_key_extended(&master_secret, auth.app_id, path, context, length)?;
    let derived_b64 = b64.encode(derived);
    maybe_add_app_response_signature(
        &config,
        &odyn,
        auth.signature.as_deref(),
        &mut response_headers,
    )
    .await;
    let plain_resp = json!({
        "app_id": auth.app_id,
        "path": payload.get("path").and_then(|v| v.as_str()).unwrap_or_default(),
        "key": derived_b64,
        "length": length,
    });
    let encrypted =
        encrypt_payload(&odyn, &plain_resp, Some(&hex::encode(&auth.tee_pubkey))).await?;
    Ok((StatusCode::OK, response_headers, Json(encrypted)))
}

async fn get_data_by_path(
    State(state): State<SharedState>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Result<Response, KmsError> {
    get_data_common(state, headers, key).await
}

async fn data_entry_get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, KmsError> {
    if let Some(key) = params.get("key") {
        return get_data_common(state, headers, key.clone()).await;
    }

    let mut response_headers = HeaderMap::new();
    let (
        service_available,
        service_unavailable_reason,
        config,
        app_registry_cache,
        nonce_store,
        store,
        odyn,
    ) = {
        let s = state.read().await;
        (
            s.service_available,
            s.service_unavailable_reason.clone(),
            s.config.clone(),
            s.app_registry_cache.clone(),
            s.nonce_store.clone(),
            s.store.clone(),
            s.odyn.clone(),
        )
    };
    ensure_service_available(service_available, &service_unavailable_reason)?;
    let auth = authenticate_app(
        &headers,
        &config,
        app_registry_cache.as_ref(),
        nonce_store.as_ref(),
    )
    .await?;
    let keys = store.keys(auth.app_id, now_ms()).await;
    maybe_add_app_response_signature(
        &config,
        &odyn,
        auth.signature.as_deref(),
        &mut response_headers,
    )
    .await;
    let payload = json!({
        "app_id": auth.app_id,
        "keys": keys,
        "count": keys.len(),
    });
    let encrypted = encrypt_payload(&odyn, &payload, Some(&hex::encode(&auth.tee_pubkey))).await?;
    Ok((StatusCode::OK, response_headers, Json(encrypted)).into_response())
}

async fn get_data_common(
    state: SharedState,
    headers: HeaderMap,
    key: String,
) -> Result<Response, KmsError> {
    let mut response_headers = HeaderMap::new();
    let (
        service_available,
        service_unavailable_reason,
        config,
        app_registry_cache,
        nonce_store,
        store,
        odyn,
        master_secret,
    ) = {
        let s = state.read().await;
        (
            s.service_available,
            s.service_unavailable_reason.clone(),
            s.config.clone(),
            s.app_registry_cache.clone(),
            s.nonce_store.clone(),
            s.store.clone(),
            s.odyn.clone(),
            s.master_secret.clone(),
        )
    };
    ensure_service_available(service_available, &service_unavailable_reason)?;
    let auth = authenticate_app(
        &headers,
        &config,
        app_registry_cache.as_ref(),
        nonce_store.as_ref(),
    )
    .await?;
    let ns = store.get_namespace(auth.app_id).await;
    let record = {
        let mut ns = ns.write().await;
        ns.get(&key, now_ms())
            .ok_or_else(|| KmsError::NotFound(format!("Key not found: {}", key)))?
    };

    let master_secret = master_secret.get_secret().await?;
    let data_key = derive_data_key(&master_secret, auth.app_id);
    let plaintext = crate::crypto::decrypt_data(&record.encrypted_value, &data_key)?;
    maybe_add_app_response_signature(
        &config,
        &odyn,
        auth.signature.as_deref(),
        &mut response_headers,
    )
    .await;
    let value_b64 = b64.encode(plaintext);
    let updated_at_ms = record.updated_at_ms;
    let payload = json!({
        "app_id": auth.app_id,
        "key": key,
        "value": value_b64,
        "updated_at_ms": updated_at_ms,
    });
    let encrypted = encrypt_payload(&odyn, &payload, Some(&hex::encode(&auth.tee_pubkey))).await?;
    Ok((StatusCode::OK, response_headers, Json(encrypted)).into_response())
}

async fn put_data(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, KmsError> {
    let mut response_headers = HeaderMap::new();
    let (
        service_available,
        service_unavailable_reason,
        config,
        app_registry_cache,
        nonce_store,
        store,
        odyn,
        master_secret,
    ) = {
        let s = state.read().await;
        (
            s.service_available,
            s.service_unavailable_reason.clone(),
            s.config.clone(),
            s.app_registry_cache.clone(),
            s.nonce_store.clone(),
            s.store.clone(),
            s.odyn.clone(),
            s.master_secret.clone(),
        )
    };
    ensure_service_available(service_available, &service_unavailable_reason)?;
    let auth = authenticate_app(
        &headers,
        &config,
        app_registry_cache.as_ref(),
        nonce_store.as_ref(),
    )
    .await?;
    let expected_app_pubkey = hex::encode(&auth.tee_pubkey);
    let payload = decode_payload(&odyn, &body, Some(&expected_app_pubkey)).await?;

    let key = payload
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing 'key' field".to_string()))?
        .to_string();
    let value_b64 = payload
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing 'value' field".to_string()))?;
    let ttl_ms = payload.get("ttl_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let value = b64
        .decode(value_b64)
        .map_err(|_| KmsError::ValidationError("Invalid base64 value".to_string()))?;
    if value.len() > config.max_kv_value_size_bytes {
        return Err(KmsError::ValidationError(format!(
            "Value size exceeds limit {}",
            config.max_kv_value_size_bytes
        )));
    }

    let master_secret = master_secret.get_secret().await?;
    let data_key = derive_data_key(&master_secret, auth.app_id);
    let encrypted_value = crate::crypto::encrypt_data(&value, &data_key)?;
    let now = now_ms();

    tracing::debug!(
        "Stored local record for sync: app_id={} key='{}' updated_at_ms={} ttl_ms={}",
        auth.app_id,
        key,
        now,
        ttl_ms
    );
    let rec = store
        .put_local(
            auth.app_id,
            &key,
            encrypted_value,
            &config.node_wallet,
            now,
            ttl_ms,
        )
        .await;

    maybe_add_app_response_signature(
        &config,
        &odyn,
        auth.signature.as_deref(),
        &mut response_headers,
    )
    .await;
    let updated_at_ms = rec.updated_at_ms;
    let payload = json!({
        "app_id": auth.app_id,
        "key": key,
        "updated_at_ms": updated_at_ms,
    });
    let encrypted = encrypt_payload(&odyn, &payload, Some(&hex::encode(&auth.tee_pubkey))).await?;
    Ok((StatusCode::OK, response_headers, Json(encrypted)))
}

async fn delete_data(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, KmsError> {
    let mut response_headers = HeaderMap::new();
    let (
        service_available,
        service_unavailable_reason,
        config,
        app_registry_cache,
        nonce_store,
        store,
        odyn,
    ) = {
        let s = state.read().await;
        (
            s.service_available,
            s.service_unavailable_reason.clone(),
            s.config.clone(),
            s.app_registry_cache.clone(),
            s.nonce_store.clone(),
            s.store.clone(),
            s.odyn.clone(),
        )
    };
    ensure_service_available(service_available, &service_unavailable_reason)?;
    let auth = authenticate_app(
        &headers,
        &config,
        app_registry_cache.as_ref(),
        nonce_store.as_ref(),
    )
    .await?;
    let expected_app_pubkey = hex::encode(&auth.tee_pubkey);
    let payload = decode_payload(&odyn, &body, Some(&expected_app_pubkey)).await?;
    let key = payload
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KmsError::ValidationError("Missing 'key' field".to_string()))?
        .to_string();

    let ns = store.get_namespace(auth.app_id).await;
    let deleted = ns
        .write()
        .await
        .delete(&key, &config.node_wallet, now_ms())
        .is_some();
    if !deleted {
        return Err(KmsError::NotFound(format!("Key not found: {}", key)));
    }
    maybe_add_app_response_signature(
        &config,
        &odyn,
        auth.signature.as_deref(),
        &mut response_headers,
    )
    .await;
    let payload = json!({
        "app_id": auth.app_id,
        "key": key,
        "deleted": true,
    });
    let encrypted = encrypt_payload(&odyn, &payload, Some(&hex::encode(&auth.tee_pubkey))).await?;
    Ok((StatusCode::OK, response_headers, Json(encrypted)))
}

fn parse_sync_records(data: &Map<String, Value>) -> Vec<(u64, DataRecord)> {
    let mut out = Vec::new();
    for (app_id_str, records_val) in data {
        let Ok(app_id) = app_id_str.parse::<u64>() else {
            continue;
        };
        let Some(records) = records_val.as_array() else {
            continue;
        };
        for rec in records {
            if let Some(parsed) = crate::models::DataRecord::from_sync_value(rec) {
                out.push((app_id, parsed));
            }
        }
    }
    out
}

async fn sync_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, KmsError> {
    let caller_wallet = headers
        .get("x-kms-wallet")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    tracing::info!("Received /sync request from {}", caller_wallet);

    let mut response_headers = HeaderMap::new();
    let (config, nonce_store, peer_cache, master_secret, store, odyn) = {
        let s = state.read().await;
        (
            s.config.clone(),
            s.nonce_store.clone(),
            s.peer_cache.clone(),
            s.master_secret.clone(),
            s.store.clone(),
            s.odyn.clone(),
        )
    };

    if !master_secret.is_initialized().await {
        let err = KmsError::ServiceUnavailable("master secret not initialized".to_string());
        tracing::warn!("Rejecting /sync from {}: {}", caller_wallet, err);
        return Err(err);
    }

    let identity =
        match authenticate_kms_peer(&headers, &config, nonce_store.as_ref(), &config.node_wallet)
            .await
        {
            Ok(identity) => identity,
            Err(err) => {
                tracing::warn!(
                    "Rejecting /sync from {} during peer authentication: {}",
                    caller_wallet,
                    err
                );
                return Err(err);
            }
        };

    let peer = match peer_cache
        .verify_kms_peer(&identity.tee_wallet, config.kms_app_id)
        .await
    {
        Ok(peer) => peer,
        Err(err) => {
            tracing::warn!(
                "Rejecting /sync from {} during peer verification: {}",
                identity.tee_wallet,
                err
            );
            return Err(err);
        }
    };

    let sender_pubkey_from_envelope = body
        .as_object()
        .and_then(|obj| obj.get("sender_tee_pubkey"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let payload = match decode_payload(&odyn, &body, Some(&peer.tee_pubkey)).await {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                "Rejecting /sync from {} during payload decode: {}",
                identity.tee_wallet,
                err
            );
            return Err(err);
        }
    };
    let payload_obj = match payload.as_object() {
        Some(obj) => obj,
        None => {
            let err = KmsError::ValidationError("Invalid sync payload".to_string());
            tracing::warn!("Rejecting /sync from {}: {}", identity.tee_wallet, err);
            return Err(err);
        }
    };

    let sender_wallet = match payload_obj
        .get("sender_wallet")
        .and_then(|v| v.as_str())
        .map(crate::auth::canonical_wallet)
        .transpose()
    {
        Ok(wallet) => wallet,
        Err(err) => {
            tracing::warn!(
                "Rejecting /sync from {}: invalid sender_wallet: {}",
                identity.tee_wallet,
                err
            );
            return Err(err);
        }
    };
    if sender_wallet
        .as_ref()
        .is_some_and(|sender| sender != &identity.tee_wallet)
    {
        let err = KmsError::Unauthorized("sender_wallet does not match PoP signature".to_string());
        tracing::warn!("Rejecting /sync from {}: {}", identity.tee_wallet, err);
        return Err(err);
    }

    let sync_type = payload_obj
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    tracing::info!(
        "Processing /sync request from {}: type={}",
        identity.tee_wallet,
        sync_type
    );

    if let Err(err) =
        verify_sync_request_hmac(&headers, &body, &payload, sync_type, master_secret.as_ref()).await
    {
        tracing::warn!(
            "Rejecting /sync from {} during HMAC verification: {}",
            identity.tee_wallet,
            err
        );
        return Err(err);
    }
    tracing::debug!("KMS PoP verified for {}", identity.tee_wallet);

    let result = match sync_type {
        "delta" => {
            let mut merged = 0usize;
            let mut skipped = 0usize;
            let mut rejected = 0usize;
            let mut total = 0usize;
            let mut skip_reasons: HashMap<&'static str, usize> = HashMap::new();
            if let Some(data) = payload_obj.get("data").and_then(|v| v.as_object()) {
                let records = parse_sync_records(data);
                for (app_id, record) in records {
                    total += 1;
                    let record_key = record.key.clone();
                    let updated_at_ms = record.updated_at_ms;
                    if let Err(reason) = validate_incoming_record_with_context(
                        config.in_enclave,
                        config.max_kv_value_size_bytes,
                        config.max_clock_skew_ms,
                        master_secret.as_ref(),
                        app_id,
                        &record,
                    )
                    .await
                    {
                        rejected += 1;
                        tracing::warn!(
                            "Incoming delta record from {} rejected: app_id={} key='{}' updated_at_ms={} reason={}",
                            identity.tee_wallet,
                            app_id,
                            record_key,
                            updated_at_ms,
                            reason
                        );
                        continue;
                    }
                    let outcome = store.merge_record_with_outcome(app_id, record).await;
                    if outcome.merged() {
                        merged += 1;
                    } else {
                        skipped += 1;
                        *skip_reasons.entry(outcome.reason()).or_default() += 1;
                        tracing::info!(
                            "Incoming delta record from {} not applied: app_id={} key='{}' updated_at_ms={} reason={}",
                            identity.tee_wallet,
                            app_id,
                            record_key,
                            updated_at_ms,
                            outcome.reason()
                        );
                    }
                }
            }
            tracing::info!(
                "Processed delta sync from {}: total={} merged={} skipped={} rejected={}",
                identity.tee_wallet,
                total,
                merged,
                skipped,
                rejected
            );
            if !skip_reasons.is_empty() {
                tracing::info!(
                    "Delta sync from {} skip reasons: {:?}",
                    identity.tee_wallet,
                    skip_reasons
                );
            }
            json!({
                "status":"ok",
                "total": total,
                "merged": merged,
                "skipped": skipped,
                "rejected": rejected,
                "skip_reasons": skip_reasons,
            })
        }
        "snapshot_request" => {
            let snapshot = store.full_snapshot(now_ms()).await;
            let record_count = snapshot.values().map(std::vec::Vec::len).sum::<usize>();
            tracing::info!(
                "Serving snapshot to {}: {} record(s) across {} app(s)",
                identity.tee_wallet,
                record_count,
                snapshot.len()
            );
            json!({
                "status":"ok",
                "data": crate::sync::serialize_deltas(&snapshot),
            })
        }
        "master_secret_request" => {
            let ecdh_pubkey_hex = match payload_obj.get("ecdh_pubkey").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => {
                    let err = KmsError::ValidationError(
                        "Sealed ECDH pubkey required for master secret exchange".to_string(),
                    );
                    tracing::warn!(
                        "Rejecting master_secret_request from {}: {}",
                        identity.tee_wallet,
                        err
                    );
                    return Err(err);
                }
            };
            let peer_pubkey = match hex::decode(ecdh_pubkey_hex) {
                Ok(v) => v,
                Err(_) => {
                    let err = KmsError::ValidationError("Invalid ecdh_pubkey hex".to_string());
                    tracing::warn!(
                        "Rejecting master_secret_request from {}: {}",
                        identity.tee_wallet,
                        err
                    );
                    return Err(err);
                }
            };
            let secret = match master_secret.get_secret().await {
                Ok(secret) => secret,
                Err(err) => {
                    tracing::warn!(
                        "Failed to serve master_secret_request to {}: {}",
                        identity.tee_wallet,
                        err
                    );
                    return Err(err);
                }
            };
            let sealed = match seal_master_secret(&secret.bytes, &peer_pubkey) {
                Ok(sealed) => sealed,
                Err(err) => {
                    tracing::warn!(
                        "Failed to seal master secret for {}: {}",
                        identity.tee_wallet,
                        err
                    );
                    return Err(err);
                }
            };
            tracing::info!("Serving sealed master secret to {}", identity.tee_wallet);
            json!({"status":"ok","sealed":sealed})
        }
        _ => {
            let err = KmsError::ValidationError(format!("Unknown sync type: {}", sync_type));
            tracing::warn!("Rejecting /sync from {}: {}", identity.tee_wallet, err);
            return Err(err);
        }
    };

    maybe_add_peer_response_signature(&config, &odyn, &identity.signature, &mut response_headers)
        .await;

    let receiver_pubkey = sender_pubkey_from_envelope.unwrap_or(peer.tee_pubkey);
    let response_body = match encrypt_payload(&odyn, &result, Some(&receiver_pubkey)).await {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!(
                "Failed to encrypt /sync response for {}: {}",
                identity.tee_wallet,
                err
            );
            return Err(err);
        }
    };

    Ok((StatusCode::OK, response_headers, Json(response_body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::AppState;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    async fn build_router(nonce_rate_limit_per_minute: u64) -> Router {
        let cfg = Config {
            in_enclave: false,
            node_url: "http://127.0.0.1:1".to_string(),
            nonce_rate_limit_per_minute,
            ..Config::default()
        };
        let state = Arc::new(RwLock::new(AppState::new(cfg).await));
        app_router(state)
    }

    async fn response_json(resp: Response) -> Value {
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = build_router(30).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["status"], "healthy");
    }

    #[tokio::test]
    async fn test_nonce_returns_base64_16_bytes() {
        let app = build_router(30).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        let nonce = json["nonce"].as_str().unwrap();
        let decoded = b64.decode(nonce.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 16);
    }

    #[tokio::test]
    async fn test_nonce_rate_limit_enforced() {
        let app = build_router(1).await;
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .uri("/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let json = response_json(second).await;
        assert_eq!(json["code"], "rate_limited");
    }

    #[tokio::test]
    async fn test_kms_derive_blocked_when_service_unavailable() {
        let app = build_router(30).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/kms/derive")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"path":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = response_json(response).await;
        assert_eq!(json["code"], "service_unavailable");
    }

    #[tokio::test]
    async fn test_sync_requires_master_secret_initialization() {
        let app = build_router(30).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sync")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"type":"delta","sender_wallet":"0x0","data":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = response_json(response).await;
        assert_eq!(json["code"], "service_unavailable");
    }

    #[tokio::test]
    async fn test_delta_sync_requires_hmac_even_without_cached_state_sync_key() {
        let master_secret = MasterSecretManager::new();
        master_secret.initialize_generated([9u8; 32]).await;

        let err = verify_sync_request_hmac(
            &HeaderMap::new(),
            &json!({"type":"delta","sender_wallet":"0x0","data":{}}),
            &json!({"type":"delta","sender_wallet":"0x0","data":{}}),
            "delta",
            &master_secret,
        )
        .await
        .unwrap_err();

        match err {
            KmsError::Unauthorized(message) => assert_eq!(message, "Missing HMAC signature"),
            other => panic!("expected unauthorized error, got {}", other),
        }
    }

    #[tokio::test]
    async fn test_master_secret_request_allows_missing_hmac() {
        let master_secret = MasterSecretManager::new();
        master_secret.initialize_generated([9u8; 32]).await;

        verify_sync_request_hmac(
            &HeaderMap::new(),
            &json!({"type":"master_secret_request"}),
            &json!({"type":"master_secret_request"}),
            "master_secret_request",
            &master_secret,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_nodes_endpoint_returns_empty_list_by_default() {
        let app = build_router(30).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/nodes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["count"], 0);
        assert!(json["operators"].as_array().unwrap().is_empty());
    }
}
