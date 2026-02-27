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
use crate::crypto::{derive_app_key_extended, derive_data_key, seal_master_secret};
use crate::error::KmsError;
use crate::models::{DataRecord, VectorClock};
use crate::state::SharedState;
use crate::sync::{canonical_json, now_ms, validate_incoming_record, verify_hmac_hex};

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

async fn ensure_service_available(state: &crate::state::AppState) -> Result<(), KmsError> {
    if state.service_available {
        return Ok(());
    }
    Err(KmsError::ServiceUnavailable(
        if state.service_unavailable_reason.is_empty() {
            "Service unavailable".to_string()
        } else {
            state.service_unavailable_reason.clone()
        },
    ))
}

async fn decrypt_envelope_payload(
    state: &crate::state::AppState,
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

    let plaintext = state
        .odyn
        .decrypt(nonce, sender_pub, encrypted_data)
        .await?;
    serde_json::from_str(&plaintext)
        .map_err(|e| KmsError::ValidationError(format!("Invalid decrypted JSON: {}", e)))
}

async fn decode_payload(
    state: &crate::state::AppState,
    body: &Value,
    expected_sender_pubkey_hex: Option<&str>,
) -> Result<Value, KmsError> {
    if is_envelope(body) {
        return decrypt_envelope_payload(state, body, expected_sender_pubkey_hex).await;
    }
    Err(KmsError::ValidationError(
        "Request must be E2E encrypted. Plaintext fallback is disabled.".to_string(),
    ))
}

async fn encrypt_payload(
    state: &crate::state::AppState,
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
    let sender_pubkey = hex::encode(state.odyn.get_encryption_public_key_der().await?);
    let encrypted = state.odyn.encrypt(&plaintext, receiver_pubkey_hex).await?;
    Ok(json!({
        "sender_tee_pubkey": sender_pubkey,
        "nonce": normalize_hex(&encrypted.nonce),
        "encrypted_data": normalize_hex(&encrypted.encrypted_data),
    }))
}

async fn maybe_add_app_response_signature(
    state: &crate::state::AppState,
    client_sig: Option<&str>,
    response_headers: &mut HeaderMap,
) {
    if let Some(client_sig) = client_sig {
        let Ok(current_wallet) = current_node_signing_wallet(&state.config, &state.odyn).await
        else {
            return;
        };
        let msg = format!("NovaKMS:Response:{}:{}", client_sig, current_wallet);
        if let Some(value) = sign_message_for_node(&state.config, &state.odyn, &msg)
            .await
            .ok()
            .and_then(|(sig, _)| sig.parse().ok())
        {
            response_headers.insert("X-KMS-Response-Signature", value);
        }
    }
}

async fn maybe_add_peer_response_signature(
    state: &crate::state::AppState,
    caller_sig: &str,
    response_headers: &mut HeaderMap,
) {
    let Ok(current_wallet) = current_node_signing_wallet(&state.config, &state.odyn).await else {
        return;
    };
    let msg = format!("NovaKMS:Response:{}:{}", caller_sig, current_wallet);
    if let Some(value) = sign_message_for_node(&state.config, &state.odyn, &msg)
        .await
        .ok()
        .and_then(|(sig, _)| sig.parse().ok())
    {
        response_headers.insert("X-KMS-Peer-Signature", value);
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
        node_wallet,
        node_url,
        kms_registry_address,
        kms_app_id,
        peer_count,
        is_operator,
        is_init,
        init_state,
        synced_from,
        service_available,
        total_namespaces,
        total_keys,
        total_bytes,
        tee_pubkey_hex,
    ) = {
        let s = state.read().await;
        let peer_count = s.peer_cache.get_peers(None).await.len();
        let is_init = s.master_secret.is_initialized().await;
        let init_state = s.master_secret.init_state().await;
        let synced_from = s.master_secret.synced_from().await;
        let (ns, keys, bytes) = s.store.stats(now_ms()).await;
        let tee_pubkey_hex = match s.odyn.get_encryption_public_key_der().await {
            Ok(v) => hex::encode(v),
            Err(_) => String::new(),
        };
        (
            s.config.node_wallet.clone(),
            s.config.node_instance_url.clone(),
            s.config.kms_registry_address.clone(),
            s.config.kms_app_id,
            peer_count,
            s.is_operator,
            is_init,
            init_state,
            synced_from,
            s.service_available,
            ns,
            keys,
            bytes,
            tee_pubkey_hex,
        )
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

    let nonce = {
        let s = state.read().await;
        if !s.nonce_rate_limiter.allow(&client_key).await {
            return Err(KmsError::RateLimitExceeded);
        }
        s.nonce_store.issue_nonce().await?
    };
    Ok((StatusCode::OK, Json(json!({ "nonce": nonce }))))
}

async fn nodes_handler(State(state): State<SharedState>) -> Result<impl IntoResponse, KmsError> {
    let peers = {
        let s = state.read().await;
        s.peer_cache.get_peers(None).await
    };

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
    let (auth, payload, derived_b64, length) = {
        let s = state.read().await;
        ensure_service_available(&s).await?;
        let auth =
            authenticate_app(&headers, &s.config, &s.app_registry_cache, &s.nonce_store).await?;
        let expected_app_pubkey = hex::encode(&auth.tee_pubkey);
        let payload = decode_payload(&s, &body, Some(&expected_app_pubkey)).await?;

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
            Some(v) => v.as_str().ok_or_else(|| {
                KmsError::ValidationError("'context' must be a string".to_string())
            })?,
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

        let master_secret = s.master_secret.get_secret().await?;
        let derived = derive_app_key_extended(&master_secret, auth.app_id, path, context, length)?;
        let derived_b64 = b64.encode(derived);
        (auth, payload, derived_b64, length)
    };

    {
        let s = state.read().await;
        maybe_add_app_response_signature(&s, auth.signature.as_deref(), &mut response_headers)
            .await;
        let plain_resp = json!({
            "app_id": auth.app_id,
            "path": payload.get("path").and_then(|v| v.as_str()).unwrap_or_default(),
            "key": derived_b64,
            "length": length,
        });
        let encrypted =
            encrypt_payload(&s, &plain_resp, Some(&hex::encode(&auth.tee_pubkey))).await?;
        Ok((StatusCode::OK, response_headers, Json(encrypted)))
    }
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
    let (auth, keys) = {
        let s = state.read().await;
        ensure_service_available(&s).await?;
        let auth =
            authenticate_app(&headers, &s.config, &s.app_registry_cache, &s.nonce_store).await?;
        let keys = s.store.keys(auth.app_id, now_ms()).await;
        maybe_add_app_response_signature(&s, auth.signature.as_deref(), &mut response_headers)
            .await;
        (auth, keys)
    };

    let s = state.read().await;
    let payload = json!({
        "app_id": auth.app_id,
        "keys": keys,
        "count": keys.len(),
    });
    let encrypted = encrypt_payload(&s, &payload, Some(&hex::encode(&auth.tee_pubkey))).await?;
    Ok((StatusCode::OK, response_headers, Json(encrypted)).into_response())
}

async fn get_data_common(
    state: SharedState,
    headers: HeaderMap,
    key: String,
) -> Result<Response, KmsError> {
    let mut response_headers = HeaderMap::new();
    let (auth, value_b64, updated_at_ms) = {
        let s = state.read().await;
        ensure_service_available(&s).await?;
        let auth =
            authenticate_app(&headers, &s.config, &s.app_registry_cache, &s.nonce_store).await?;
        let ns = s.store.get_namespace(auth.app_id).await;
        let mut ns = ns.write().await;
        let record = ns
            .get(&key, now_ms())
            .ok_or_else(|| KmsError::NotFound(format!("Key not found: {}", key)))?;

        let master_secret = s.master_secret.get_secret().await?;
        let data_key = derive_data_key(&master_secret, auth.app_id);
        let plaintext = crate::crypto::decrypt_data(&record.encrypted_value, &data_key)?;
        maybe_add_app_response_signature(&s, auth.signature.as_deref(), &mut response_headers)
            .await;
        (auth, b64.encode(plaintext), record.updated_at_ms)
    };

    let s = state.read().await;
    let payload = json!({
        "app_id": auth.app_id,
        "key": key,
        "value": value_b64,
        "updated_at_ms": updated_at_ms,
    });
    let encrypted = encrypt_payload(&s, &payload, Some(&hex::encode(&auth.tee_pubkey))).await?;
    Ok((StatusCode::OK, response_headers, Json(encrypted)).into_response())
}

async fn put_data(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, KmsError> {
    let mut response_headers = HeaderMap::new();
    let (auth, key, updated_at_ms) = {
        let s = state.read().await;
        ensure_service_available(&s).await?;
        let auth =
            authenticate_app(&headers, &s.config, &s.app_registry_cache, &s.nonce_store).await?;
        let expected_app_pubkey = hex::encode(&auth.tee_pubkey);
        let payload = decode_payload(&s, &body, Some(&expected_app_pubkey)).await?;

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
        if value.len() > s.config.max_kv_value_size_bytes {
            return Err(KmsError::ValidationError(format!(
                "Value size exceeds limit {}",
                s.config.max_kv_value_size_bytes
            )));
        }

        let master_secret = s.master_secret.get_secret().await?;
        let data_key = derive_data_key(&master_secret, auth.app_id);
        let encrypted_value = crate::crypto::encrypt_data(&value, &data_key)?;
        let now = now_ms();

        let mut vc = VectorClock::new();
        vc.increment(&s.config.node_wallet);

        let rec = DataRecord {
            key: key.clone(),
            encrypted_value,
            version: vc,
            updated_at_ms: now,
            tombstone: false,
            ttl_ms,
        };
        let ns = s.store.get_namespace(auth.app_id).await;
        ns.write().await.put(&key, rec);

        maybe_add_app_response_signature(&s, auth.signature.as_deref(), &mut response_headers)
            .await;
        (auth, key, now)
    };

    let s = state.read().await;
    let payload = json!({
        "app_id": auth.app_id,
        "key": key,
        "updated_at_ms": updated_at_ms,
    });
    let encrypted = encrypt_payload(&s, &payload, Some(&hex::encode(&auth.tee_pubkey))).await?;
    Ok((StatusCode::OK, response_headers, Json(encrypted)))
}

async fn delete_data(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, KmsError> {
    let mut response_headers = HeaderMap::new();
    let (auth, key) = {
        let s = state.read().await;
        ensure_service_available(&s).await?;
        let auth =
            authenticate_app(&headers, &s.config, &s.app_registry_cache, &s.nonce_store).await?;
        let expected_app_pubkey = hex::encode(&auth.tee_pubkey);
        let payload = decode_payload(&s, &body, Some(&expected_app_pubkey)).await?;
        let key = payload
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KmsError::ValidationError("Missing 'key' field".to_string()))?
            .to_string();

        let ns = s.store.get_namespace(auth.app_id).await;
        let deleted = ns
            .write()
            .await
            .delete(&key, &s.config.node_wallet, now_ms())
            .is_some();
        if !deleted {
            return Err(KmsError::NotFound(format!("Key not found: {}", key)));
        }
        maybe_add_app_response_signature(&s, auth.signature.as_deref(), &mut response_headers)
            .await;
        (auth, key)
    };

    let s = state.read().await;
    let payload = json!({
        "app_id": auth.app_id,
        "key": key,
        "deleted": true,
    });
    let encrypted = encrypt_payload(&s, &payload, Some(&hex::encode(&auth.tee_pubkey))).await?;
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
    let mut response_headers = HeaderMap::new();
    let (response_body, response_receiver_pubkey) = {
        let s = state.read().await;
        if !s.master_secret.is_initialized().await {
            return Err(KmsError::ServiceUnavailable(
                "master secret not initialized".to_string(),
            ));
        }
        let identity =
            authenticate_kms_peer(&headers, &s.config, &s.nonce_store, &s.config.node_wallet)
                .await?;
        let peer = s
            .peer_cache
            .verify_kms_peer(&identity.tee_wallet, s.config.kms_app_id)
            .await?;

        let sender_pubkey_from_envelope = body
            .as_object()
            .and_then(|obj| obj.get("sender_tee_pubkey"))
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let payload = decode_payload(&s, &body, Some(&peer.tee_pubkey)).await?;
        let payload_obj = payload
            .as_object()
            .ok_or_else(|| KmsError::ValidationError("Invalid sync payload".to_string()))?;

        let sender_wallet = payload_obj
            .get("sender_wallet")
            .and_then(|v| v.as_str())
            .map(crate::auth::canonical_wallet)
            .transpose()?;
        if sender_wallet.is_some_and(|sender| sender != identity.tee_wallet) {
            return Err(KmsError::Unauthorized(
                "sender_wallet does not match PoP signature".to_string(),
            ));
        }

        let sync_type = payload_obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        match (s.sync_key, sync_type) {
            (Some(sync_key), st) if st != "master_secret_request" => {
                let sig = headers
                    .get("x-sync-signature")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| KmsError::Unauthorized("Missing HMAC signature".to_string()))?;
                let signed_payload = if is_envelope(&body) { &body } else { &payload };
                let canonical = canonical_json(signed_payload)?;
                if !verify_hmac_hex(&sync_key, canonical.as_bytes(), sig) {
                    return Err(KmsError::Unauthorized("Invalid HMAC signature".to_string()));
                }
            }
            _ => {}
        }

        let result = match sync_type {
            "delta" => {
                let mut merged = 0usize;
                if let Some(data) = payload_obj.get("data").and_then(|v| v.as_object()) {
                    let records = parse_sync_records(data);
                    for (app_id, record) in records {
                        if !validate_incoming_record(&state, app_id, &record).await {
                            continue;
                        }
                        if s.store.merge_record(app_id, record).await {
                            merged += 1;
                        }
                    }
                }
                json!({"status":"ok","merged":merged})
            }
            "snapshot_request" => {
                let snapshot = s.store.full_snapshot(now_ms()).await;
                json!({
                    "status":"ok",
                    "data": crate::sync::serialize_deltas(&snapshot),
                })
            }
            "master_secret_request" => {
                let ecdh_pubkey_hex = payload_obj
                    .get("ecdh_pubkey")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        KmsError::ValidationError(
                            "Sealed ECDH pubkey required for master secret exchange".to_string(),
                        )
                    })?;
                let peer_pubkey = hex::decode(ecdh_pubkey_hex).map_err(|_| {
                    KmsError::ValidationError("Invalid ecdh_pubkey hex".to_string())
                })?;
                let secret = s.master_secret.get_secret().await?;
                let sealed = seal_master_secret(&secret.bytes, &peer_pubkey)?;
                json!({"status":"ok","sealed":sealed})
            }
            _ => {
                return Err(KmsError::ValidationError(format!(
                    "Unknown sync type: {}",
                    sync_type
                )));
            }
        };

        maybe_add_peer_response_signature(&s, &identity.signature, &mut response_headers).await;

        let receiver_pubkey = sender_pubkey_from_envelope.unwrap_or(peer.tee_pubkey);
        let encrypted = encrypt_payload(&s, &result, Some(&receiver_pubkey)).await?;
        (encrypted, receiver_pubkey)
    };

    let _ = response_receiver_pubkey;
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
        let mut cfg = Config::default();
        cfg.in_enclave = false;
        cfg.node_url = "http://127.0.0.1:1".to_string();
        cfg.nonce_rate_limit_per_minute = nonce_rate_limit_per_minute;
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
