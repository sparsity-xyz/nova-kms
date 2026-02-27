use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    response::Response,
    routing::{delete, get, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

use crate::auth::{
    authenticate_app, authenticate_kms_peer, current_node_signing_wallet, sign_message_for_node,
};
use crate::crypto::{derive_app_key_extended, derive_data_key, seal_master_secret};
use crate::error::KmsError;
use crate::models::{DataRecord, VectorClock};
use crate::state::SharedState;
use crate::sync::{canonical_json, now_ms, verify_hmac_hex};

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
    if let Some(expected) = expected_sender_pubkey_hex
        && !expected.is_empty()
        && normalize_hex(expected) != normalize_hex(sender_pub)
    {
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
    if state.config.allow_plaintext_fallback() {
        return Ok(body.clone());
    }
    Err(KmsError::ValidationError(
        "Request must be E2E encrypted".to_string(),
    ))
}

async fn encrypt_payload(
    state: &crate::state::AppState,
    payload: &Value,
    receiver_pubkey_hex: Option<&str>,
) -> Result<Value, KmsError> {
    if let Some(receiver_pubkey_hex) = receiver_pubkey_hex
        && !receiver_pubkey_hex.is_empty()
    {
        let plaintext = canonical_json(payload)?;
        let sender_pubkey = hex::encode(state.odyn.get_encryption_public_key_der().await?);
        let encrypted = state.odyn.encrypt(&plaintext, receiver_pubkey_hex).await?;
        return Ok(json!({
            "sender_tee_pubkey": sender_pubkey,
            "nonce": normalize_hex(&encrypted.nonce),
            "encrypted_data": normalize_hex(&encrypted.encrypted_data),
        }));
    }

    if state.config.allow_plaintext_fallback() {
        return Ok(payload.clone());
    }
    Err(KmsError::ValidationError(
        "Receiver teePubkey required for response encryption".to_string(),
    ))
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
        if let Ok((sig, _)) = sign_message_for_node(&state.config, &state.odyn, &msg).await
            && let Ok(value) = sig.parse()
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
    if let Ok((sig, _)) = sign_message_for_node(&state.config, &state.odyn, &msg).await
        && let Ok(value) = sig.parse()
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

async fn nonce_handler(State(state): State<SharedState>) -> Result<impl IntoResponse, KmsError> {
    let nonce = {
        let s = state.read().await;
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
    let (auth, payload, derived_b64) = {
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
        let context = payload
            .get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let length = payload.get("length").and_then(|v| v.as_u64()).unwrap_or(32) as usize;

        let master_secret = s.master_secret.get_secret().await?;
        let derived = derive_app_key_extended(&master_secret, auth.app_id, path, context, length)?;
        let derived_b64 = b64.encode(derived);
        (auth, payload, derived_b64)
    };

    {
        let s = state.read().await;
        maybe_add_app_response_signature(&s, auth.signature.as_deref(), &mut response_headers)
            .await;
        let plain_resp = json!({
            "app_id": auth.app_id,
            "path": payload.get("path").and_then(|v| v.as_str()).unwrap_or_default(),
            "key": derived_b64,
            "length": payload.get("length").and_then(|v| v.as_u64()).unwrap_or(32),
        });
        let encrypted =
            encrypt_payload(&s, &plain_resp, Some(&hex::encode(&auth.tee_pubkey))).await?;
        return Ok((StatusCode::OK, response_headers, Json(encrypted)));
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

        if let Some(sender_wallet) = payload_obj.get("sender_wallet").and_then(|v| v.as_str()) {
            if crate::auth::canonical_wallet(sender_wallet)? != identity.tee_wallet {
                return Err(KmsError::Unauthorized(
                    "sender_wallet does not match PoP signature".to_string(),
                ));
            }
        }

        let sync_type = payload_obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if let Some(sync_key) = s.sync_key
            && sync_type != "master_secret_request"
        {
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

        let result = match sync_type {
            "delta" => {
                let mut merged = 0usize;
                if let Some(data) = payload_obj.get("data").and_then(|v| v.as_object()) {
                    let records = parse_sync_records(data);
                    for (app_id, record) in records {
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
