use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post, put, delete},
    Json, Router,
};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use tokio::sync::RwLock;

use crate::state::SharedState;
use crate::error::KmsError;
use crate::models::{DataRecord, VectorClock};

pub fn app_router(state: SharedState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        .route("/nonce", get(nonce_handler))
        .route("/kms/data", get(get_data))
        .route("/kms/data", put(put_data))
        .route("/kms/data", delete(delete_data))
        .route("/sync", post(not_implemented_handler))
        .with_state(state)
}

async fn health_handler() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

async fn status_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let s = state.read().await;
    let up = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - s.startup_time;
    
    let is_init = s.master_secret.get_secret().await.is_ok();
    
    (StatusCode::OK, Json(json!({
        "status": "online",
        "version": "1.0.0",
        "network": "nova",
        "uptime": up,
        "mode": if s.config.in_enclave { "enclave" } else { "dev" },
        "wallet": s.config.node_wallet,
        "master_secret_initialized": is_init
    })))
}

async fn nonce_handler() -> impl IntoResponse {
    let nonce = hex::encode(crate::crypto::encrypt_data(b"nonce", &[0; 32]).unwrap_or_default());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    (StatusCode::OK, Json(json!({
        "nonce": nonce.chars().take(32).collect::<String>(),
        "timestamp": now
    })))
}

async fn get_data(State(state): State<SharedState>, headers: HeaderMap, axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>) -> Result<impl IntoResponse, KmsError> {
    let s = state.read().await;
    let auth = crate::auth::authenticate_app(&headers, &s.config, &s.registry, &s.nonce_store).await?;
    
    let key = params.get("key").ok_or_else(|| KmsError::ValidationError("Missing key parameter".to_string()))?;
    
    let mut store = s.store.get_namespace(auth.app_id).await;
    let mut ns = store.write().await;
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() * 1000;
    
    let record_opt = ns.get(key, current_time);
    
    if let Some(record) = record_opt {
        if record.tombstone {
            return Err(KmsError::NotFound(format!("Key not found or deleted: {}", key)));
        }
        
        let master_secret = s.master_secret.get_secret().await?;
        let data_key = crate::crypto::derive_data_key(&master_secret, auth.app_id);
        
        let plaintext = crate::crypto::decrypt_data(&record.encrypted_value, &data_key)?;
        
        let val_b64 = b64.encode(plaintext);
        
        // Mocking E2E response encryption since odyn client integration requires full payload
        let resp = json!({
            "app_id": auth.app_id,
            "key": key,
            "value": val_b64,
            "version": record.version.get(&s.config.node_wallet),
            "updated_at_ms": record.updated_at_ms
        });
        
        Ok((StatusCode::OK, Json(resp)))
    } else {
        Err(KmsError::NotFound(format!("Key not found: {}", key)))
    }
}

async fn put_data(State(state): State<SharedState>, headers: HeaderMap, Json(body): Json<Value>) -> Result<impl IntoResponse, KmsError> {
    let s = state.read().await;
    let auth = crate::auth::authenticate_app(&headers, &s.config, &s.registry, &s.nonce_store).await?;
    
    // Simplification for skeleton:
    let key = body.get("key").and_then(|v| v.as_str()).ok_or_else(|| KmsError::ValidationError("Missing key".to_string()))?;
    let val_b64 = body.get("value").and_then(|v| v.as_str()).ok_or_else(|| KmsError::ValidationError("Missing value".to_string()))?;
    
    let plaintext = b64.decode(val_b64).map_err(|_| KmsError::ValidationError("Invalid base64".to_string()))?;
    
    let master_secret = s.master_secret.get_secret().await?;
    let data_key = crate::crypto::derive_data_key(&master_secret, auth.app_id);
    
    let ciphertext = crate::crypto::encrypt_data(&plaintext, &data_key)?;
    
    let mut store = s.store.get_namespace(auth.app_id).await;
    let mut ns = store.write().await;
    
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() * 1000;
    
    let mut vc = VectorClock::new();
    vc.increment(&s.config.node_wallet);
    
    let ttl = body.get("ttl_ms").and_then(|v| v.as_u64());
    
    let record = DataRecord {
        key: key.to_string(),
        encrypted_value: ciphertext,
        version: vc,
        updated_at_ms: current_time,
        tombstone: false,
        ttl_ms: ttl,
    };
    
    ns.put(key, record.clone());
    
    Ok((StatusCode::OK, Json(json!({
        "app_id": auth.app_id,
        "key": key,
        "updated_at_ms": current_time
    }))))
}

async fn delete_data(State(state): State<SharedState>, headers: HeaderMap, Json(body): Json<Value>) -> Result<impl IntoResponse, KmsError> {
    let s = state.read().await;
    let auth = crate::auth::authenticate_app(&headers, &s.config, &s.registry, &s.nonce_store).await?;
    
    let key = body.get("key").and_then(|v| v.as_str()).ok_or_else(|| KmsError::ValidationError("Missing key".to_string()))?;
    
    let mut store = s.store.get_namespace(auth.app_id).await;
    let mut ns = store.write().await;
    
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() * 1000;
    ns.delete(key, &s.config.node_wallet, current_time);
    
    Ok((StatusCode::OK, Json(json!({
        "app_id": auth.app_id,
        "key": key,
        "deleted": true
    }))))
}

async fn not_implemented_handler() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"detail": "Not implemented"})))
}
