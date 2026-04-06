use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use sqlx::{Row, SqlitePool, sqlite::SqliteQueryResult};
use tracing::{info, error, debug, warn};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Verifier, VerifyingKey, Signature, SigningKey, Signer};
use std::path::PathBuf;
use std::fs;
use std::sync::Arc;

use crate::models::{SignedRequest, SignedResult, UnsignedPayload, Test, SignedResponse};
use crate::config::Config;

// =========================================================
// HELPER: Sign Outgoing Server Response
// =========================================================
fn sign_response(
    payload: serde_json::Value,
    config: &Arc<Config>,
) -> Result<SignedResponse, Box<dyn std::error::Error>> {
    let key_dir = PathBuf::from(config.key.key_path.as_deref().unwrap_or(""));
    let priv_file = config.key.private_key.as_deref().unwrap_or("scmserver.key");
    let priv_path = key_dir.join(priv_file);

    let priv_base64 = fs::read_to_string(&priv_path)?;
    let priv_bytes = general_purpose::STANDARD.decode(priv_base64.trim())?;
    
    let key_array: [u8; 32] = priv_bytes.try_into().map_err(|_| "Invalid private key length")?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let payload_bytes = bincode::serialize(&payload)?;

    let signature = signing_key.sign(&payload_bytes);
    let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());

    debug!("Server successfully signed outgoing response envelope.");

    Ok(SignedResponse {
        payload,
        signature: signature_base64,
    })
}


// ... existing imports ...

// =========================================================
// HANDLER: Heartbeat and Registration (POST /send)
// =========================================================
pub async fn send(
    Extension(pool): Extension<SqlitePool>,
    Extension(config): Extension<Arc<Config>>,
    Json(signed_req): Json<SignedRequest<UnsignedPayload>>,
) -> impl IntoResponse {
    let payload = &signed_req.payload;
    let mut response_data = serde_json::json!({});
    let now = chrono::Utc::now().to_string();

    info!("Connection received from agent: {} (IP: {})", payload.hostname, payload.ip);

    let id = match payload.id.parse::<i64>() {
        Ok(val) => val,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid ID format"}))).into_response()
    };
    // 1. REGISTRATION (ID 0)
    if id == 0 {
        info!("Processing NEW agent registration for: {}", payload.hostname);
        
        let res = sqlx::query(
            r#"INSERT INTO systems (key, name, ver, os, ip, arch, status) 
               VALUES (?, ?, ?, ?, ?, ?, 'pending')"#
        )
        .bind(&payload.public_key)
        .bind(&payload.hostname)
        .bind(&payload.ver)
        .bind(&payload.os)
        .bind(&payload.ip)
        .bind(&payload.arch)
        .execute(&pool).await;

        match res {
            Ok(r) => {
                let new_id = r.last_insert_rowid();
                info!("Registration PENDING: Assigned ID {} to agent {}", new_id, payload.hostname);
                
                response_data = serde_json::json!({
                    "status": "pending", 
                    "id": new_id,
                    "command": "REGISTER"
                });
            },
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
        }
    } else {
        // 2. HEARTBEAT: Fetch key and status without the '?' operator
        let (db_pubkey, status) = match sqlx::query("SELECT key, status FROM systems WHERE id = ?")
            .bind(id)
            .fetch_optional(&pool)
            .await 
        {
            Ok(Some(row)) => {
                // Using .get() because we know these columns exist in our schema
                let k: String = row.get("key");
                let s: Option<String> = row.get("status");
                (k, s)
            },
            Ok(None) => {
                warn!("Identity Check: Agent ID {} not found.", id);
                return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Agent not found"}))).into_response()
            },
            Err(e) => {
                error!("DB Error: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response()
            }
        };

        // --- AUTHENTICATION ---
        let pub_key_bytes: [u8; 32] = match general_purpose::STANDARD.decode(&db_pubkey) {
            Ok(bytes) => bytes.try_into().unwrap_or([0u8; 32]),
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Key corruption"}))).into_response(),
        };

        let sig_bytes: [u8; 64] = match general_purpose::STANDARD.decode(&signed_req.signature) {
            Ok(bytes) => bytes.try_into().unwrap_or([0u8; 64]),
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Bad signature"}))).into_response(),
        };

        let verifier = VerifyingKey::from_bytes(&pub_key_bytes).unwrap();
        let payload_bytes = bincode::serialize(payload).unwrap();

        if verifier.verify(&payload_bytes, &Signature::from_bytes(&sig_bytes)).is_err() {
            error!("SECURITY ALERT: Invalid signature from Agent ID {}!", id);
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid Signature"}))).into_response();
        }

        // 3. PROCESS BASED ON STATUS
        match status.as_deref().unwrap_or("pending") {
            "approved" | "active" => {
                let mut tx = pool.begin().await.unwrap();
                let _ = sqlx::query("UPDATE systems SET name=?, ver=?, os=?, ip=?, arch=?, status='active', last_seen = CURRENT_TIMESTAMP  WHERE id=?")
                    .bind(&payload.hostname).bind(&payload.ver).bind(&payload.os).bind(&payload.ip).bind(&payload.arch).bind(id)
                    .execute(&mut *tx).await;

                let tests: Vec<Test> = sqlx::query_as::<_, Test>(
                    "SELECT t.* FROM commands c JOIN tests t ON c.test_id = t.id WHERE c.system_id = ? LIMIT 20"
                ).bind(id).fetch_all(&mut *tx).await.unwrap_or_default();

                let _ = sqlx::query("DELETE FROM commands WHERE system_id = ?").bind(id).execute(&mut *tx).await;
                let _ = tx.commit().await;

                response_data = serde_json::json!({
                    "status": "approved",
                    "id": id,
                    "command": if tests.is_empty() { "NONE" } else { "TEST" },
                    "data": tests
                });

                // Attach Server Public Key
                let key_dir = PathBuf::from(config.key.key_path.as_deref().unwrap_or(""));
                let pub_file = config.key.public_key.as_deref().unwrap_or("scmserver.pub");
                if let Ok(key) = fs::read_to_string(key_dir.join(pub_file)) {
                    response_data["server_public_key"] = serde_json::json!(key.trim());
                }
            },
            "denied" => {
                response_data = serde_json::json!({ "status": "denied", "command": "NONE" });
            },
            _ => { // "pending"
                let _ = sqlx::query("UPDATE systems SET name=?, ver=?, os=?, ip=?, arch=?, last_seen = CURRENT_TIMESTAMP  WHERE id=?")
                    .bind(&payload.hostname)
                    .bind(&payload.ver)
                    .bind(&payload.os)
                    .bind(&payload.ip)
                    .bind(&payload.arch)
                    .bind(id)
                    .execute(&pool).await;

                response_data = serde_json::json!({ "status": "pending", "command": "NONE" });
            }
        }
    }

    // 4. SIGN AND RETURN
    match sign_response(response_data, &config) {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Signing Error"}))).into_response(),
    }
}



// =========================================================
// HANDLER: Receive Compliance Results (POST /result)
// =========================================================
pub async fn receive_result(
    Extension(pool): Extension<SqlitePool>,
    Extension(config): Extension<Arc<Config>>,
    Json(signed_req): Json<SignedResult>,
) -> impl IntoResponse {
    let payload = &signed_req.payload;

    info!("Result received from Agent ID: {} (Test ID: {})", payload.client_id, payload.test_id);

    // 1. Auth Check
    let db_pubkey = match sqlx::query_scalar::<_, String>("SELECT key FROM systems WHERE id = ?")
        .bind(payload.client_id).fetch_optional(&pool).await 
    {
        Ok(Some(k)) => k,
        _ => {
            warn!("Result Rejected: Unknown Agent ID {} attempted to upload results.", payload.client_id);
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Unknown Agent"}))).into_response()
        },
    };

    // 2. Verify Result Signature
    let pub_key_bytes: [u8; 32] = general_purpose::STANDARD.decode(&db_pubkey).unwrap().try_into().unwrap();
    let sig_bytes: [u8; 64] = general_purpose::STANDARD.decode(&signed_req.signature).unwrap().try_into().unwrap();
    let verifier = VerifyingKey::from_bytes(&pub_key_bytes).unwrap();
    let payload_bytes = bincode::serialize(payload).unwrap();

    if verifier.verify(&payload_bytes, &Signature::from_bytes(&sig_bytes)).is_err() {
        error!("SECURITY ALERT: Invalid signature on compliance results from Agent ID {}!", payload.client_id);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Result Auth Failed"}))).into_response();
    }
    
    debug!("Result Authenticity: Verified signature for Agent ID {}.", payload.client_id);

    // 3. Store Result
    let now = chrono::Utc::now().to_string();
    let db_res = sqlx::query(
        r#"INSERT INTO results (system_id, test_id, result, last_updated) 
           VALUES (?, ?, ?, ?) 
           ON CONFLICT(system_id, test_id) DO UPDATE SET result=excluded.result, last_updated=excluded.last_updated"#
    )
    .bind(payload.client_id).bind(payload.test_id).bind(&payload.result).bind(&now)
    .execute(&pool).await;

    if let Err(e) = db_res {
        error!("DB Error: Failed to store compliance result: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Storage Error"}))).into_response();
    }

    info!("COMPLIANCE LOG: System {} passed Test {} with status: {}", payload.client_id, payload.test_id, payload.result);

    let response_data = serde_json::json!({"status": "ok"});
    match sign_response(response_data, &config) {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Signing Error"}))).into_response(),
    }
}
