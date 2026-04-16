use axum::{extract::Extension,http::StatusCode,response::IntoResponse,Json,};
use tokio::sync::mpsc;
use sqlx::SqlitePool;
use tracing::{info, error, debug, warn};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Verifier, VerifyingKey, Signature, SigningKey, Signer};

use crate::models::{SignedRequest, SignedResult, UnsignedPayload, SignedResponse};
use crate::models::Test;


#[derive(sqlx::FromRow)]
struct AuthCheck {
    pub key: String,
    pub status: Option<String>,
}


pub async fn sign_response(
    pool: &SqlitePool,
    tenant_id: &str,
    payload: serde_json::Value,
) -> Result<SignedResponse, Box<dyn std::error::Error>> {
    // Note: No semicolon at the end of the line before .ok_or_else
    let priv_base64 = sqlx::query_scalar::<_, String>(
        "SELECT private_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1"
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await? // <-- Ensure there is NO semicolon here
    .ok_or_else(|| format!("CRITICAL: No signing key found for tenant '{}'", tenant_id))?;

    let priv_bytes = general_purpose::STANDARD.decode(priv_base64.trim())?;
    let key_array: [u8; 32] = priv_bytes.try_into().map_err(|_| "Invalid private key length")?;
    let signing_key = SigningKey::from_bytes(&key_array);

    // Inside the heartbeat section of send()

    let payload_bytes = bincode::serialize(&payload)?;
    let signature = signing_key.sign(&payload_bytes);
    let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());

    Ok(SignedResponse {
        payload,
        signature: signature_base64,
    })
}




pub async fn send(
    Extension(pool): Extension<SqlitePool>,
    Json(signed_req): Json<SignedRequest<UnsignedPayload>>,
) -> impl IntoResponse {
    let payload = &signed_req.payload;
    let mut response_data = serde_json::json!({});
    
    // Fallback to 'default' for old clients
    let tenant_id = if payload.tenant_id.is_empty() { 
        "default" 
    } else { 
        &payload.tenant_id 
    };


    let id = match payload.id.parse::<i64>() {
        Ok(val) => val,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid ID"}))).into_response()
    };



    // =========================================================
    // 1. VALIDATE TENANT EXISTENCE (The Gatekeeper)
    // =========================================================
    let tenant_exists = match sqlx::query_scalar::<_, i32>("SELECT COUNT(*) FROM tenants WHERE id = ?")
        .bind(tenant_id)
        .fetch_one(&pool)
        .await 
    {
        Ok(count) => count > 0,
        Err(e) => {
            error!("Database error checking tenant: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response();
        }
    };

    if !tenant_exists {
        warn!("REJECTED: Agent '{}' attempted to connect to non-existent tenant '{}'.", payload.hostname, tenant_id);
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Unauthorized: Tenant does not exist"}))).into_response();
    }


    // 1. REGISTRATION (ID 0)
    if id == 0 {
        info!("New agent: {} (Tenant: {})", payload.hostname, tenant_id);
        
        let res = sqlx::query(
            r#"INSERT INTO systems (tenant_id, key, name, ver, os, ip, arch, status) 
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')"#
        )
        .bind(tenant_id)
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
                response_data = serde_json::json!({
                    "status": "pending", 
                    "id": new_id,
                    "tenant_id": tenant_id,
                    "command": "REGISTER"
                });
            },
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
        }
    } else {
        
        // 2. HEARTBEAT
        let auth_result: Result<Option<AuthCheck>, sqlx::Error> = sqlx::query_as::<_, AuthCheck>(
            "SELECT key, status FROM systems WHERE id = ? AND tenant_id = ?"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&pool)
        .await;


        // Inside the heartbeat section of send()
debug!("Verifying signature for Agent {}. Payload: {:?}", id, payload);

let payload_bytes = bincode::serialize(payload).unwrap();
debug!("Serialized bytes length: {}", payload_bytes.len()); // Compare this to the client's length


        let auth = match auth_result {
            Ok(Some(a)) => a,
            Ok(None) => {
                warn!("Identity Check: Agent ID {} not found for tenant {}.", id, tenant_id);
                return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Agent not found"}))).into_response();
            },
            Err(e) => {
                // Now the compiler knows for sure 'e' is a sqlx::Error
                error!("DB Error for Tenant {}: {}", tenant_id, e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
            }
        };



        // --- AUTHENTICATION ---
        let pub_key_bytes: [u8; 32] = general_purpose::STANDARD.decode(&auth.key).unwrap().try_into().unwrap_or([0u8; 32]);
        let sig_bytes: [u8; 64] = general_purpose::STANDARD.decode(&signed_req.signature).unwrap().try_into().unwrap_or([0u8; 64]);
        
        let verifier = VerifyingKey::from_bytes(&pub_key_bytes).unwrap();
        let payload_bytes = bincode::serialize(payload).unwrap();

        if verifier.verify(&payload_bytes, &Signature::from_bytes(&sig_bytes)).is_err() {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid Signature"}))).into_response();
        }

        // 3. PROCESS STATUS
        match auth.status.as_deref().unwrap_or("pending") {
            "approved" | "active" => {
                let mut tx = pool.begin().await.unwrap();
                
                // Update with Tenant Check
                let _ = sqlx::query("UPDATE systems SET name=?, ver=?, os=?, ip=?, arch=?, status='active', last_seen=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?")
                    .bind(&payload.hostname).bind(&payload.ver).bind(&payload.os).bind(&payload.ip).bind(&payload.arch).bind(id).bind(tenant_id)
                    .execute(&mut *tx).await;

                let tests: Vec<Test> = sqlx::query_as::<_, Test>(
                    "SELECT t.* FROM commands c JOIN tests t ON c.test_id = t.id WHERE c.system_id = ? AND c.tenant_id = ? LIMIT 20"
                ).bind(id).bind(tenant_id).fetch_all(&mut *tx).await.unwrap_or_default();

                let _ = sqlx::query("DELETE FROM commands WHERE system_id = ? AND tenant_id = ?").bind(id).bind(tenant_id).execute(&mut *tx).await;
                let _ = tx.commit().await;

                response_data = serde_json::json!({
                    "status": "approved",
                    "id": id,
                    "tenant_id": tenant_id,
                    "command": if tests.is_empty() { "NONE" } else { "TEST" },
                    "data": tests
                });

                // Get Server Public Key from DB
                if let Ok(Some(pub_key)) = sqlx::query_scalar::<_, String>(
                    "SELECT public_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1"
                ).bind(tenant_id).fetch_optional(&pool).await {
                    response_data["server_public_key"] = serde_json::json!(pub_key);
                }
            },
            "denied" => {
                response_data = serde_json::json!({ "status": "denied", "command": "NONE" });
            },
            _ => {
                let _ = sqlx::query("UPDATE systems SET last_seen=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?")
                    .bind(id).bind(tenant_id).execute(&pool).await;
                response_data = serde_json::json!({ "status": "pending", "command": "NONE" });
            }
        }
    }

    // 4. SIGN AND RETURN (Async)
    match sign_response(&pool, tenant_id, response_data).await {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(e) => {
            error!("Sign error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Signing Error"}))).into_response()
        }
    }
}




// =========================================================
// HANDLER: Receive Compliance Results (POST /result)
// =========================================================
pub async fn receive_result(
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    Json(signed_req): Json<SignedResult>,
) -> impl IntoResponse {
    let payload = &signed_req.payload;
    
    // If the string is empty, we treat it as "default", otherwise use the string itself
    let tenant_id = if payload.tenant_id.is_empty() { 
        "default" 
    } else { 
        &payload.tenant_id 
    };

    info!("Result received from Agent ID: {} , Tenant: {}  (Test ID: {})", payload.client_id, payload.tenant_id,payload.test_id);

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

    // 3. Store Individual Result
    let now = chrono::Utc::now().to_string();
    let db_res = sqlx::query(
        r#"INSERT INTO results (tenant_id, system_id, test_id, result, last_updated) 
           VALUES (?, ?, ?, ?, ?) 
           ON CONFLICT(tenant_id,system_id, test_id) DO UPDATE SET result=excluded.result, last_updated=excluded.last_updated"#
    )
    .bind(tenant_id)
    .bind(payload.client_id)
    .bind(payload.test_id)
    .bind(&payload.result)
    .bind(&now)
    .execute(&pool).await;

    if let Err(e) = db_res {
        error!("DB Error: Failed to store compliance result: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Storage Error"}))).into_response();
    }

    // Run compliance recalculation
    let _ = sync_tx.send(()).await;

    // 6. Response
    let response_data = serde_json::json!({"status": "ok"});
    match sign_response(&pool, tenant_id, response_data).await {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(e) => {
            error!("Signing Error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Signing Error"}))).into_response()
        }
    }
}



