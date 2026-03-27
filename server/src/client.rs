use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use sqlx::SqlitePool;
use tracing::{info, error};
use base64::engine::general_purpose;
use base64::Engine;
use ed25519_dalek::{Verifier, VerifyingKey, Signature};

use crate::models::{SignedRequest, SignedResult, UnsignedPayload, Test};

pub async fn send(
    Extension(pool): Extension<SqlitePool>,
    Json(signed_req): Json<SignedRequest<UnsignedPayload>>,
) -> impl IntoResponse {

    let payload = &signed_req.payload;

    // =========================
    // Parse ID
    // =========================
    let id = match payload.id.parse::<i64>() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status":"error","message":"Invalid ID"})),
            );
        }
    };

    let now = chrono::Utc::now().to_string();

    // =========================
    // NEW AGENT
    // =========================
    if id == 0 {
        let res = sqlx::query(
            "INSERT INTO systems (key, name, os, ip, arch, created_date, last_seen, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&payload.public_key)
        .bind(&payload.hostname)
        .bind(&payload.os)
        .bind(&payload.ip)
        .bind(&payload.arch)
        .bind(&now)
        .bind(&now)
        .bind("pending")
        .execute(&pool)
        .await;
       
        info!("New Agent was created with id={}",id);
        return match res {
            Ok(r) => (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "status":"created",
                    "id": r.last_insert_rowid(),
                    "command":"REGISTER"
                })),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status":"error",
                    "message": format!("{}", e)
                })),
            ),
        };
    }

    // =========================
    // LOAD PUBLIC KEY
    // =========================
    let db_pubkey = match sqlx::query_scalar::<_, String>(
        "SELECT key FROM systems WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(k)) => k, // row found
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"status":"error","message":"Agent not found"})),
            );
        }
        Err(e) => {
            error!("DB query failed for system {}: {}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"status":"error","message": format!("DB error: {}", e)})),
            );
        }
    };


    // =========================
    // DECODE PUBLIC KEY
    // =========================
    let public_key_bytes: [u8; 32] = match general_purpose::STANDARD.decode(&db_pubkey)
        .and_then(|b| b.try_into().map_err(|_| base64::DecodeError::InvalidLength))
    {
        Ok(arr) => arr,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status":"error","message":"Invalid public key"})),
            );
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status":"error","message":"Invalid public key format"})),
            );
        }
    };

    // =========================
    // DECODE SIGNATURE
    // =========================
    let signature_bytes: [u8; 64] = match general_purpose::STANDARD.decode(&signed_req.signature)
        .and_then(|b| b.try_into().map_err(|_| base64::DecodeError::InvalidLength))
    {
        Ok(arr) => arr,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status":"error","message":"Invalid signature"})),
            );
        }
    };

    let signature = Signature::from_bytes(&signature_bytes);

    // =========================
    // VERIFY SIGNATURE
    // =========================
    let payload_bytes = match bincode::serialize(payload) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status":"error","message":"Serialization failed"})),
            );
        }
    };

    if verifying_key.verify(&payload_bytes, &signature).is_err() {
        error!("Agent {} failed auth", id);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"status":"error","message":"Signature verification failed"})),
        );
    }

    // =========================
    // TRANSACTION
    // =========================
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"status":"error","message":"DB error"})),
            );
        }
    };

    // Update system
    let _ = sqlx::query(
        "UPDATE systems SET name=?, os=?, ip=?, arch=?, last_seen=? WHERE id=?"
    )
    .bind(&payload.hostname)
    .bind(&payload.os)
    .bind(&payload.ip)
    .bind(&payload.arch)
    .bind(&now)
    .bind(id)
    .execute(&mut *tx)
    .await;

    // Fetch tests for this system
    let tests: Vec<Test> = match sqlx::query_as::<_, Test>(
        r#"
        SELECT t.*
        FROM commands c
        JOIN tests t ON c.test_id = t.id
        WHERE c.system_id = ?
        LIMIT 20
        "#
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    {
        Ok(tests) => tests,
        Err(e) => {
            error!("Failed to fetch tests for system {}: {}", id, e);
            vec![]
        }
    };

    // If no tests, send NONE
    if tests.is_empty() {
        let _ = tx.commit().await;
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "id": id,
                "command": "NONE"
            })),
        );
    }

    
    // Delete commands after fetching
    if let Err(e) = sqlx::query("DELETE FROM commands WHERE system_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete commands for system {}: {}", id, e);
    }



    let _ = tx.commit().await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status":"ok",
            "id": id,
            "command":"TEST",
            "data": tests
        })),
    )
}




// receive_result
pub async fn receive_result(
    Extension(pool): Extension<SqlitePool>,
    Json(signed_req): Json<SignedResult>,
) -> impl IntoResponse {
    let payload = &signed_req.payload;

    // Fetch client public key from DB
    let db_pubkey = match sqlx::query_scalar::<_, String>(
        "SELECT key FROM systems WHERE id = ?"
    )
    .bind(payload.client_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(k)) => k,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "status": "error",
                    "message": "Agent not found"
                })),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "status": "error",
                    "message": format!("DB error: {}", e)
                })),
            );
        }
    };

    
    let public_key_bytes_vec = match general_purpose::STANDARD.decode(&db_pubkey) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "message": "Invalid public key encoding"
                })),
            );
        }
    };

    // Convert Vec<u8> -> [u8; 32]
    let public_key_bytes: [u8; 32] = match public_key_bytes_vec.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "message": "Invalid public key length"
                })),
            );
        }
    };

    // Build verifying key
    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "message": "Invalid public key format"
                })),
            );
        }
    };



    // Decode signature from base64
    let signature_bytes = match general_purpose::STANDARD.decode(&signed_req.signature) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status":"error","message":"Invalid signature"})),
            );
        }
    };

    // Convert Vec<u8> to [u8; 64]
    let signature_bytes: [u8; 64] = match signature_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status":"error","message":"Invalid signature length"})),
            );
        }
    };

    // Create signature (ed25519-dalek 2.x)
    let signature = Signature::from_bytes(&signature_bytes);



    // Verify signature
    let payload_bytes = match bincode::serialize(payload) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status":"error","message":"Serialization failed"})),
            );
        }
    };

    if verifying_key.verify(&payload_bytes, &signature).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"status":"error","message":"Signature verification failed"})),
        );
    }

    // Log result
    info!(
        "Received result → client_id: {}, test_id: {}, result: {}",
        payload.client_id,
        payload.test_id,
        payload.result
    );
    
    // === SAVE RESULT INTO DATABASE ===
    let now = chrono::Utc::now().to_string();

    let db_res = sqlx::query(
        r#"
        INSERT INTO results (system_id, test_id, result, last_updated)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(system_id, test_id)
        DO UPDATE SET
            result = excluded.result,
            last_updated = excluded.last_updated
        "#
    )
    .bind(payload.client_id)            // system/client id
    .bind(payload.test_id)              // test id
    .bind(&payload.result)              // result string
    .bind(&now)                         // timestamp
    .execute(&pool)
    .await;

    if let Err(e) = db_res {
        error!(
            "Failed to store result in DB: client={}, test={}, error={}",
            payload.client_id,
            payload.test_id,
            e
        );

        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "message": "Failed to store result in database"
            })),
        );
    }


    (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
}


