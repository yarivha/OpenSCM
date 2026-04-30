use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use tokio::sync::mpsc;
use sqlx::{SqlitePool, QueryBuilder};
use std::collections::HashMap;
use tracing::{info, error, debug, warn};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Verifier, VerifyingKey, Signature, SigningKey, Signer};

use crate::models::{SignedRequest, SignedResult, UnsignedPayload, SignedResponse, Test, TestCondition, TestWithConditions};


#[derive(sqlx::FromRow)]
struct AuthCheck {
    pub key: String,
    pub status: Option<String>,
}



// ============================================================
// HELPERS
// ============================================================

/// Sign a JSON payload using the tenant's active Ed25519 private key.
pub async fn sign_response(
    pool: &SqlitePool,
    tenant_id: &str,
    payload: serde_json::Value,
) -> Result<SignedResponse, Box<dyn std::error::Error>> {
    let priv_base64 = sqlx::query_scalar::<_, String>(
        "SELECT private_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| format!("CRITICAL: No signing key found for tenant '{}'", tenant_id))?;

    let priv_bytes = general_purpose::STANDARD.decode(priv_base64.trim())?;
    let key_array: [u8; 32] = priv_bytes
        .try_into()
        .map_err(|_| "Invalid private key length: expected 32 bytes")?;

    let signing_key = SigningKey::from_bytes(&key_array);

    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = signing_key.sign(&payload_bytes);
    let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());

    Ok(SignedResponse {
        payload,
        signature: signature_base64,
    })
}


fn decode_public_key(base64_key: &str) -> Result<VerifyingKey, String> {
    let bytes = general_purpose::STANDARD
        .decode(base64_key)
        .map_err(|e| format!("Invalid base64 in public key: {}", e))?;

    let key_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;

    VerifyingKey::from_bytes(&key_array)
        .map_err(|e| format!("Invalid Ed25519 public key: {}", e))
}


fn decode_signature(base64_sig: &str) -> Result<Signature, String> {
    let bytes = general_purpose::STANDARD
        .decode(base64_sig)
        .map_err(|e| format!("Invalid base64 in signature: {}", e))?;

    let sig_array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes".to_string())?;

    Ok(Signature::from_bytes(&sig_array))
}


fn verify_signature<T: serde::Serialize>(
    payload: &T,
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<(), String> {
    let verifier = decode_public_key(public_key_b64)?;
    let signature = decode_signature(signature_b64)?;
    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| format!("Failed to serialize payload for verification: {}", e))?;

    verifier
        .verify(&payload_bytes, &signature)
        .map_err(|_| "Signature verification failed".to_string())
}


// ============================================================
// HANDLERS
// ============================================================

/// Handle agent registration and heartbeat (POST /send)
pub async fn send(
    Extension(pool): Extension<SqlitePool>,
    Json(signed_req): Json<SignedRequest<UnsignedPayload>>,
) -> impl IntoResponse {
    let payload = &signed_req.payload;

    let tenant_id = if payload.tenant_id.is_empty() {
        "default"
    } else {
        &payload.tenant_id
    };

    let id = match payload.id.parse::<i64>() {
        Ok(val) => val,
        Err(_) => {
            warn!("Rejected request with invalid ID from host '{}'", payload.hostname);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid ID"})),
            )
                .into_response();
        }
    };

    // =========================================================
    // STEP 1: VALIDATE TENANT EXISTENCE
    // =========================================================
    let tenant_exists = match sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM tenants WHERE id = ?",
    )
    .bind(tenant_id)
    .fetch_one(&pool)
    .await
    {
        Ok(count) => count > 0,
        Err(e) => {
            error!("Database error checking tenant '{}': {}", tenant_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    if !tenant_exists {
        warn!(
            "REJECTED: Agent '{}' attempted to connect to non-existent tenant '{}'.",
            payload.hostname, tenant_id
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Unauthorized: Tenant does not exist"})),
        )
            .into_response();
    }

    let mut response_data = serde_json::json!({});

    // =========================================================
    // STEP 2: REGISTRATION (ID == 0)
    // =========================================================
    if id == 0 {
        if let Some(ref pub_key) = payload.public_key {
            if decode_public_key(pub_key).is_err() {
                warn!(
                    "REJECTED: Agent '{}' provided malformed public key during registration.",
                    payload.hostname
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid public key format"})),
                )
                    .into_response();
            }
        }

        info!(
            "New agent registration: '{}' (Tenant: {})",
            payload.hostname, tenant_id
        );

        let res = sqlx::query(
            r#"INSERT INTO systems (tenant_id, key, name, ver, os, ip, arch, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')"#,
        )
        .bind(tenant_id)
        .bind(&payload.public_key)
        .bind(&payload.hostname)
        .bind(&payload.ver)
        .bind(&payload.os)
        .bind(&payload.ip)
        .bind(&payload.arch)
        .execute(&pool)
        .await;

        match res {
            Ok(r) => {
                let new_id = r.last_insert_rowid();
                info!(
                    "Agent '{}' registered with ID {} (pending approval).",
                    payload.hostname, new_id
                );
                response_data = serde_json::json!({
                    "status": "pending",
                    "id": new_id,
                    "tenant_id": tenant_id,
                    "command": "REGISTER"
                });

                // Send server public key on registration so the client can
                // verify signatures immediately without waiting for the next heartbeat.
                match sqlx::query_scalar::<_, String>(
                    "SELECT public_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1",
                )
                .bind(tenant_id)
                .fetch_optional(&pool)
                .await
                {
                    Ok(Some(pub_key)) => {
                        response_data["server_public_key"] = serde_json::json!(pub_key);
                    }
                    Ok(None) => warn!("No active public key found for tenant '{}' during registration.", tenant_id),
                    Err(e)  => error!("Failed to fetch server public key for tenant '{}': {}", tenant_id, e),
                }
            }
            Err(e) => {
                error!("Failed to register agent '{}': {}", payload.hostname, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    } else {
        // =========================================================
        // STEP 3: HEARTBEAT (ID > 0)
        // =========================================================
        let auth_result = sqlx::query_as::<_, AuthCheck>(
            "SELECT key, status FROM systems WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&pool)
        .await;

        let auth = match auth_result {
            Ok(Some(a)) => a,
            Ok(None) => {
                warn!(
                    "Identity Check: Agent ID {} not found for tenant '{}'.",
                    id, tenant_id
                );
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "Agent not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error fetching agent {} for tenant '{}': {}", id, tenant_id, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };

        // M8: Check denied BEFORE signature verification — no benefit verifying a denied agent,
        // and doing so leaks status information (denied → 200 vs pending → 200 vs bad sig → 401).
        if auth.status.as_deref() == Some("denied") {
            info!("Agent ID {} is denied — request rejected without signature check.", id);
            response_data = serde_json::json!({
                "status": "denied",
                "command": "NONE"
            });
        } else {

        debug!("Verifying signature for Agent ID {} (Tenant: {}).", id, tenant_id);
        if let Err(err) = verify_signature(payload, &signed_req.signature, &auth.key) {
            warn!(
                "SECURITY: Invalid signature from Agent ID {} (Tenant: '{}'): {}",
                id, tenant_id, err
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid Signature"})),
            )
                .into_response();
        }
        debug!("Signature verified for Agent ID {}.", id);

        match auth.status.as_deref().unwrap_or("pending") {
            "approved" | "active" => {
                let mut tx = match pool.begin().await {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("Failed to begin transaction for agent {}: {}", id, e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": "Database error"})),
                        )
                            .into_response();
                    }
                };

                // Update system info
                if let Err(e) = sqlx::query(
                    "UPDATE systems SET name=?, ver=?, os=?, ip=?, arch=?, status='active', last_seen=CURRENT_TIMESTAMP
                     WHERE id=? AND tenant_id=?",
                )
                .bind(&payload.hostname)
                .bind(&payload.ver)
                .bind(&payload.os)
                .bind(&payload.ip)
                .bind(&payload.arch)
                .bind(id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                {
                    error!("Failed to update system info for agent {}: {}", id, e);
                    tx.rollback().await.ok();
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                // Fetch pending commands
                let tests: Vec<Test> = match sqlx::query_as::<_, Test>(
                    "SELECT t.* FROM commands c
                     JOIN tests t ON c.test_id = t.id
                     WHERE c.system_id = ? AND c.tenant_id = ?
                     LIMIT 500",
                )
                .bind(id)
                .bind(tenant_id)
                .fetch_all(&mut *tx)
                .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Failed to fetch commands for agent {}: {}", id, e);
                        tx.rollback().await.ok();
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": "Database error"})),
                        )
                            .into_response();
                    }
                };

                // M1: Batch-fetch ALL conditions for ALL tests in one query instead of N+1.
                let test_ids: Vec<i64> = tests.iter().map(|t| t.id.unwrap_or(0) as i64).collect();

                let all_conditions: Vec<TestCondition> = if test_ids.is_empty() {
                    vec![]
                } else {
                    let mut qb = QueryBuilder::new(
                        "SELECT id, tenant_id, test_id, type, element, input, selement, condition, sinput
                         FROM test_conditions WHERE tenant_id = ",
                    );
                    qb.push_bind(tenant_id);
                    qb.push(" AND test_id IN (");
                    let mut sep = qb.separated(", ");
                    for tid in &test_ids { sep.push_bind(*tid); }
                    qb.push(") ORDER BY test_id ASC, id ASC");

                    qb.build_query_as::<TestCondition>()
                        .fetch_all(&pool)
                        .await
                        .unwrap_or_else(|e| {
                            error!("Failed to batch-fetch conditions for agent {}: {}", id, e);
                            vec![]
                        })
                };

                // Group by (test_id, type)
                let mut cond_map: HashMap<(i64, &str), Vec<TestCondition>> = HashMap::new();
                for c in all_conditions {
                    let key = (c.test_id, if c.r#type == "applicability" { "applicability" } else { "condition" });
                    cond_map.entry(key).or_default().push(c);
                }

                let mut tests_with_conditions: Vec<TestWithConditions> = Vec::new();
                for test in tests {
                    let test_id = test.id.unwrap_or(0) as i64;
                    let conditions = cond_map.remove(&(test_id, "condition")).unwrap_or_default();
                    let applicability = cond_map.remove(&(test_id, "applicability")).filter(|v| !v.is_empty());
                    tests_with_conditions.push(TestWithConditions { test, conditions, applicability });
                }

                // Clear delivered commands
                if let Err(e) = sqlx::query(
                    "DELETE FROM commands WHERE system_id = ? AND tenant_id = ?",
                )
                .bind(id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                {
                    error!("Failed to clear commands for agent {}: {}", id, e);
                    tx.rollback().await.ok();
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                if let Err(e) = tx.commit().await {
                    error!("Failed to commit heartbeat transaction for agent {}: {}", id, e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Database error"})),
                    )
                        .into_response();
                }

                info!(
                    "Heartbeat from Agent ID {} — {} test(s) dispatched.",
                    id,
                    tests_with_conditions.len()
                );

                response_data = serde_json::json!({
                    "status": "approved",
                    "id": id,
                    "tenant_id": tenant_id,
                    "command": if tests_with_conditions.is_empty() { "NONE" } else { "TEST" },
                    "data": tests_with_conditions
                });

                // Only send the server public key when the client explicitly
                // requests it — indicated by the client including its own
                // public_key in the payload (needs_handshake path in the agent).
                // This covers two cases: first heartbeat after registration
                // (server key not yet saved) and key file loss/corruption.
                // On normal heartbeats public_key is None so we skip the DB
                // lookup entirely.
                if payload.public_key.is_some() {
                    match sqlx::query_scalar::<_, String>(
                        "SELECT public_key FROM tenant_keys WHERE tenant_id = ? AND is_active = 1",
                    )
                    .bind(tenant_id)
                    .fetch_optional(&pool)
                    .await
                    {
                        Ok(Some(pub_key)) => {
                            response_data["server_public_key"] = serde_json::json!(pub_key);
                            debug!("Server public key included in response for Agent ID {} (re-handshake).", id);
                        }
                        Ok(None) => warn!("No active public key found for tenant '{}'.", tenant_id),
                        Err(e)  => error!("Failed to fetch server public key for tenant '{}': {}", tenant_id, e),
                    }
                }
            }

            _ => {
                // Pending (or any other unrecognised status): update last_seen only.
                if let Err(e) = sqlx::query(
                    "UPDATE systems SET last_seen=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?",
                )
                .bind(id)
                .bind(tenant_id)
                .execute(&pool)
                .await
                {
                    error!("Failed to update last_seen for pending agent {}: {}", id, e);
                }

                response_data = serde_json::json!({
                    "status": "pending",
                    "command": "NONE"
                });
            }
        }
        } // end else (not denied)
    } // end else (id > 0 heartbeat path)

    // Sign and return response
    match sign_response(&pool, tenant_id, response_data).await {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(e) => {
            error!("Failed to sign response for tenant '{}': {}", tenant_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Signing Error"})),
            )
                .into_response()
        }
    }
}


/// Handle incoming compliance results (POST /result)
pub async fn receive_result(
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    Json(signed_req): Json<SignedResult>,
) -> impl IntoResponse {
    let payload = &signed_req.payload;

    let tenant_id = if payload.tenant_id.is_empty() {
        "default"
    } else {
        &payload.tenant_id
    };

    info!(
        "Result received from Agent ID {} (Tenant: '{}', Test ID: {})",
        payload.client_id, tenant_id, payload.test_id
    );

    // H-new-1: Fetch key AND status together — denied/pending agents must not be able
    // to submit results even if they still hold valid signing keys from a prior active period.
    let auth_check = match sqlx::query_as::<_, AuthCheck>(
        "SELECT key, status FROM systems WHERE id = ? AND tenant_id = ?",
    )
    .bind(payload.client_id)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(a)) => a,
        Ok(None) => {
            warn!(
                "Result Rejected: Unknown Agent ID {} for tenant '{}'.",
                payload.client_id, tenant_id
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Unknown Agent"})),
            )
                .into_response();
        }
        Err(e) => {
            error!(
                "DB error fetching key for Agent ID {} (Tenant: '{}'): {}",
                payload.client_id, tenant_id, e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    // Reject results from agents that are not active/approved
    match auth_check.status.as_deref().unwrap_or("pending") {
        "active" | "approved" => {}
        "denied" => {
            warn!(
                "Result Rejected: Agent ID {} (Tenant: '{}') is denied.",
                payload.client_id, tenant_id
            );
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "Agent is denied"})),
            )
                .into_response();
        }
        _ => {
            warn!(
                "Result Rejected: Agent ID {} (Tenant: '{}') is pending approval.",
                payload.client_id, tenant_id
            );
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": "Agent not yet approved"})),
            )
                .into_response();
        }
    }

    // H-new-2: Validate result value — only PASS/FAIL/NA are meaningful;
    // an agent cannot write arbitrary strings into the compliance results table.
    let normalized_result = match payload.result.to_uppercase().as_str() {
        "PASS" => "PASS",
        "FAIL" => "FAIL",
        "NA"   => "NA",
        other  => {
            warn!(
                "Result Rejected: Agent ID {} sent invalid result value '{}'.",
                payload.client_id, other
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid result value"})),
            )
                .into_response();
        }
    };

    if let Err(err) = verify_signature(payload, &signed_req.signature, &auth_check.key) {
        error!(
            "SECURITY ALERT: Invalid signature on results from Agent ID {} (Tenant: '{}'): {}",
            payload.client_id, tenant_id, err
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Result Auth Failed"})),
        )
            .into_response();
    }

    debug!(
        "Signature verified for Agent ID {} (Tenant: '{}').",
        payload.client_id, tenant_id
    );

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
    if let Err(e) = sqlx::query(
        r#"INSERT INTO results (tenant_id, system_id, test_id, result, last_updated)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(tenant_id, system_id, test_id)
           DO UPDATE SET result = excluded.result, last_updated = excluded.last_updated"#,
    )
    .bind(tenant_id)
    .bind(payload.client_id)
    .bind(payload.test_id)
    .bind(normalized_result)
    .bind(&now)
    .execute(&pool)
    .await
    {
        error!(
            "Failed to store result from Agent ID {} (Tenant: '{}'): {}",
            payload.client_id, tenant_id, e
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Storage Error"})),
        )
            .into_response();
    }

    info!(
        "Result stored: Agent ID {} | Test ID {} | Result: {} (Tenant: '{}')",
        payload.client_id, payload.test_id, normalized_result, tenant_id
    );

    let _ = sync_tx.send(()).await;

    let response_data = serde_json::json!({"status": "ok"});
    match sign_response(&pool, tenant_id, response_data).await {
        Ok(signed) => (StatusCode::OK, Json(signed)).into_response(),
        Err(e) => {
            error!(
                "Failed to sign response for Agent ID {} (Tenant: '{}'): {}",
                payload.client_id, tenant_id, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Signing Error"})),
            )
                .into_response()
        }
    }
}
