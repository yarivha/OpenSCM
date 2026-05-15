// =============================================================================
// settings.rs — admin settings: thresholds, SMTP, email test, DB reset
//
// All routes require Admin role or higher. SMTP settings are global (stored
// under the default tenant); compliance thresholds are per-tenant.
// =============================================================================

use axum::response::{IntoResponse, Redirect};
use axum::extract::{Extension, Query, Form};
use axum::extract::RawForm;
use axum::http::StatusCode;
use axum::Json;
use tera::{Tera, Context};
use sqlx::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use tracing::{info, error};
use urlencoding;
use serde::Serialize;

use crate::models::{ErrorQuery, UserRole, AuthSession};
use crate::auth;
use crate::handlers::{render_template, parse_form_data};

#[derive(serde::Serialize)]
pub struct Settings {
    pub schema_version: String,
    pub offline_threshold: String,
    pub auto_prune_inactive: String,
    pub compliance_sat: String,
    pub compliance_marginal: String,
    pub smtp_host:     String,
    pub smtp_port:     String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from:     String,
    pub smtp_tls:      String,
    pub app_url:       String,
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /settings
// Render the admin settings page with current thresholds and SMTP config.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn settings(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    // Per-tenant settings (compliance thresholds, offline threshold)
    let rows = sqlx::query(
        "SELECT skey, value FROM settings WHERE tenant_id = ?
         AND skey NOT IN ('smtp_host','smtp_port','smtp_username','smtp_password','smtp_from','smtp_tls','app_url')",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    let mut map = std::collections::HashMap::new();
    for row in rows {
        let key: String = row.get("skey");
        let value: String = row.get("value");
        map.insert(key, value);
    }

    // SMTP settings are global — always read from the default tenant
    let smtp_rows = sqlx::query(
        "SELECT skey, value FROM settings WHERE tenant_id = 'default'
         AND skey IN ('smtp_host','smtp_port','smtp_username','smtp_password','smtp_from','smtp_tls','app_url')",
    )
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    for row in smtp_rows {
        let key: String = row.get("skey");
        let value: String = row.get("value");
        map.insert(key, value);
    }

    // Schema version lives in schema_info, not in the settings key-value store.
    let schema_version: i64 = sqlx::query_scalar("SELECT version FROM schema_info WHERE id = 1")
        .fetch_one(&*pool)
        .await
        .unwrap_or(0);

    let settings = Settings {
        schema_version:    schema_version.to_string(),
        offline_threshold: map.get("offline_threshold").cloned().unwrap_or_else(|| "3600".to_string()),
        auto_prune_inactive: map.get("auto_prune_inactive").cloned().unwrap_or_else(|| "0".to_string()),
        compliance_sat:    map.get("compliance_sat").cloned().unwrap_or_else(|| "80".to_string()),
        compliance_marginal: map.get("compliance_marginal").cloned().unwrap_or_else(|| "60".to_string()),
        smtp_host:     map.get("smtp_host").cloned().unwrap_or_default(),
        smtp_port:     map.get("smtp_port").cloned().unwrap_or_else(|| "587".to_string()),
        smtp_username: map.get("smtp_username").cloned().unwrap_or_default(),
        smtp_password: map.get("smtp_password").cloned().unwrap_or_default(),
        smtp_from:     map.get("smtp_from").cloned().unwrap_or_default(),
        smtp_tls:      map.get("smtp_tls").cloned().unwrap_or_else(|| "starttls".to_string()),
        app_url:       map.get("app_url").cloned().unwrap_or_default(),
    };

    
    let offline_minutes = map.get("offline_threshold")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(600) / 60;

    let mut context = Context::new();
    if let Some(msg) = query.error_message { context.insert("error_message", &msg); }
    if let Some(msg) = query.success_message { context.insert("success_message", &msg); }
    context.insert("settings", &settings);
    context.insert("offline_minutes", &offline_minutes);

    render_template(&tera, Some(&pool), "settings.html", context, Some(auth))
        .await
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /settings/save
// Persist updated compliance thresholds and (if Superuser) SMTP settings.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn settings_save(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    RawForm(raw_form): RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let raw_string = String::from_utf8_lossy(&raw_form).to_string();
    let form_data = parse_form_data(&raw_string);

    // M7: Validate numeric settings before persisting.
    let raw_threshold    = form_data.get("offline_threshold").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_auto_prune   = form_data.get("auto_prune_inactive").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_sat          = form_data.get("compliance_sat").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_marginal     = form_data.get("compliance_marginal").and_then(|v| v.first()).cloned().unwrap_or_default();

    let threshold: i64 = match raw_threshold.parse() {
        Ok(v) if v >= 60 => v,
        _ => return Redirect::to("/settings?error_message=Offline+threshold+must+be+a+number+%E2%89%A560+seconds").into_response(),
    };

    let auto_prune: i64 = match raw_auto_prune.parse::<i64>() {
        Ok(0) => 0,
        Ok(v) if v >= 1 => v,
        _ => return Redirect::to("/settings?error_message=Auto-prune+threshold+must+be+0+(disabled)+or+a+positive+number+of+minutes").into_response(),
    };

    let sat: i64 = match raw_sat.parse() {
        Ok(v) if (0..=100).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Compliance+satisfied+threshold+must+be+0-100").into_response(),
    };

    let marginal: i64 = match raw_marginal.parse() {
        Ok(v) if (0..=100).contains(&v) => v,
        _ => return Redirect::to("/settings?error_message=Compliance+marginal+threshold+must+be+0-100").into_response(),
    };

    if marginal >= sat {
        return Redirect::to("/settings?error_message=Marginal+threshold+must+be+less+than+Satisfied+threshold").into_response();
    }

    let mut updates: Vec<(&str, String)> = vec![
        ("offline_threshold",   threshold.to_string()),
        ("auto_prune_inactive", auto_prune.to_string()),
        ("compliance_sat",      sat.to_string()),
        ("compliance_marginal", marginal.to_string()),
    ];

    // Email settings — superuser only
    if UserRole::from(auth.role.as_str()) >= UserRole::Superuser {
        let smtp_host     = form_data.get("smtp_host").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_port_raw = form_data.get("smtp_port").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_username = form_data.get("smtp_username").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_password = form_data.get("smtp_password").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_from     = form_data.get("smtp_from").and_then(|v| v.first()).cloned().unwrap_or_default();
        let smtp_tls      = form_data.get("smtp_tls").and_then(|v| v.first()).cloned().unwrap_or_default();
        let app_url       = form_data.get("app_url").and_then(|v| v.first()).cloned().unwrap_or_default();

        let smtp_port: String = match smtp_port_raw.parse::<u16>() {
            Ok(p) if p >= 1 => p.to_string(),
            _ => "587".to_string(),
        };

        updates.extend([
            ("smtp_host",     smtp_host),
            ("smtp_port",     smtp_port),
            ("smtp_username", smtp_username),
            ("smtp_from",     smtp_from),
            ("smtp_tls",      smtp_tls),
            ("app_url",       app_url),
        ]);

        if !smtp_password.is_empty() {
            updates.push(("smtp_password", smtp_password));
        }
    }

    const SMTP_KEYS: &[&str] = &[
        "smtp_host", "smtp_port", "smtp_username", "smtp_password",
        "smtp_from", "smtp_tls", "app_url",
    ];

    for (key, value) in updates {
        // SMTP settings are global — always stored under the default tenant
        let tenant = if SMTP_KEYS.contains(&key) { "default" } else { &auth.tenant_id };
        if let Err(e) = sqlx::query(
            "INSERT INTO settings (tenant_id, skey, value)
     VALUES (?, ?, ?)
     ON CONFLICT (tenant_id, skey) DO UPDATE SET value = excluded.value"
        )
        .bind(tenant)
        .bind(key)
        .bind(&value)
        .execute(&pool)
        .await
        {
            let encoded = urlencoding::encode(&format!("Error saving setting {}: {}", key, e)).to_string();
            return Redirect::to(&format!("/settings?error_message={}", encoded)).into_response();
        }
    }

    info!("Settings updated by '{}'.", auth.username);
    Redirect::to("/settings?success_message=Settings+saved+successfully").into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /settings/test-email
// Send a test email to the logged-in user's address via the configured SMTP.
// Role: Superuser
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TestEmailResponse {
    pub ok:      bool,
    pub message: String,
}

pub async fn settings_test_email(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
) -> (StatusCode, Json<TestEmailResponse>) {
    if auth::authorize(&auth.role, UserRole::Superuser).is_some() {
        return (StatusCode::FORBIDDEN, Json(TestEmailResponse {
            ok: false,
            message: "Access denied.".into(),
        }));
    }

    // Recipient: logged-in user's email address (looked up from DB)
    let to: String = match sqlx::query_scalar::<_, Option<String>>(
        "SELECT email FROM users WHERE id = ? AND tenant_id = ?",
    )
    .bind(auth.userid)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    .unwrap_or(None)
    .flatten()
    .filter(|e| !e.is_empty()) {
        Some(e) => e,
        None => return (StatusCode::BAD_REQUEST, Json(TestEmailResponse {
            ok: false,
            message: "Your account has no email address. Edit your profile and add one first.".into(),
        })),
    };

    // SMTP settings are global — always read from the default tenant
    let rows = sqlx::query(
        "SELECT skey, value FROM settings WHERE tenant_id = 'default'
         AND skey IN ('smtp_host','smtp_port','smtp_username','smtp_password','smtp_from','smtp_tls','app_url')"
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let mut map = std::collections::HashMap::new();
    for row in rows {
        let k: String = row.get("skey");
        let v: String = row.get("value");
        map.insert(k, v);
    }

    let host = map.get("smtp_host").cloned().unwrap_or_default();
    if host.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(TestEmailResponse {
            ok: false,
            message: "SMTP Host is not configured. Save your settings first.".into(),
        }));
    }

    let port: u16 = map.get("smtp_port").and_then(|v| v.parse().ok()).unwrap_or(587);
    let username  = map.get("smtp_username").cloned().unwrap_or_default();
    let password  = map.get("smtp_password").cloned().unwrap_or_default();
    let from      = map.get("smtp_from").cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("OpenSCM <noreply@{}>", host));
    let tls_mode  = map.get("smtp_tls").cloned().unwrap_or_else(|| "starttls".into());

    // Build transport using the shared email module helper
    let transport = match crate::email::build_transport(&host, port, &tls_mode, &username, &password) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_GATEWAY, Json(TestEmailResponse {
            ok: false,
            message: format!("Failed to create SMTP transport: {}", e),
        })),
    };

    // Build and send a test message
    use lettre::{AsyncTransport, Message, message::header::ContentType};
    let message = match Message::builder()
        .from(from.parse().unwrap_or_else(|_| "OpenSCM <noreply@openscm.io>".parse().unwrap()))
        .to(match to.parse() {
            Ok(m) => m,
            Err(e) => return (StatusCode::BAD_REQUEST, Json(TestEmailResponse {
                ok: false,
                message: format!("Invalid recipient address: {}", e),
            })),
        })
        .subject("OpenSCM — SMTP Test Email")
        .header(ContentType::TEXT_HTML)
        .body("<p>This is a test email from <strong>OpenSCM</strong>.</p><p>Your SMTP relay is configured correctly.</p>".to_string())
    {
        Ok(m) => m,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(TestEmailResponse {
            ok: false,
            message: format!("Failed to build email: {}", e),
        })),
    };

    match transport.send(message).await {
        Ok(_) => {
            info!("Test email sent to {} by '{}'", to, auth.username);
            (StatusCode::OK, Json(TestEmailResponse {
                ok: true,
                message: format!("Test email sent successfully to {}.", to),
            }))
        }
        Err(e) => {
            error!("Test email failed for '{}': {}", auth.username, e);
            (StatusCode::BAD_GATEWAY, Json(TestEmailResponse {
                ok: false,
                message: format!("SMTP error: {}", e),
            }))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /settings/reset
// Wipe all tenant operational data; requires the literal "RESET" confirmation.
// Role: Superuser
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ResetForm {
    confirm: String,
}

pub async fn settings_reset(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    Form(form): Form<ResetForm>,
) -> impl IntoResponse {
    // Superuser only
    if auth::authorize(&auth.role, UserRole::Superuser).is_some() {
        return Redirect::to("/settings?error_message=Access+denied").into_response();
    }

    // Require exact confirmation token
    if form.confirm.trim() != "RESET" {
        return Redirect::to("/settings?error_message=Confirmation+text+did+not+match").into_response();
    }

    let tenant = &auth.tenant_id;

    let result: Result<(), sqlx::Error> = async {
        let mut tx = pool.begin().await?;

        // Delete all operational data for this tenant, preserving:
        //   - users WHERE id = 1 AND tenant_id = 'default'  (bootstrap admin)
        //   - settings                                       (SMTP config, thresholds)
        //   - tenant_keys WHERE tenant_id = 'default'        (default tenant signing keys only)
        //   - schema_info                                    (migration state)

        // Dependent tables first (foreign keys with ON DELETE CASCADE handle most,
        // but we delete explicitly to be safe with all SQLite pragma states).
        for sql in &[
            // Results & history
            format!("DELETE FROM results            WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM compliance_history WHERE tenant_id = '{tenant}'"),
            // Reports
            format!("DELETE FROM system_reports     WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM reports            WHERE tenant_id = '{tenant}'"),
            // Scheduler
            format!("DELETE FROM policy_schedules   WHERE tenant_id = '{tenant}'"),
            // Policy / test relations
            format!("DELETE FROM tests_in_policy    WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM test_conditions    WHERE tenant_id = '{tenant}'"),
            // System relations
            format!("DELETE FROM systems_in_policy  WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM systems_in_groups  WHERE tenant_id = '{tenant}'"),
            // Top-level entities
            format!("DELETE FROM policies           WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM tests              WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM system_groups      WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM systems            WHERE tenant_id = '{tenant}'"),
            // Notifications
            format!("DELETE FROM notify             WHERE tenant_id = '{tenant}'"),
            // Auth tokens (base schema — present in all editions)
            format!("DELETE FROM email_verifications WHERE tenant_id = '{tenant}'"),
            format!("DELETE FROM password_resets     WHERE user_id IN (SELECT id FROM users WHERE tenant_id = '{tenant}')"),
            // Users — keep bootstrap admin (id=1, default tenant)
            format!("DELETE FROM users WHERE tenant_id = '{tenant}' AND NOT (id = 1 AND tenant_id = 'default')"),
            // Tenant keys — keep only default tenant keys
            "DELETE FROM tenant_keys WHERE tenant_id != 'default'".to_string(),
        ] {
            sqlx::query(sql).execute(&mut *tx).await?;
        }

        tx.commit().await
    }.await;

    match result {
        Ok(_) => {
            info!(
                "Database reset performed by superuser '{}' (tenant: {})",
                auth.username, auth.tenant_id
            );
            Redirect::to("/settings?success_message=Database+cleaned+successfully").into_response()
        }
        Err(e) => {
            error!("Database reset failed for '{}': {}", auth.username, e);
            let msg = urlencoding::encode(&format!("Reset failed: {}", e)).to_string();
            Redirect::to(&format!("/settings?error_message={}", msg)).into_response()
        }
    }
}
