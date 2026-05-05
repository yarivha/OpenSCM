//////////////////// Settings /////////////////////////
 
use axum::response::{IntoResponse, Redirect};
use axum::extract::{Extension, Query};
use axum::extract::RawForm;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use tracing::info;
use urlencoding;

use crate::models::{ErrorQuery, UserRole, AuthSession};
use crate::auth;
use crate::handlers::{render_template, parse_form_data};

#[derive(serde::Serialize)]
pub struct Settings {
    pub schema_version: String,
    pub offline_threshold: String,
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

pub async fn settings(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let rows = sqlx::query(
        "SELECT key, value FROM settings WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .unwrap_or_default();

    let mut map = std::collections::HashMap::new();
    for row in rows {
        let key: String = row.get("key");
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
    let raw_threshold = form_data.get("offline_threshold").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_sat       = form_data.get("compliance_sat").and_then(|v| v.first()).cloned().unwrap_or_default();
    let raw_marginal  = form_data.get("compliance_marginal").and_then(|v| v.first()).cloned().unwrap_or_default();

    let threshold: i64 = match raw_threshold.parse() {
        Ok(v) if v >= 60 => v,
        _ => return Redirect::to("/settings?error_message=Offline+threshold+must+be+a+number+%E2%89%A560+seconds").into_response(),
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

    // SMTP plain string fields
    let smtp_host     = form_data.get("smtp_host").and_then(|v| v.first()).cloned().unwrap_or_default();
    let smtp_port_raw = form_data.get("smtp_port").and_then(|v| v.first()).cloned().unwrap_or_default();
    let smtp_username = form_data.get("smtp_username").and_then(|v| v.first()).cloned().unwrap_or_default();
    let smtp_password = form_data.get("smtp_password").and_then(|v| v.first()).cloned().unwrap_or_default();
    let smtp_from     = form_data.get("smtp_from").and_then(|v| v.first()).cloned().unwrap_or_default();
    let smtp_tls      = form_data.get("smtp_tls").and_then(|v| v.first()).cloned().unwrap_or_default();
    let app_url       = form_data.get("app_url").and_then(|v| v.first()).cloned().unwrap_or_default();

    // Validate smtp_port — fall back to 587 if not a valid port number
    let smtp_port: String = match smtp_port_raw.parse::<u16>() {
        Ok(p) if p >= 1 => p.to_string(),
        _ => "587".to_string(),
    };

    let mut updates: Vec<(&str, String)> = vec![
        ("offline_threshold",   threshold.to_string()),
        ("compliance_sat",      sat.to_string()),
        ("compliance_marginal", marginal.to_string()),
        ("smtp_host",     smtp_host),
        ("smtp_port",     smtp_port),
        ("smtp_username", smtp_username),
        ("smtp_from",     smtp_from),
        ("smtp_tls",      smtp_tls),
        ("app_url",       app_url),
    ];

    // Only update smtp_password if the form field is non-empty
    if !smtp_password.is_empty() {
        updates.push(("smtp_password", smtp_password));
    }

    for (key, value) in updates {
        if let Err(e) = sqlx::query(
            "UPDATE settings SET value = ? WHERE tenant_id = ? AND key = ?",
        )
        .bind(&value)
        .bind(&auth.tenant_id)
        .bind(key)
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
