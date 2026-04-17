use axum::response::{Html, Response, IntoResponse};
use axum::http::{StatusCode, header};
use axum::body::Body;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::collections::HashMap;
use urlencoding::decode;
use tracing::error;

use crate::models::{Notification, UserRole, AuthSession};


// ============================================================
// TEMPLATE RENDERING
// ============================================================

pub async fn render_template(
    tera: &Tera,
    pool: Option<&SqlitePool>,
    template_name: &str,
    mut context: Context,
    auth: Option<AuthSession>,
) -> Result<Html<String>, StatusCode> {

    // Global context — available on every page
    context.insert("version", env!("CARGO_PKG_VERSION"));

    // Database-driven context
    if let Some(db_pool) = pool {
        if let Some(session) = &auth {
            // Pending systems count — filtered by tenant
            let pending_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM systems WHERE status = 'pending' AND tenant_id = ?",
            )
            .bind(&session.tenant_id)
            .fetch_one(db_pool)
            .await
            .unwrap_or(0);

            context.insert("pending_count", &pending_count);

            // Notification count for current user
            let notify_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM notify WHERE owner_id = ? AND tenant_id = ?",
            )
            .bind(&session.userid)
            .bind(&session.tenant_id)
            .fetch_one(db_pool)
            .await
            .unwrap_or(0);

            context.insert("notify_count", &notify_count);

            // Top 10 notifications for current user
            let notifications = sqlx::query_as::<_, Notification>(
                "SELECT id, tenant_id, type, timestamp, owner_id, message
                 FROM notify
                 WHERE owner_id = ? AND tenant_id = ?
                 ORDER BY timestamp DESC
                 LIMIT 10",
            )
            .bind(&session.userid)
            .bind(&session.tenant_id)
            .fetch_all(db_pool)
            .await
            .unwrap_or_default();

            context.insert("notifications", &notifications);

        } else {
            // Guest defaults
            context.insert("pending_count", &0i64);
            context.insert("notify_count", &0i64);
            context.insert("notifications", &Vec::<Notification>::new());
        }
    } else {
        // No pool available
        context.insert("pending_count", &0i64);
        context.insert("notify_count", &0i64);
        context.insert("notifications", &Vec::<Notification>::new());
    }

    // Session context — user info and permissions
    if let Some(session) = &auth {
        let role_enum = UserRole::from(session.role.as_str());

        context.insert("username", &session.username);
        context.insert("userid", &session.userid);
        context.insert("tenant_id", &session.tenant_id);
        context.insert("role", &session.role);

        context.insert("is_admin",  &(role_enum >= UserRole::Admin));
        context.insert("is_editor", &(role_enum >= UserRole::Editor));
        context.insert("is_runner", &(role_enum >= UserRole::Runner));
        context.insert("is_viewer", &(role_enum >= UserRole::Viewer));
    } else {
        context.insert("username", "Guest");
        context.insert("role", "Guest");
        context.insert("is_admin",  &false);
        context.insert("is_editor", &false);
        context.insert("is_runner", &false);
        context.insert("is_viewer", &false);
    }

    // Render template
    let rendered = tera.render(template_name, &context).map_err(|e| {
        error!("Template render error ({}): {:?}", template_name, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Html(rendered))
}


// ============================================================
// FORM PARSING
// ============================================================

/// Parse URL-encoded form data into a map of key -> list of values.
/// Handles `+` as space and percent-encoded characters.
pub fn parse_form_data(raw_string: &str) -> HashMap<String, Vec<String>> {
    let mut form_data: HashMap<String, Vec<String>> = HashMap::new();

    for pair in raw_string.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let key = key.replace('+', " ");
            let value = value.replace('+', " ");

            let key_decoded = decode(&key)
                .unwrap_or_else(|_| key.clone().into())
                .to_string();
            let value_decoded = decode(&value)
                .unwrap_or_else(|_| value.clone().into())
                .to_string();

            form_data
                .entry(key_decoded)
                .or_insert_with(Vec::new)
                .push(value_decoded);
        }
    }

    form_data
}


// ============================================================
// NOTIFICATIONS
// ============================================================


/// Insert a notification for a specific user.
pub async fn add_notification(
    pool: &SqlitePool,
    tenant_id: &str,
    n_type: &str,
    owner_id: i32,
    message: &str,
) {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M").to_string();

    if let Err(e) = sqlx::query(
        "INSERT INTO notify (tenant_id, type, timestamp, owner_id, message) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(tenant_id)
    .bind(n_type)
    .bind(&now)
    .bind(owner_id)
    .bind(message)
    .execute(pool)
    .await
    {
        error!("Failed to insert notification for user {}: {}", owner_id, e);
    }
}



// ============================================================
// STATUS NORMALIZATION
// ============================================================

/// Normalize result status strings to a consistent "PASS" or "FAIL".
/// Handles legacy formats: "true", "1", "pass", "PASS".
pub fn normalize_status(raw: &str) -> &'static str {
    match raw.to_lowercase().as_str() {
        "pass" | "true" | "1" => "PASS",
        _ => "FAIL",
    }
}


// ============================================================
// FALLBACK HANDLERS
// ============================================================

pub async fn not_found() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("404 - Not Found"))
        .unwrap_or_else(|e| {
            error!("Failed to build 404 response: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}
