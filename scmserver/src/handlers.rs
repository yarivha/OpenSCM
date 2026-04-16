use axum::response::{Html, Response, IntoResponse};
use axum::http::{StatusCode, header};
use http_body_util::Full;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use urlencoding;
use std::collections::HashMap;
use urlencoding::decode;
use tracing::{info,warn,error};


use crate::models::Notification;
use crate::models::UserRole;
use crate::auth::AuthSession;


//////////////////////////////// Helper Functions ///////////////////////////////////

pub async fn render_template(
    tera: &Tera,
    pool: Option<&SqlitePool>,
    template_name: &str,
    mut context: Context,
    auth: Option<AuthSession>,
) -> Result<Html<String>, StatusCode> {
    // 1. GLOBAL CONTEXT
    // These values are inserted for every request, regardless of login status
    context.insert("version", env!("CARGO_PKG_VERSION"));

    // 2. DATABASE LOGIC (If a pool is provided)
    if let Some(db_pool) = pool {
        
        // --- Global Database Query ---
        // Guests and logged-in users both need to see this
        let pending_count: i64 = sqlx::query("SELECT COUNT(*) as count FROM systems WHERE status = 'pending'")
            .fetch_one(db_pool)
            .await
            .map(|row| row.get::<i64, _>("count"))
            .unwrap_or(0);
        
        context.insert("pending_count", &pending_count);

        // --- User-Specific Database Query ---
        // We only "reach in" for these if a session exists
        if let Some(session) = &auth {
            // Get notification count
            let notify_count: i64 = sqlx::query(
                "SELECT COUNT(*) as count FROM notify WHERE owner_id = ? AND tenant_id = ?"
            )
            .bind(&session.userid)
            .bind(&session.tenant_id) // Standardized on "default" string
            .fetch_one(db_pool)
            .await
            .map(|row| row.get::<i64, _>("count"))
            .unwrap_or(0);

            context.insert("notify_count", &notify_count);

            // Get notification list (Top 10)
            let notifications = sqlx::query_as::<_, Notification>(
                "SELECT id, type, timestamp, message FROM notify WHERE owner_id = ? AND tenant_id = ? ORDER BY timestamp DESC LIMIT 10"
            )
            .bind(&session.userid)
            .bind(&session.tenant_id)
            .fetch_all(db_pool)
            .await
            .unwrap_or_default();

            context.insert("notifications", &notifications);
        } else {
            // Guest defaults for DB-related fields
            context.insert("notify_count", &0);
            context.insert("notifications", &Vec::<Notification>::new());
        }
    } else {
        // Fallback if no pool is available at all
        context.insert("pending_count", &0);
        context.insert("notify_count", &0);
    }

    // 3. AUTHORIZATION & SESSION CONTEXT
    // This populates the UI permissions and user info
    if let Some(session) = &auth {
        let role_enum = UserRole::from(session.role.as_str());

        context.insert("username", &session.username);
        context.insert("userid", &session.userid);
        context.insert("tenant_id", &session.tenant_id);
        context.insert("role", &session.role);

        // Permissions hierarchy
        context.insert("is_admin", &(role_enum >= UserRole::Admin));
        context.insert("is_editor", &(role_enum >= UserRole::Editor));
        context.insert("is_runner", &(role_enum >= UserRole::Runner));
        context.insert("is_viewer", &(role_enum >= UserRole::Viewer));
    } else {
        // Guest defaults for UI
        context.insert("username", "Guest");
        context.insert("role", "Guest");
        context.insert("is_admin", &false);
        context.insert("is_editor", &false);
        context.insert("is_runner", &false);
        context.insert("is_viewer", &false);
    }

    // 4. FINAL RENDER
    let rendered = tera.render(template_name, &context).map_err(|e| {
        error!("Template render error ({}): {:?}", template_name, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Html(rendered))
}



// Helper function to parse URL-encoded form data
pub fn parse_form_data(raw_string: &str) -> HashMap<String, Vec<String>> {
    let mut form_data: HashMap<String, Vec<String>> = HashMap::new();
    
    for pair in raw_string.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            // Replace '+' with spaces before decoding
            let key = key.replace('+', " ");
            let value = value.replace('+', " ");

            // Decode percent-encoded values safely
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



pub async fn not_found() -> impl IntoResponse {
    // Body content
    let body = "404 - Not Found";

    // Build the response
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Full::from(body))  // Use Full or Boxed body type
        .unwrap()
}


/// Creates a notification entry for a specific owner or the system
pub async fn add_notification(pool: &sqlx::SqlitePool, n_type: &str, owner_id: i32, message: &str) {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M").to_string();
    
    let result = sqlx::query(
        "INSERT INTO notify (type, timestamp, owner_id, message) VALUES (?, ?, ?, ?)"
    )
    .bind(n_type)
    .bind(now)
    .bind(owner_id) 
    .bind(message)
    .execute(pool)
    .await;

    if let Err(e) = result {
        error!("Failed to insert notification: {}", e);
    }
}


