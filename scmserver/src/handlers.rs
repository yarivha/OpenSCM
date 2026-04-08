use axum::response::{Html, Response, IntoResponse};
use axum::http::{StatusCode, header};
use http_body_util::Full;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use urlencoding;
use std::collections::HashMap;
use urlencoding::decode;
use tracing::error;

use crate::models::Notification;
use crate::auth::UserRole;
use crate::auth::AuthSession;



//////////////////////////////// Helper Functions ///////////////////////////////////
pub async fn render_template(
    tera: &Tera,
    pool: Option<&SqlitePool>,
    template_name: &str,
    mut context: Context,
    auth: Option<AuthSession>,
) -> Result<Html<String>, StatusCode> {
    // Add common context values
    context.insert("version", env!("CARGO_PKG_VERSION"));
    if let Some(session) = &auth {
        context.insert("username", &session.username);
         context.insert("userid", &session.userid);
        context.insert("role", &session.role);
    }

    if let Some(pool) = pool {
        
        // Add notify count
        let notify_row = sqlx::query("SELECT COUNT(*) as count FROM notify")
                  .fetch_one(pool)
                  .await
                  .map_err(|e| {
                    error!("DB error getting notify count: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                  })?;

        let notify_count: i64 = notify_row.get("count");
        context.insert("notify_count", &notify_count);

        // Add notify list
        let notifications = sqlx::query("SELECT id, type, timestamp, message FROM notify ORDER BY timestamp DESC LIMIT 10")
            .map(|row: sqlx::sqlite::SqliteRow| Notification {
                id: row.get("id"),
                r#type: row.get("type"),
                timestamp: row.get("timestamp"),
                message: row.get("message"),
            })
            .fetch_all(pool)
            .await
            .map_err(|e| {
                error!("Failed to fetch notifications: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        context.insert("notifications", &notifications);

        // Add pending registrations count 
        let pending_row = sqlx::query("SELECT COUNT(*) as count FROM systems WHERE status = 'pending'")
                  .fetch_one(pool)
                  .await
                  .map_err(|e| {
                    error!("DB error getting pending count: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                  })?;

        let pending_count: i64 = pending_row.get("count");
        context.insert("pending_count", &pending_count);
    }
   
    // Add authorization functions
    if let Some(session) = &auth {
        // 2. Now 'session' is the actual AuthSession, so we can access .role
        let role_enum = UserRole::from(session.role.as_str());

        // 3. Insert the specific strings for the template
        context.insert("username", &session.username);
        context.insert("role", &session.role);

        // 4. Calculate permissions based on your hierarchy
        context.insert("is_admin", &(role_enum >= UserRole::Admin));
        context.insert("is_editor", &(role_enum >= UserRole::Editor));
        context.insert("is_runner", &(role_enum >= UserRole::Runner));
        context.insert("is_viewer", &(role_enum >= UserRole::Viewer));

    } else {
        // Optional: Logic for when NO user is logged in (Guest mode)
        context.insert("is_admin", &false);
        context.insert("is_editor", &false);
        context.insert("is_runner", &false);
        context.insert("is_viewer", &false);
    }


    // Render template
    let rendered = tera.render(template_name, &context).map_err(|e| {
        error!("Template render error ({}): {}", template_name, e);
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



