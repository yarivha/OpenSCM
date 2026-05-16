// =============================================================================
// handlers.rs — shared utilities: template rendering, form parsing,
//               notifications, status normalization, and 404 fallback
//
// These are internal helpers used across all route modules.
// =============================================================================

use axum::response::{Html, Redirect, Response, IntoResponse};
use axum::http::{StatusCode, header};
use axum::body::Body;
use axum::Extension;
use tera::{Tera, Context};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use urlencoding::decode;
use tracing::{info,error};

use crate::models::{Notification, UserRole, AuthSession};

// ─────────────────────────────────────────────────────────────────────────────
// SaaS mode flag
// Set once at startup by the SaaS binary via `enable_saas_mode()`. Drives
// the `is_saas` context variable so SaaS-only UI (tenant chip, Support
// menu, Platform Admin treeview) can live in the shared base.html.
// ─────────────────────────────────────────────────────────────────────────────
static SAAS_MODE: AtomicBool = AtomicBool::new(false);

pub fn enable_saas_mode()       { SAAS_MODE.store(true, Ordering::Relaxed); }
pub fn is_saas_mode() -> bool   { SAAS_MODE.load(Ordering::Relaxed) }


// ============================================================
// TEMPLATE RENDERING
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// Helper: render_template
// Populates global context (version, edition, pending count, notifications,
// session info) then renders the named Tera template to HTML.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn render_template(
    tera: &Tera,
    pool: Option<&SqlitePool>,
    template_name: &str,
    mut context: Context,
    auth: Option<AuthSession>,
) -> Result<Html<String>, StatusCode> {

    // Global context — available on every page
    context.insert("version", crate::app_version());
    context.insert("edition", crate::app_edition());

    // Database-driven context
    if let Some(db_pool) = pool {
        if let Some(session) = &auth {
            // Batch query 1: pending systems count + tenant display name in one round-trip.
            // LEFT JOIN ensures we always get a row even if the tenant row is missing.
            let (pending_count, tenant_name): (i64, String) = sqlx::query_as(
                "SELECT
                    (SELECT COUNT(*) FROM systems
                     WHERE status = 'pending' AND tenant_id = t.id) AS pending_count,
                    t.name AS tenant_name
                 FROM tenants t WHERE t.id = ?",
            )
            .bind(&session.tenant_id)
            .fetch_optional(db_pool)
            .await
            .ok()
            .flatten()
            .unwrap_or((0i64, session.tenant_id.clone()));

            context.insert("pending_count", &pending_count);

            // Batch query 2: top 10 notifications + total count in one round-trip.
            // COUNT(*) OVER() is a window function supported by SQLite ≥ 3.25 (2018).
            // The count reflects all rows, the LIMIT applies only to returned rows.
            #[derive(sqlx::FromRow)]
            struct NotifyRow {
                id: i64, tenant_id: String, ntype: String, nts: String,
                owner_id: i32, message: String,
                total_count: i64,
            }
            let notify_rows: Vec<NotifyRow> = sqlx::query_as(
                "SELECT id, tenant_id, ntype, nts, owner_id, message,
                        COUNT(*) OVER() AS total_count
                 FROM notify
                 WHERE owner_id = ? AND tenant_id = ?
                 ORDER BY nts DESC
                 LIMIT 10",
            )
            .bind(&session.userid)
            .bind(&session.tenant_id)
            .fetch_all(db_pool)
            .await
            .unwrap_or_default();

            let notify_count = notify_rows.first().map(|r| r.total_count).unwrap_or(0);
            let notifications: Vec<Notification> = notify_rows.into_iter().map(|r| Notification {
                id: r.id, tenant_id: r.tenant_id, ntype: r.ntype,
                nts: r.nts, owner_id: r.owner_id, message: r.message,
            }).collect();

            context.insert("notify_count", &notify_count);
            context.insert("notifications", &notifications);
            context.insert("tenant_name", &tenant_name);

        } else {
            // Guest defaults
            context.insert("pending_count", &0i64);
            context.insert("notify_count", &0i64);
            context.insert("notifications", &Vec::<Notification>::new());
            context.insert("tenant_name", &String::new());
        }
    } else {
        // No pool available
        context.insert("pending_count", &0i64);
        context.insert("notify_count", &0i64);
        context.insert("notifications", &Vec::<Notification>::new());
        context.insert("tenant_name", &String::new());
    }

    // Session context — user info and permissions
    if let Some(session) = &auth {
        let role_enum = UserRole::from(session.role.as_str());

        context.insert("username", &session.username);
        context.insert("userid", &session.userid);
        context.insert("tenant_id", &session.tenant_id);
        context.insert("role", &session.role);

        context.insert("is_superuser", &(role_enum >= UserRole::Superuser));
        context.insert("is_admin",  &(role_enum >= UserRole::Admin));
        context.insert("is_editor", &(role_enum >= UserRole::Editor));
        context.insert("is_runner", &(role_enum >= UserRole::Runner));
        context.insert("is_viewer", &(role_enum >= UserRole::Viewer));
    } else {
        context.insert("username", "Guest");
        context.insert("role", "Guest");
        context.insert("is_superuser", &false);
        context.insert("is_admin",  &false);
        context.insert("is_editor", &false);
        context.insert("is_runner", &false);
        context.insert("is_viewer", &false);
    }

    // Edition marker — drives SaaS-only UI in the shared base.html.
    context.insert("is_saas", &is_saas_mode());

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

// ─────────────────────────────────────────────────────────────────────────────
// Helper: parse_form_data
// Parses URL-encoded form data into a map of key → list of values.
// Handles + as space and percent-encoded characters.
// ─────────────────────────────────────────────────────────────────────────────
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
                .or_default()
                .push(value_decoded);
        }
    }

    form_data
}


// ============================================================
// NOTIFICATIONS
// ============================================================


// ─────────────────────────────────────────────────────────────────────────────
// Helper: add_notification
// Inserts a notification row for a specific user in the notify table.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn add_notification(
    pool: &SqlitePool,
    tenant_id: &str,
    n_type: &str,
    owner_id: i32,
    message: &str,
) {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();

    if let Err(e) = sqlx::query(
        "INSERT INTO notify (tenant_id, ntype, nts, owner_id, message) VALUES (?, ?, ?, ?, ?)",
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
// CLEAR NOTIFICATIONS
// ============================================================
// ─────────────────────────────────────────────────────────────────────────────
// GET /notifications/clear
// Deletes all notifications for the current user, then redirects to /.
// Role: Viewer (any authenticated user)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn clear_notifications(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
) -> Redirect {
    let result = sqlx::query("DELETE FROM notify WHERE owner_id = ? AND tenant_id = ?")
        .bind(&auth.userid)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await;

    match result {
        Ok(_) => info!("User {} cleared notifications for tenant {}", auth.userid, auth.tenant_id),
        Err(e) => error!("Failed to clear notifications: {}", e),
    }

    // Redirect back to the dashboard or wherever they were
    Redirect::to("/")
}



// ============================================================
// STATUS NORMALIZATION AND COMPLIANCE VERDICT
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// Helper: is_system_passed
// Returns true when a system (or policy) has at least one PASS and zero FAILs.
// All-NA systems (pass == 0 && fail == 0) return false; the caller is
// responsible for rendering them as "NOT APPLICABLE" rather than "Non-Compliant".
// ─────────────────────────────────────────────────────────────────────────────
pub fn is_system_passed(pass_count: usize, fail_count: usize) -> bool {
    pass_count > 0 && fail_count == 0
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: normalize_status
// Maps raw result strings (true/1/pass → PASS, na/n/a → NA, else → FAIL).
// ─────────────────────────────────────────────────────────────────────────────
pub fn normalize_status(raw: &str) -> &'static str {
    match raw.to_lowercase().as_str() {
        "pass" | "true" | "1" => "PASS",
        "na" | "n/a"          => "NA",
        "not_scanned"         => "NOT_SCANNED",
        _ => "FAIL",
    }
}


// ============================================================
// FALLBACK HANDLERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// Fallback: not_found
// Returns a plain-text 404 response for all unmatched routes.
// ─────────────────────────────────────────────────────────────────────────────
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
