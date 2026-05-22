// =============================================================================
// audit.rs — immutable record of state-changing admin actions
//
// Every handler that mutates a row that an auditor would later want to ask
// "who did this?" calls `audit::record(...).await` exactly once. The call is
// fire-and-forget: a DB error during the audit write is logged via tracing
// but never propagated, because failing the audit must not fail the request
// being audited.
//
// The audit_log table and its retention setting (settings.audit_log_retention_days)
// are introduced by schema migration v19 → v20. The actual retention-cleanup
// scheduler tick lives in Task #9 (data retention / cleanup policy).
// =============================================================================

use axum::extract::{Extension, Query};
use axum::response::IntoResponse;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::sync::Arc;
use tera::{Tera, Context};
use tracing::error;

use crate::auth;
use crate::handlers::render_template;
use crate::models::{AuditEntry, AuthSession, UserRole};

// ─────────────────────────────────────────────────────────────────────────────
// record
// Writes one audit_log row. Swallows DB errors so the request being audited
// can never fail because of a logging side-effect. Pass actor=None for events
// triggered without an authenticated session (e.g. a failed login attempt
// before AuthSession exists, or a background scheduler job).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record(
    pool:        &SqlitePool,
    tenant_id:   &str,
    actor:       Option<&AuthSession>,
    ip_address:  Option<&str>,
    action:      &str,
    target_type: Option<&str>,
    target_id:   Option<&str>,
    details:     Option<&str>,
) {
    let (actor_user_id, actor_username): (Option<i32>, &str) = match actor {
        Some(s) => (Some(s.userid), s.username.as_str()),
        None    => (None,           "system"),
    };
    record_raw(pool, tenant_id, actor_user_id, actor_username,
               ip_address, action, target_type, target_id, details).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// record_raw
// Lower-level primitive for events where there is no AuthSession yet —
// e.g. a failed login attempt that still needs to record the attempted
// username, or a background scheduler event with no human actor at all.
// Pass actor_user_id=None + actor_username="system" for daemon-originated.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn record_raw(
    pool:           &SqlitePool,
    tenant_id:      &str,
    actor_user_id:  Option<i32>,
    actor_username: &str,
    ip_address:     Option<&str>,
    action:         &str,
    target_type:    Option<&str>,
    target_id:      Option<&str>,
    details:        Option<&str>,
) {
    let res = sqlx::query(
        "INSERT INTO audit_log
            (tenant_id, actor_user_id, actor_username, action,
             target_type, target_id, details, ip_address)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(tenant_id)
    .bind(actor_user_id)
    .bind(actor_username)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(details)
    .bind(ip_address)
    .execute(pool)
    .await;

    if let Err(e) = res {
        error!(
            "audit_log write failed (action={}, tenant={}, target={:?}): {}",
            action, tenant_id, target_id, e
        );
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /admin/audit-log
// Read-only paginated viewer of recent audit_log rows for the caller's tenant.
// Admin role only. No filters in v1 — just the last N rows ordered newest-first.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Deserialize)]
pub struct AuditQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

pub async fn audit_log_view(
    auth: AuthSession,
    Query(q): Query<AuditQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir.into_response();
    }

    let per_page = q.per_page.unwrap_or(100).clamp(10, 500);
    let page     = q.page.unwrap_or(1).max(1);
    let offset   = (page - 1) * per_page;

    let entries: Vec<AuditEntry> = sqlx::query_as(
        "SELECT id, tenant_id, actor_user_id, actor_username, action,
                target_type, target_id, details, ip_address, created_at
         FROM audit_log
         WHERE tenant_id = ?
         ORDER BY id DESC
         LIMIT ? OFFSET ?",
    )
    .bind(&auth.tenant_id)
    .bind(per_page as i64)
    .bind(offset as i64)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(0);

    let retention_days: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings
         WHERE tenant_id = ? AND skey = 'audit_log_retention_days'",
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(730);

    let total_pages = ((total as u32) + per_page - 1) / per_page.max(1);

    let mut ctx = Context::new();
    ctx.insert("entries",        &entries);
    ctx.insert("total",          &total);
    ctx.insert("page",           &page);
    ctx.insert("per_page",       &per_page);
    ctx.insert("total_pages",    &total_pages);
    ctx.insert("retention_days", &retention_days);

    render_template(&tera, Some(&pool), "audit_log.html", ctx, Some(auth))
        .await
        .into_response()
}
