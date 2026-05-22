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

use sqlx::SqlitePool;
use tracing::error;

use crate::models::AuthSession;

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
        // Never propagate — audit failure must not abort the underlying op.
        error!(
            "audit_log write failed (action={}, tenant={}, target={:?}): {}",
            action, tenant_id, target_id, e
        );
    }
}
