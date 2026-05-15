// =============================================================================
// systems.rs — managed system CRUD, group management, bulk actions,
//              live compliance report
//
// All routes are tenant-scoped. Viewer role required for reads;
// Editor role required for writes.
// =============================================================================

use axum::response::{IntoResponse, Redirect};
use axum::extract::{RawForm, Extension, Query, Path};
use tokio::sync::mpsc;
use tera::{Tera, Context};
use sqlx::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use crate::db_compat;
use urlencoding;
use std::collections::HashMap;
use tracing::{info, warn, error};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use std::collections::BTreeMap;
use crate::handlers::normalize_status;
use crate::models::{
    ErrorQuery, System, SystemGroup, SystemInsideGroup, UserRole, AuthSession,
    IndividualResult, PolicyResultGroup, SystemReportData,
};
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data};


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems
// List all systems (active + pending) for the current tenant, with optional
// ?filter=active|pending query param.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems(
    auth: AuthSession,
    Query(params): Query<HashMap<String, String>>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let filter = params.get("filter").map(|s| s.to_lowercase());

    // Fetch threshold first so we can compute is_offline server-side in SQL.
    let offline_threshold: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'offline_threshold'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(3600);

    let gc        = db_compat::group_concat_col("sg.name");
    let created   = db_compat::format_datetime_col("s.created_date");
    let last_seen = db_compat::format_datetime_col("s.last_seen");
    let unix_diff = db_compat::unix_diff_col("s.last_seen");

    let rows_result = match filter.as_deref() {
        Some("active") | Some("pending") => {
            let sql = format!(
                r#"SELECT
                    s.id AS system_id,
                    COALESCE(s.name, 'NA') AS system_name,
                    COALESCE(s.ver,  'NA') AS system_ver,
                    COALESCE(s.ip,   'NA') AS system_ip,
                    COALESCE(s.os,   'NA') AS system_os,
                    COALESCE(s.arch, 'NA') AS system_arch,
                    COALESCE(s.status, 'NA') AS system_status,
                    COALESCE({gc}, 'none') AS group_names,
                    {created} AS created_date,
                    {last_seen} AS last_seen,
                    CASE
                        WHEN s.status != 'active' THEN 0
                        WHEN s.last_seen IS NULL   THEN 0
                        WHEN {unix_diff} > ?        THEN 1
                        ELSE 0
                    END AS is_offline
                FROM systems AS s
                LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
                LEFT JOIN system_groups     AS sg  ON sig.group_id = sg.id
                WHERE s.status = ? AND s.tenant_id = ?
                GROUP BY s.id
                ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END, s.id ASC"#
            );
            sqlx::query(&sql)
                .bind(offline_threshold)
                .bind(filter.as_deref().unwrap_or("active"))
                .bind(&auth.tenant_id)
                .fetch_all(&pool)
                .await
        }
        _ => {
            let sql = format!(
                r#"SELECT
                    s.id AS system_id,
                    COALESCE(s.name, 'NA') AS system_name,
                    COALESCE(s.ver,  'NA') AS system_ver,
                    COALESCE(s.ip,   'NA') AS system_ip,
                    COALESCE(s.os,   'NA') AS system_os,
                    COALESCE(s.arch, 'NA') AS system_arch,
                    COALESCE(s.status, 'NA') AS system_status,
                    COALESCE({gc}, 'none') AS group_names,
                    {created} AS created_date,
                    {last_seen} AS last_seen,
                    CASE
                        WHEN s.status != 'active' THEN 0
                        WHEN s.last_seen IS NULL   THEN 0
                        WHEN {unix_diff} > ?        THEN 1
                        ELSE 0
                    END AS is_offline
                FROM systems AS s
                LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
                LEFT JOIN system_groups     AS sg  ON sig.group_id = sg.id
                WHERE s.tenant_id = ?
                GROUP BY s.id
                ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END, s.id ASC"#
            );
            sqlx::query(&sql)
                .bind(offline_threshold)
                .bind(&auth.tenant_id)
                .fetch_all(&pool)
                .await
        }
    };

    let rows = match rows_result {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to fetch systems: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load systems.");
            context.insert("systems", &Vec::<System>::new());
            return render_template(&tera, Some(&pool), "systems.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let systems: Vec<System> = rows
        .into_iter()
        .map(|row| System {
            id: row.try_get("system_id").unwrap_or(None),
            name: row.get("system_name"),
            ver: row.try_get("system_ver").ok(),
            ip: row.try_get("system_ip").ok(),
            os: row.try_get("system_os").ok(),
            arch: row.try_get("system_arch").ok(),
            status: row.try_get("system_status").ok(),
            groups: row.try_get("group_names").ok(),
            auth_signature: None,
            auth_public_key: None,
            trust_challenge: None,
            trust_proof: None,
            created_date: row.try_get::<String, _>("created_date").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            last_seen: row.try_get::<String, _>("last_seen").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            is_offline: row.try_get::<bool, _>("is_offline").unwrap_or(false),
        })
        .collect();


    let groups_result = sqlx::query("SELECT id, name FROM system_groups WHERE tenant_id = ? ORDER BY name ASC")
        .bind(&auth.tenant_id)
        .fetch_all(&pool)
        .await;

    let groups: Vec<(i64, String)> = match groups_result {
        Ok(rows) => rows.into_iter().map(|r| (r.get("id"), r.get("name"))).collect(),
        Err(_) => vec![],
    };

    let mut context = Context::new();
    context.insert("groups", &groups);

    if let Some(error_message) = params.get("error_message") {
        context.insert("error_message", error_message);
    }
    if let Some(success_message) = params.get("success_message") {
        context.insert("success_message", success_message);
    }
    context.insert("systems", &systems);
    render_template(&tera, Some(&pool), "systems.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/approve/{id}
// Approve a pending system (set status → active).
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_approve(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    if let Err(e) = sqlx::query(
        "UPDATE systems SET status = 'active' WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&pool)
    .await
    {
        error!("Failed to approve system {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error approving system: {}", e)).to_string();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }

    info!("System ID {} approved by '{}'.", id, auth.username);
    Redirect::to("/systems").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/delete/{id}
// Delete a system and cascade-remove its results; signals compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    // ON DELETE CASCADE handles related records automatically
    if let Err(e) = sqlx::query("DELETE FROM systems WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
    {
        error!("Failed to delete system {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting system: {}", e)).to_string();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("System ID {} deleted by '{}'. Compliance update signaled.", id, auth.username);
    Redirect::to("/systems").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/edit/{id}
// Render the system edit form (group assignment).
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let row_result = sqlx::query(
        "SELECT id, name, ver, ip, os, arch, status
         FROM systems
         WHERE id = ? AND tenant_id = ? AND status = 'active'",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!("Database error fetching system {}: {}", id, e);
            return Redirect::to("/systems?error_message=Database+error").into_response();
        }
    };

    let system = System {
        id: row.try_get("id").unwrap_or(None),
        name: row.get("name"),
        ver: row.try_get("ver").ok(),
        ip: row.try_get("ip").ok(),
        os: row.try_get("os").ok(),
        arch: row.try_get("arch").ok(),
        status: row.try_get("status").ok(),
        groups: None,
        auth_signature: None,
        auth_public_key: None,
        trust_challenge: None,
        trust_proof: None,
        created_date: None,
        last_seen: None,
        is_offline: false,
    };

    let groups_result = sqlx::query(
        "SELECT sg.id AS group_id, sg.name AS group_name, sg.description AS group_description
         FROM system_groups AS sg
         WHERE sg.tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let groups: Vec<SystemGroup> = match groups_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemGroup {
                id: row.get("group_id"),
                name: row.get("group_name"),
                description: row.try_get("group_description").ok(),
                systems: None,
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch groups for system edit {}: {}", id, e);
            vec![]
        }
    };

    let sig_result = sqlx::query(
        "SELECT system_id, group_id FROM systems_in_groups WHERE system_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems_in_groups: Vec<SystemInsideGroup> = match sig_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemInsideGroup {
                system_id: row.get("system_id"),
                group_id: row.get("group_id"),
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch group memberships for system {}: {}", id, e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("system", &system);
    context.insert("groups", &groups);
    context.insert("systems_in_groups", &systems_in_groups);
    render_template(&tera, Some(&pool), "systems_edit.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/edit/{id}
// Persist group-membership changes for a system; signals compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_edit_save(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = String::from_utf8_lossy(&bytes).to_string();
    let form_data = parse_form_data(&raw_string);
    let selected_groups = form_data.get("groups").cloned();

    if let Err(e) = sqlx::query(
        "DELETE FROM systems_in_groups WHERE system_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Failed to clear old groups: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }

    if let Some(group_ids) = selected_groups {
        for g_id_str in group_ids {
            if let Ok(g_id) = g_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
                )
                .bind(id)
                .bind(g_id)
                .bind(&auth.tenant_id)
                .execute(&mut *tx)
                .await
                {
                    let encoded =
                        urlencoding::encode(&format!("Failed to link group {}: {}", g_id, e))
                            .to_string();
                    tx.rollback().await.ok();
                    return Redirect::to(&format!("/systems?error_message={}", encoded))
                        .into_response();
                }
            }
        }
    }


    // Clean up results for tests no longer reachable through current groups
    if let Err(e) = sqlx::query(r#"
        DELETE FROM results
        WHERE system_id = ?
        AND test_id NOT IN (
            SELECT DISTINCT tip.test_id
            FROM tests_in_policy tip
            JOIN systems_in_policy sip ON tip.policy_id = sip.policy_id
            JOIN systems_in_groups sig ON sip.group_id = sig.group_id
            WHERE sig.system_id = ?
            AND sig.tenant_id = ?
        )
    "#)
    .bind(id)
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }



    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/systems?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("System ID {} groups updated by '{}'.", id, auth.username);
    Redirect::to("/systems?success_message=System+groups+updated+successfully").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/pending
// List all systems with status = 'pending' awaiting approval.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_pending(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let sql = format!(
        r#"SELECT
            s.id AS system_id,
            COALESCE(s.name, 'NA') AS system_name,
            COALESCE(s.ver,  'NA') AS system_ver,
            COALESCE(s.ip,   'NA') AS system_ip,
            COALESCE(s.os,   'NA') AS system_os,
            COALESCE(s.arch, 'NA') AS system_arch,
            COALESCE(s.status, 'NA') AS system_status,
            COALESCE({gc}, 'none') AS group_names,
            {created} AS created_date,
            {last_seen} AS last_seen
        FROM systems AS s
        LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
        LEFT JOIN system_groups     AS sg  ON sig.group_id = sg.id
        WHERE s.status = 'pending' AND s.tenant_id = ?
        GROUP BY s.id"#,
        gc      = db_compat::group_concat_col("sg.name"),
        created = db_compat::format_datetime_col("s.created_date"),
        last_seen = db_compat::format_datetime_col("s.last_seen"),
    );
    let rows_result = sqlx::query(&sql)
        .bind(&auth.tenant_id)
        .fetch_all(&*pool)
        .await;

    let rows = match rows_result {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to fetch pending systems: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load pending systems.");
            context.insert("systems", &Vec::<System>::new());
            return render_template(&tera, Some(&pool), "systems.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let systems: Vec<System> = rows
        .into_iter()
        .map(|row| System {
            id: row.try_get("system_id").unwrap_or(None),
            name: row.get("system_name"),
            ver: row.try_get("system_ver").ok(),
            ip: row.try_get("system_ip").ok(),
            os: row.try_get("system_os").ok(),
            arch: row.try_get("system_arch").ok(),
            status: row.try_get("system_status").ok(),
            groups: row.try_get("group_names").ok(),
            auth_signature: None,
            auth_public_key: None,
            trust_challenge: None,
            trust_proof: None,
            created_date: row.try_get::<String, _>("created_date").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            last_seen: row.try_get::<String, _>("last_seen").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
            is_offline: false,
        })
        .collect();

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    context.insert("systems", &systems);
    render_template(&tera, Some(&pool), "systems.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups
// List all system groups and their member systems for the current tenant.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let gc_sql = format!(
        "SELECT sg.id, sg.name, sg.description,
            {gc} AS systems
         FROM system_groups AS sg
         LEFT JOIN systems_in_groups AS sig ON sg.id = sig.group_id
         LEFT JOIN systems AS s ON sig.system_id = s.id
         WHERE sg.tenant_id = ?
         GROUP BY sg.id, sg.name, sg.description",
        gc = db_compat::group_concat_col("s.name"),
    );
    let rows_result = sqlx::query(&gc_sql)
        .bind(&auth.tenant_id)
        .fetch_all(&*pool)
        .await;

    let system_groups: Vec<SystemGroup> = match rows_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemGroup {
                id: Some(row.get("id")),
                name: row.get("name"),
                description: row.try_get("description").ok(),
                systems: row.try_get("systems").ok(),
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch system groups: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load system groups.");
            context.insert("system_groups", &Vec::<SystemGroup>::new());
            return render_template(&tera, Some(&pool), "system_groups.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    context.insert("system_groups", &system_groups);
    render_template(&tera, Some(&pool), "system_groups.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups/add
// Render the add-group form with available active systems.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_add(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let rows_result = sqlx::query(
        "SELECT id, name, status FROM systems WHERE status = 'active' AND tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems: Vec<System> = match rows_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| System {
                id: row.get("id"),
                name: row.get("name"),
                ver: None,
                ip: None,
                os: None,
                arch: None,
                status: row.try_get("status").ok(),
                groups: None,
                auth_signature: None,
                auth_public_key: None,
                trust_challenge: None,
                trust_proof: None,
                created_date: None,
                last_seen: None,
            is_offline: false,
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch systems for group add: {}", e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("systems", &systems);
    render_template(&tera, Some(&pool), "system_groups_add.html", context, Some(auth))
        .await
        .into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// POST /system_groups/add
// Create a new system group and associate the selected systems.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_add_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    // Validate name
    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => {
            return Redirect::to("/system_groups?error_message=Group+name+is+required").into_response();
        }
    };

    // --- FIX STARTS HERE ---
    // Instead of .filter(!s.is_empty()) which creates a None (NULL),
    // we use unwrap_or_default() to ensure we ALWAYS have a String.
    let description: String = form_data
        .get("description")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default(); 
    // --- FIX ENDS HERE ---

    let systems: Option<Vec<String>> = form_data.get("systems").cloned();

    // The bind now sends a String (possibly "") instead of Option<String>
    if let Err(e) = sqlx::query(
        "INSERT INTO system_groups (tenant_id, name, description) VALUES (?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&description)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    let group_id: i64 = match sqlx::query_scalar(db_compat::last_insert_id_sql())
        .fetch_one(&mut *tx)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
        }
    };

    // Process systems association
    if let Some(system_ids) = systems {
        for system_id_str in system_ids {
            match system_id_str.parse::<i32>() {
                Ok(system_id) => {
                    if let Err(e) = sqlx::query(
                        "INSERT INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
                    )
                    .bind(system_id)
                    .bind(group_id)
                    .bind(&auth.tenant_id)
                    .execute(&mut *tx)
                    .await
                    {
                        let encoded = urlencoding::encode(&format!("Failed to add system: {}", e)).to_string();
                        tx.rollback().await.ok();
                        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
                    }
                }
                Err(_) => {
                    let encoded = urlencoding::encode(&format!("Invalid system ID: {}", system_id_str)).to_string();
                    tx.rollback().await.ok();
                    return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
                }
            }
        }
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    info!("System group '{}' created by '{}'.", name, auth.username);
    Redirect::to("/system_groups").into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups/delete/{id}
// Delete a system group and clean up dangling results; signals compliance
// refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }


    // Before the DELETE FROM system_groups:
    if let Err(e) = sqlx::query(r#"
        DELETE FROM results
        WHERE system_id IN (
            SELECT id FROM systems WHERE tenant_id = ?
        )
        AND test_id NOT IN (
            SELECT DISTINCT tip.test_id
            FROM tests_in_policy tip
            JOIN systems_in_policy sip ON tip.policy_id = sip.policy_id
            JOIN systems_in_groups sig ON sip.group_id = sig.group_id
            WHERE sig.tenant_id = ?
        )
    "#)
    .bind(&auth.tenant_id)
    .bind(&auth.tenant_id)
    .execute(&pool)
    .await
    {
        error!("Failed to clean up results for deleted group {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }




    // ON DELETE CASCADE handles systems_in_groups automatically
    if let Err(e) = sqlx::query(
        "DELETE FROM system_groups WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&pool)
    .await
    {
        error!("Failed to delete system group {}: {}", id, e);
        let encoded =
            urlencoding::encode(&format!("Error deleting system group: {}", e)).to_string();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("System group ID {} deleted by '{}'. Compliance update signaled.", id, auth.username);
    Redirect::to("/system_groups").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /system_groups/edit/{id}
// Render the edit form for a system group with current membership.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let row_result = sqlx::query(
        "SELECT id, name, description FROM system_groups WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Redirect::to(
                "/system_groups?error_message=System+group+not+found",
            )
            .into_response();
        }
        Err(e) => {
            error!("Database error fetching group {}: {}", id, e);
            return Redirect::to("/system_groups?error_message=Database+error").into_response();
        }
    };

    let group = SystemGroup {
        id: row.try_get("id").unwrap_or(None),
        name: row.get("name"),
        description: row.try_get("description").ok(),
        systems: None,
    };

    let systems_result = sqlx::query(
        "SELECT id, name, status FROM systems WHERE status = 'active' AND tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems: Vec<System> = match systems_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| System {
                id: row.get("id"),
                name: row.get("name"),
                ver: None,
                ip: None,
                os: None,
                arch: None,
                status: row.try_get("status").ok(),
                groups: None,
                auth_signature: None,
                auth_public_key: None,
                trust_challenge: None,
                trust_proof: None,
                created_date: None,
                last_seen: None,
                is_offline: false,
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch systems for group edit {}: {}", id, e);
            vec![]
        }
    };

    let sig_result = sqlx::query(
        "SELECT system_id, group_id FROM systems_in_groups WHERE group_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems_in_groups: Vec<SystemInsideGroup> = match sig_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemInsideGroup {
                system_id: row.get("system_id"),
                group_id: row.get("group_id"),
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch group memberships for group {}: {}", id, e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("group", &group);
    context.insert("systems", &systems);
    context.insert("systems_in_groups", &systems_in_groups);
    render_template(&tera, Some(&pool), "system_groups_edit.html", context, Some(auth))
        .await
        .into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// POST /system_groups/edit/{id}
// Persist name, description, and membership changes; signals compliance
// refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_groups_edit_save(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded))
                .into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded =
                urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded))
                .into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    // Validate name
    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => {
            return Redirect::to("/system_groups?error_message=Group+name+is+required")
                .into_response();
        }
    };

    // --- FIX: Ensure description is NEVER NULL ---
    // Removed .filter(|s| !s.is_empty()) so empty strings stay empty strings
    let description: String = form_data
        .get("description")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    let systems: Option<Vec<String>> = form_data.get("systems").cloned();

    // Update the group details
    if let Err(e) = sqlx::query(
        "UPDATE system_groups SET name = ?, description = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&name)
    .bind(&description) // Binding the String directly
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error updating group: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    // Clear existing associations
    if let Err(e) = sqlx::query("DELETE FROM systems_in_groups WHERE group_id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await
    {
        let encoded =
            urlencoding::encode(&format!("Error clearing group members: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    // Re-add selected systems
    if let Some(system_ids) = systems {
        for system_id_str in system_ids {
            match system_id_str.parse::<i32>() {
                Ok(system_id) => {
                    if let Err(e) = sqlx::query(
                        "INSERT INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
                    )
                    .bind(system_id)
                    .bind(id)
                    .bind(&auth.tenant_id)
                    .execute(&mut *tx)
                    .await
                    {
                        let encoded =
                            urlencoding::encode(&format!("Error adding system to group: {}", e))
                                .to_string();
                        tx.rollback().await.ok();
                        return Redirect::to(&format!(
                            "/system_groups?error_message={}",
                            encoded
                        ))
                        .into_response();
                    }
                }
                Err(_) => {
                    warn!("Invalid system ID in form: {}", system_id_str);
                }
            }
        }
    }

    // Clean up results for tests no longer reachable
    if let Err(e) = sqlx::query(r#"
        DELETE FROM results
        WHERE system_id IN (
            SELECT id FROM systems WHERE tenant_id = ?
        )
        AND test_id NOT IN (
            SELECT DISTINCT tip.test_id
            FROM tests_in_policy tip
            JOIN systems_in_policy sip ON tip.policy_id = sip.policy_id
            JOIN systems_in_groups sig ON sip.group_id = sig.group_id
            WHERE sig.tenant_id = ?
        )
    "#)
    .bind(&auth.tenant_id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("System group ID {} updated by '{}'.", id, auth.username);
    Redirect::to("/system_groups").into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/bulk/approve
// Approve multiple pending systems in one operation.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_bulk_approve(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/systems?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);
    let ids: Vec<i32> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if ids.is_empty() {
        return Redirect::to("/systems?error_message=No+systems+selected").into_response();
    }

    let mut approved = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query(
            "UPDATE systems SET status = 'active' WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
        {
            error!("Bulk approve: failed for system {}: {}", id, e);
        } else {
            approved += 1;
        }
    }

    info!("Bulk approved {} systems by '{}'.", approved, auth.username);
    let msg = urlencoding::encode(&format!("{} system(s) approved.", approved)).to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/bulk/delete
// Delete multiple systems and signal a compliance refresh.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_bulk_delete(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/systems?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);
    let ids: Vec<i32> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if ids.is_empty() {
        return Redirect::to("/systems?error_message=No+systems+selected").into_response();
    }

    let mut deleted = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query("DELETE FROM systems WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(&auth.tenant_id)
            .execute(&pool)
            .await
        {
            error!("Bulk delete: failed for system {}: {}", id, e);
        } else {
            deleted += 1;
        }
    }

    let _ = sync_tx.send(()).await;
    info!("Bulk deleted {} systems by '{}'.", deleted, auth.username);
    let msg = urlencoding::encode(&format!("{} system(s) deleted.", deleted)).to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/bulk/add-group
// Add multiple systems to a selected group in one operation.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_bulk_add_group(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/systems?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);

    let group_id: i32 = match form_data
        .get("group_id")
        .and_then(|v| v.first())
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => return Redirect::to("/systems?error_message=No+group+selected").into_response(),
    };

    let ids: Vec<i32> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if ids.is_empty() {
        return Redirect::to("/systems?error_message=No+systems+selected").into_response();
    }

    // Verify group belongs to this tenant
    let group_exists: bool = sqlx::query_scalar(
        "SELECT COUNT(*) FROM system_groups WHERE id = ? AND tenant_id = ?",
    )
    .bind(group_id)
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(0i64) > 0;

    if !group_exists {
        return Redirect::to("/systems?error_message=Invalid+group").into_response();
    }

    let mut added = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query(&db_compat::adapt_sql(
            "INSERT OR IGNORE INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
        ))
        .bind(id)
        .bind(group_id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
        {
            error!("Bulk add group: failed for system {}: {}", id, e);
        } else {
            added += 1;
        }
    }

    info!("Bulk added {} systems to group {} by '{}'.", added, group_id, auth.username);
    let msg = urlencoding::encode(&format!("{} system(s) added to group.", added)).to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// fetch_system_report_data
// Gather all policy/test compliance results for one system into
// SystemReportData. Shared by the live report handler and the save handler.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn fetch_system_report_data(
    system_id: i32,
    tenant_id: &str,
    pool: &SqlitePool,
) -> Result<SystemReportData, sqlx::Error> {
    let sys_row = sqlx::query(&format!(
        "SELECT id, name, os, arch, ip, compliance_score,
                {last_seen} AS last_seen
         FROM systems WHERE id = ? AND tenant_id = ?",
        last_seen = db_compat::format_datetime_col("last_seen"),
    ))
    .bind(system_id)
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    let raw = sqlx::query(r#"
        SELECT
            p.id          AS policy_id,
            p.name        AS policy_name,
            p.version     AS policy_version,
            p.description AS policy_description,
            t.name        AS test_name,
            COALESCE(r.result, 'NOT_SCANNED') AS status
        FROM systems_in_groups sig
        JOIN systems_in_policy sip
            ON sig.group_id = sip.group_id AND sig.tenant_id = sip.tenant_id
        JOIN policies p
            ON sip.policy_id = p.id AND p.tenant_id = sip.tenant_id
        JOIN tests_in_policy tip
            ON tip.policy_id = p.id AND tip.tenant_id = p.tenant_id
        JOIN tests t
            ON tip.test_id = t.id
        LEFT JOIN results r
            ON r.test_id = t.id AND r.system_id = ? AND r.tenant_id = ?
        WHERE sig.system_id = ? AND sig.tenant_id = ?
        ORDER BY p.name, t.name
    "#)
    .bind(system_id)
    .bind(tenant_id)
    .bind(system_id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let mut policy_map: BTreeMap<i32, PolicyResultGroup> = BTreeMap::new();
    for row in &raw {
        let policy_id: i32                     = row.get("policy_id");
        let policy_name: String                = row.get("policy_name");
        let policy_version: String             = row.get("policy_version");
        let policy_description: Option<String> = row.try_get("policy_description").ok();
        let test_name: String                  = row.get("test_name");
        let status_raw: String                 = row.get("status");
        let status = normalize_status(&status_raw).to_string();

        let entry = policy_map.entry(policy_id).or_insert_with(|| PolicyResultGroup {
            policy_id,
            policy_name,
            policy_version,
            policy_description,
            results: Vec::new(),
            is_passed: false,
            pass_count: 0,
            fail_count: 0,
        });

        match status.as_str() {
            "PASS" => entry.pass_count += 1,
            "FAIL" => entry.fail_count += 1,
            _ => {}
        }
        entry.results.push(IndividualResult { test_name, status });
    }

    let mut policy_groups: Vec<PolicyResultGroup> = policy_map.into_values().collect();
    for p in &mut policy_groups {
        p.is_passed = p.pass_count > 0 && p.fail_count == 0;
    }

    let total_pass: usize = policy_groups.iter().map(|p| p.pass_count).sum();
    let total_fail: usize = policy_groups.iter().map(|p| p.fail_count).sum();
    let total_na: usize = policy_groups.iter()
        .flat_map(|p| p.results.iter())
        .filter(|r| r.status == "NA" || r.status == "NOT_SCANNED")
        .count();

    let last_seen: Option<String> = sys_row
        .try_get::<String, _>("last_seen")
        .ok()
        .map(|s| {
            s.parse::<DateTime<Utc>>()
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or(s)
        });

    Ok(SystemReportData {
        system_id:        sys_row.get("id"),
        system_name:      sys_row.get("name"),
        os:               sys_row.get::<Option<String>, _>("os").unwrap_or_default(),
        arch:             sys_row.get("arch"),
        ip:               sys_row.get("ip"),
        compliance_score: sys_row.get::<f64, _>("compliance_score"),
        last_seen,
        policy_groups,
        total_pass,
        total_fail,
        total_na,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/report/{id}
// Render the live compliance report for a single system.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let report = match fetch_system_report_data(id, &auth.tenant_id, &pool).await {
        Ok(r) => r,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %id, "Failed to fetch system report data");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let compliance_sat: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_sat'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&*pool)
    .await
    .unwrap_or(80);

    let compliance_marginal: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_marginal'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&*pool)
    .await
    .unwrap_or(60);

    let mut context = Context::new();
    context.insert("report", &report);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    render_template(&tera, Some(&pool), "systems_report.html", context, Some(auth))
        .await
        .into_response()
}
