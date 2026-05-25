// =============================================================================
// systems.rs — managed system CRUD, bulk actions, live compliance report
//
// System-group CRUD (list / add / edit / delete) lives in `groups.rs`.
// `systems_bulk_add_group` is here because it operates on the systems table
// (assigning rows to a group id), even though it's group-adjacent.
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
use urlencoding;
use std::collections::HashMap;
use tracing::{info, error};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use std::collections::BTreeMap;
use semver::Version;
use crate::agents::derive_platform;
use crate::handlers::{normalize_status, is_system_passed};
use crate::models::{
    AgentPackage, ErrorQuery, System, SystemGroup, SystemInsideGroup, UserRole, AuthSession,
    IndividualResult, PolicyResultGroup, SystemReportData, TestMeta,
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
    // Stored in MINUTES (aligned with auto_prune_inactive); the SQL placeholder
    // expects seconds, so we multiply by 60 at bind time below.
    let offline_threshold_min: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'offline_threshold'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(60);
    let offline_threshold = offline_threshold_min * 60;

    let gc        = "GROUP_CONCAT(sg.name)".to_string();
    let created   = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.created_date), '')".to_string();
    let last_seen = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.last_seen), '')".to_string();
    let unix_diff = "(CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', s.last_seen) AS INTEGER))".to_string();

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
                    END AS is_offline,
                    s.cpu_usage, s.mem_used_mb, s.mem_total_mb,
                    s.disk_used_gb, s.disk_total_gb, s.uptime_secs
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
                    END AS is_offline,
                    s.cpu_usage, s.mem_used_mb, s.mem_total_mb,
                    s.disk_used_gb, s.disk_total_gb, s.uptime_secs
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

    // Fetch all agent packages once for upgrade-availability annotation.
    let agent_pkgs: HashMap<String, AgentPackage> = sqlx::query_as::<_, AgentPackage>(
        "SELECT platform, version, sha256, url FROM agent_packages",
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|p| (p.platform.clone(), p))
    .collect();

    let systems: Vec<System> = rows
        .into_iter()
        .map(|row| {
            let ver:  Option<String> = row.try_get("system_ver").ok();
            let arch: Option<String> = row.try_get("system_arch").ok();
            let os:   Option<String> = row.try_get("system_os").ok();

            // Derive platform on read from arch + os instead of persisting it,
            // so a server upgrade can change the normalisation rules without a
            // backfill migration.
            let platform = match (&arch, &os) {
                (Some(a), Some(o)) if a != "NA" && o != "NA" => Some(derive_platform(a, o)),
                _ => None,
            };

            // Determine upgrade availability: compare versions with semver.
            // Silently ignore unparseable version strings (very old agents may
            // not conform; they simply show no upgrade button).
            let (upgrade_available, upgrade_version) = if let (Some(pf), Some(cv)) = (&platform, &ver) {
                if let Some(pkg) = agent_pkgs.get(pf) {
                    let current  = Version::parse(cv).ok();
                    let available = Version::parse(&pkg.version).ok();
                    match (current, available) {
                        (Some(c), Some(a)) if a > c => (true, Some(pkg.version.clone())),
                        _ => (false, None),
                    }
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            };

            System {
                id:               row.try_get("system_id").unwrap_or(None),
                name:             row.get("system_name"),
                ver,
                ip:               row.try_get("system_ip").ok(),
                os,
                arch,
                platform,
                status:           row.try_get("system_status").ok(),
                groups:           row.try_get("group_names").ok(),
                auth_signature:   None,
                auth_public_key:  None,
                trust_challenge:  None,
                trust_proof:      None,
                created_date:     row.try_get::<String, _>("created_date").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
                last_seen:        row.try_get::<String, _>("last_seen").ok().and_then(|s| s.parse::<DateTime<Utc>>().ok()),
                is_offline:       row.try_get::<bool, _>("is_offline").unwrap_or(false),
                upgrade_available,
                upgrade_version,
                cpu_usage:        row.try_get("cpu_usage").ok(),
                mem_used_mb:      row.try_get("mem_used_mb").ok(),
                mem_total_mb:     row.try_get("mem_total_mb").ok(),
                disk_used_gb:     row.try_get("disk_used_gb").ok(),
                disk_total_gb:    row.try_get("disk_total_gb").ok(),
                uptime_secs:      row.try_get("uptime_secs").ok(),
                has_telemetry:    row.try_get::<Option<f32>, _>("cpu_usage").ok().flatten().is_some(),
            }
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
    let has_upgradable = systems.iter().any(|s| s.upgrade_available && !s.is_offline);
    context.insert("systems", &systems);
    context.insert("has_upgradable", &has_upgradable);
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
    ip: crate::handlers::ClientIp,
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
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "system.approve",
        Some("system"), Some(&id.to_string()),
        None,
    ).await;
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
    ip: crate::handlers::ClientIp,
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
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "system.delete",
        Some("system"), Some(&id.to_string()),
        None,
    ).await;
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
        platform: None,
        upgrade_available: false,
        upgrade_version: None,
        cpu_usage: None,
        mem_used_mb: None,
        mem_total_mb: None,
        disk_used_gb: None,
        disk_total_gb: None,
        uptime_secs: None,
        has_telemetry: false,
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
        gc      = "GROUP_CONCAT(sg.name)",
        created = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.created_date), '')",
        last_seen = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.last_seen), '')",
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
            platform: None,
            upgrade_available: false,
            upgrade_version: None,
            cpu_usage: None,
            mem_used_mb: None,
            mem_total_mb: None,
            disk_used_gb: None,
            disk_total_gb: None,
            uptime_secs: None,
            has_telemetry: false,
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
// System-group CRUD (list / add / edit / delete) was split out into
// `groups.rs` when this file passed ~1500 lines. `systems_bulk_add_group`
// below stays here because it operates on the systems table — it's a bulk
// action that assigns selected systems to a group id.
// ─────────────────────────────────────────────────────────────────────────────


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
        if let Err(e) = sqlx::query(
            "INSERT OR IGNORE INTO systems_in_groups (system_id, group_id, tenant_id) VALUES (?, ?, ?)",
        )
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
        last_seen = "COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', last_seen), '')",
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
            t.id          AS test_id,
            t.name        AS test_name,
            COALESCE(r.result, 'NOT_SCANNED') AS status,
            COALESCE(r.excluded, 0) AS is_excluded
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
        let test_id: Option<i64>               = row.try_get("test_id").ok();
        let test_name: String                  = row.get("test_name");
        let status_raw: String                 = row.get("status");
        let status = normalize_status(&status_raw).to_string();
        let is_excluded: bool = row.try_get::<i64, _>("is_excluded").unwrap_or(0) != 0;

        let entry = policy_map.entry(policy_id).or_insert_with(|| PolicyResultGroup {
            policy_id,
            policy_name,
            policy_version,
            policy_description,
            results: Vec::new(),
            is_passed: false,
            pass_count: 0,
            fail_count: 0,
            na_count: 0,
            excluded_count: 0,
        });

        // Excluded findings are treated as NA — they don't bump pass or fail counts.
        if is_excluded {
            entry.excluded_count += 1;
        } else {
            match status.as_str() {
                "PASS"                       => entry.pass_count += 1,
                "FAIL"                       => entry.fail_count += 1,
                "NA" | "NOT_SCANNED"         => entry.na_count   += 1,
                _ => {}
            }
        }
        entry.results.push(IndividualResult {
            test_name,
            status,
            is_excluded,
            // System report is read-only; no right-click menu, but show the badge.
            is_excludable: false,
            system_id: Some(system_id as i64),
            test_id,
        });
    }

    let mut policy_groups: Vec<PolicyResultGroup> = policy_map.into_values().collect();
    for p in &mut policy_groups {
        p.is_passed = is_system_passed(p.pass_count, p.fail_count);
    }

    let total_pass: usize = policy_groups.iter().map(|p| p.pass_count).sum();
    let total_fail: usize = policy_groups.iter().map(|p| p.fail_count).sum();
    // Excluded results are tallied alongside NA so the three counters add up
    // to total results without double-counting.
    let total_na: usize = policy_groups.iter()
        .flat_map(|p| p.results.iter())
        .filter(|r| r.is_excluded || r.status == "NA" || r.status == "NOT_SCANNED")
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

    let mut report = match fetch_system_report_data(id, &auth.tenant_id, &pool).await {
        Ok(r) => r,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %id, "Failed to fetch system report data");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Live system report — enable the right-click Exclude / Unexclude menu.
    // fetch_system_report_data marks rows non-excludable so save / PDF / archive
    // paths freeze the badge; we override that here for the interactive page only.
    for policy in &mut report.policy_groups {
        for r in &mut policy.results {
            r.is_excludable = true;
        }
    }

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

    // Pull live test metadata so the template can pop a detail modal when a
    // test row is clicked (mirrors the policy-report UX). Looked up by name
    // in the template; tests deleted/renamed since this report was rendered
    // simply fall through to plain text — no link.
    let tests_metadata = fetch_tenant_tests_metadata(&auth.tenant_id, &pool).await;

    let mut context = Context::new();
    context.insert("report", &report);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    context.insert("is_smtp_configured", &crate::reports::is_smtp_configured(&pool).await);
    context.insert("tests_metadata", &tests_metadata);
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


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/report/{system_id}/exclude/{test_id}
// Same effect as the policy-report exclude: flips the `excluded` flag on the
// matching `results` row. Distinct endpoint so the redirect lands back on the
// system report instead of a policy report.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_exclude(
    auth: AuthSession,
    Path((system_id, test_id)): Path<(i32, i32)>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let res = sqlx::query(
        "UPDATE results SET excluded = 1, excluded_by = ?, excluded_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ? AND system_id = ? AND test_id = ?",
    )
    .bind(&auth.username)
    .bind(&auth.tenant_id)
    .bind(system_id)
    .bind(test_id)
    .execute(&pool)
    .await;

    let back = format!("/systems/report/{}", system_id);
    match res {
        Ok(_) => {
            info!(
                "Result excluded by '{}' from system view — system={} test={}",
                auth.username, system_id, test_id
            );
            let _ = sync_tx.try_send(());
            let msg = urlencoding::encode("Finding excluded.").to_string();
            Redirect::to(&format!("{}?success_message={}", back, msg)).into_response()
        }
        Err(e) => {
            error!("Failed to insert result exclusion: {}", e);
            let msg = urlencoding::encode("Failed to exclude finding.").to_string();
            Redirect::to(&format!("{}?error_message={}", back, msg)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/report/{system_id}/unexclude/{test_id}
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_unexclude(
    auth: AuthSession,
    Path((system_id, test_id)): Path<(i32, i32)>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let res = sqlx::query(
        "UPDATE results SET excluded = 0, excluded_by = NULL, excluded_at = NULL
         WHERE tenant_id = ? AND system_id = ? AND test_id = ?",
    )
    .bind(&auth.tenant_id)
    .bind(system_id)
    .bind(test_id)
    .execute(&pool)
    .await;

    let back = format!("/systems/report/{}", system_id);
    match res {
        Ok(_) => {
            info!(
                "Result un-excluded by '{}' from system view — system={} test={}",
                auth.username, system_id, test_id
            );
            let _ = sync_tx.try_send(());
            let msg = urlencoding::encode("Finding restored.").to_string();
            Redirect::to(&format!("{}?success_message={}", back, msg)).into_response()
        }
        Err(e) => {
            error!("Failed to delete result exclusion: {}", e);
            let msg = urlencoding::encode("Failed to restore finding.").to_string();
            Redirect::to(&format!("{}?error_message={}", back, msg)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: fetch_tenant_tests_metadata
// Pulls every test (name + description + rational + remediation) for the
// given tenant, used by the system-report views so the template can pop a
// detail modal when a test row is clicked. Returns an empty vec on DB error
// — the template just falls back to non-clickable test names. Also re-used
// by reports.rs::system_reports_view (archive flavour).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn fetch_tenant_tests_metadata(
    tenant_id: &str,
    pool: &SqlitePool,
) -> Vec<TestMeta> {
    let rows = sqlx::query(
        "SELECT name, description, rational, remediation
         FROM tests WHERE tenant_id = ?",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rows.into_iter()
        .map(|row| TestMeta {
            name:        row.try_get::<String, _>("name").unwrap_or_default(),
            description: row.try_get::<Option<String>, _>("description").ok().flatten().unwrap_or_default(),
            rational:    row.try_get::<Option<String>, _>("rational").ok().flatten().unwrap_or_default(),
            remediation: row.try_get::<Option<String>, _>("remediation").ok().flatten().unwrap_or_default(),
        })
        .collect()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/upgrade/{id}
// Queue an upgrade for a single active system. Inserts a row into commands
// with command_type='UPGRADE'; the next heartbeat from that agent dispatches
// the UPGRADE and deletes the row. The partial unique index makes a repeat
// click idempotent — second insert is silently ignored.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_upgrade(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    // Verify the system exists and is active before queueing.
    let is_active: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM systems WHERE id = ? AND tenant_id = ? AND status = 'active'",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten();

    if is_active.is_none() {
        let msg = urlencoding::encode("System not found or not active.").to_string();
        return Redirect::to(&format!("/systems?error_message={}", msg)).into_response();
    }

    match sqlx::query(
        "INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id, command_type)
         VALUES (?, ?, NULL, 'UPGRADE')",
    )
    .bind(&auth.tenant_id)
    .bind(id)
    .execute(&pool)
    .await
    {
        Ok(_) => {
            info!("Upgrade queued for system ID {} by '{}'.", id, auth.username);
            crate::audit::record(
                &pool, &auth.tenant_id,
                Some(&auth), Some(ip.as_str()),
                "system.upgrade_queued",
                Some("system"), Some(&id.to_string()),
                None,
            ).await;
            let msg = urlencoding::encode("Upgrade queued — agent will upgrade on next check-in.").to_string();
            Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
        }
        Err(e) => {
            error!("Failed to queue upgrade for system {}: {}", id, e);
            let msg = urlencoding::encode(&format!("Error queuing upgrade: {}", e)).to_string();
            Redirect::to(&format!("/systems?error_message={}", msg)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/bulk/upgrade
// Queue upgrades for all selected active systems.
// Body: repeated `ids` form fields.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_bulk_upgrade(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
    raw_form: RawForm,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
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
        .filter_map(|s| s.parse::<i32>().ok())
        .collect();

    if ids.is_empty() {
        let msg = urlencoding::encode("No systems selected.").to_string();
        return Redirect::to(&format!("/systems?error_message={}", msg)).into_response();
    }

    // INSERT...SELECT FROM systems WHERE active in one query per id — same
    // result as a verify-then-insert but with half the round-trips.
    let mut queued: usize = 0;
    for id in &ids {
        match sqlx::query(
            "INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id, command_type)
             SELECT tenant_id, id, NULL, 'UPGRADE'
             FROM systems
             WHERE id = ? AND tenant_id = ? AND status = 'active'",
        )
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
        {
            Ok(r) if r.rows_affected() > 0 => queued += 1,
            Ok(_) => {}
            Err(e) => error!("Failed to queue upgrade for system {}: {}", id, e),
        }
    }

    info!(
        "Bulk upgrade queued for {}/{} system(s) by '{}'.",
        queued,
        ids.len(),
        auth.username
    );
    let id_list = ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "system.upgrade_queued_bulk",
        Some("system"), Some(&format!("ids:{}", id_list)),
        Some(&format!("{{\"requested\":{},\"queued\":{}}}", ids.len(), queued)),
    ).await;
    let msg = urlencoding::encode(&format!(
        "Upgrade queued for {} system(s) — agents will upgrade on next check-in.",
        queued
    ))
    .to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/upgrade_all
// Queue an upgrade for every active system that has a newer agent_packages
// row available for its platform. One-click "upgrade the fleet" — same
// semver-aware availability check as the per-row buttons, but applied to the
// whole tenant in a single transaction.
// Role: Admin
// ─────────────────────────────────────────────────────────────────────────────
pub async fn systems_upgrade_all(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    ip: crate::handlers::ClientIp,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    // Fetch every active system's (id, ver, arch, os) so we can derive each
    // platform and compare against agent_packages by semver — same logic the
    // /systems page applies at render time when it decides whether to show
    // the per-row Upgrade button.
    let rows = match sqlx::query(
        "SELECT id,
                COALESCE(ver,  '') AS ver,
                COALESCE(arch, '') AS arch,
                COALESCE(os,   '') AS os
         FROM systems
         WHERE tenant_id = ? AND status = 'active'",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("upgrade_all: failed to fetch systems: {}", e);
            let msg = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/systems?error_message={}", msg)).into_response();
        }
    };

    let agent_pkgs: HashMap<String, AgentPackage> = sqlx::query_as::<_, AgentPackage>(
        "SELECT platform, version, sha256, url FROM agent_packages",
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|p| (p.platform.clone(), p))
    .collect();

    // Find every system whose bundled agent_packages row is strictly newer
    // (by semver) than the system's reported version. Systems on platforms
    // we don't ship binaries for are skipped silently.
    let mut targets: Vec<i64> = Vec::new();
    for row in &rows {
        let id:   i64    = row.try_get("id").unwrap_or(0);
        let ver:  String = row.try_get("ver").unwrap_or_default();
        let arch: String = row.try_get("arch").unwrap_or_default();
        let os:   String = row.try_get("os").unwrap_or_default();

        if arch.is_empty() || os.is_empty() || ver.is_empty() {
            continue;
        }
        let platform = crate::agents::derive_platform(&arch, &os);
        let pkg = match agent_pkgs.get(&platform) {
            Some(p) => p,
            None    => continue,
        };
        let current   = Version::parse(&ver).ok();
        let available = Version::parse(&pkg.version).ok();
        if let (Some(c), Some(a)) = (current, available) {
            if a > c {
                targets.push(id);
            }
        }
    }

    if targets.is_empty() {
        let msg = urlencoding::encode("No systems are eligible for upgrade.").to_string();
        return Redirect::to(&format!("/systems?error_message={}", msg)).into_response();
    }

    // Queue the UPGRADE row per system. INSERT OR IGNORE means a system that
    // already has an upgrade pending stays at one row, so re-clicking
    // "Upgrade All" is idempotent.
    let mut queued: usize = 0;
    for id in &targets {
        match sqlx::query(
            "INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id, command_type)
             VALUES (?, ?, NULL, 'UPGRADE')",
        )
        .bind(&auth.tenant_id)
        .bind(id)
        .execute(&pool)
        .await
        {
            Ok(r) if r.rows_affected() > 0 => queued += 1,
            Ok(_) => {}  // already had a pending UPGRADE row
            Err(e) => error!("upgrade_all: queue failed for system {}: {}", id, e),
        }
    }

    info!(
        "Upgrade All queued for {}/{} eligible system(s) by '{}'.",
        queued,
        targets.len(),
        auth.username
    );
    let id_list = targets.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    crate::audit::record(
        &pool, &auth.tenant_id,
        Some(&auth), Some(ip.as_str()),
        "system.upgrade_queued_all",
        Some("system"), Some(&format!("ids:{}", id_list)),
        Some(&format!(
            "{{\"eligible\":{},\"queued\":{}}}",
            targets.len(), queued
        )),
    ).await;
    let msg = urlencoding::encode(&format!(
        "Upgrade queued for {} system(s) — agents will upgrade on next check-in.",
        queued
    )).to_string();
    Redirect::to(&format!("/systems?success_message={}", msg)).into_response()
}
