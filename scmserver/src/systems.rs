use axum::response::{IntoResponse, Redirect};
use axum::extract::{RawForm, Extension, Query, Path};
use tokio::sync::mpsc;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use std::collections::HashMap;
use tracing::{info, warn, error};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use crate::models::{ErrorQuery, System, SystemGroup, SystemInsideGroup, UserRole, AuthSession};
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data};


// ============================================================
// SYSTEMS
// ============================================================

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

    let rows_result = match filter.as_deref() {
        Some("active") | Some("pending") => {
            sqlx::query(
                r#"
                SELECT
                    s.id AS system_id,
                    COALESCE(s.name, 'NA') AS system_name,
                    COALESCE(s.ver, 'NA') AS system_ver,
                    COALESCE(s.ip, 'NA') AS system_ip,
                    COALESCE(s.os, 'NA') AS system_os,
                    COALESCE(s.arch, 'NA') AS system_arch,
                    COALESCE(s.status, 'NA') AS system_status,
                    COALESCE(GROUP_CONCAT(sg.name), 'none') AS group_names,
                    COALESCE(s.created_date, '') AS created_date,
                    COALESCE(s.last_seen, '') AS last_seen
                FROM systems AS s
                LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
                LEFT JOIN system_groups AS sg ON sig.group_id = sg.id
                WHERE s.status = ? AND s.tenant_id = ?
                GROUP BY s.id
                ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END, s.id ASC
                "#,
            )
            .bind(filter.as_deref().unwrap_or("active"))
            .bind(&auth.tenant_id)
            .fetch_all(&pool)
            .await
        }
        _ => {
            sqlx::query(
                r#"
                SELECT
                    s.id AS system_id,
                    COALESCE(s.name, 'NA') AS system_name,
                    COALESCE(s.ver, 'NA') AS system_ver,
                    COALESCE(s.ip, 'NA') AS system_ip,
                    COALESCE(s.os, 'NA') AS system_os,
                    COALESCE(s.arch, 'NA') AS system_arch,
                    COALESCE(s.status, 'NA') AS system_status,
                    COALESCE(GROUP_CONCAT(sg.name), 'none') AS group_names,
                    COALESCE(s.created_date, '') AS created_date,
                    COALESCE(s.last_seen, '') AS last_seen
                FROM systems AS s
                LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
                LEFT JOIN system_groups AS sg ON sig.group_id = sg.id
                WHERE s.tenant_id = ?
                GROUP BY s.id
                ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END, s.id ASC
                "#,
            )
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
            name: row.try_get("system_name").unwrap_or_default(),
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
            // Use .ok() so a NULL/unparseable timestamp becomes None instead of Utc::now()
            created_date: row.try_get::<DateTime<Utc>, _>("created_date").ok(),
            last_seen: row.try_get::<DateTime<Utc>, _>("last_seen").ok(),
        })
        .collect();


    let offline_threshold: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND key = 'offline_threshold'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(600);


    let groups_result = sqlx::query("SELECT id, name FROM system_groups WHERE tenant_id = ? ORDER BY name ASC")
        .bind(&auth.tenant_id)
        .fetch_all(&pool)
        .await;

    let groups: Vec<(i64, String)> = match groups_result {
        Ok(rows) => rows.into_iter().map(|r| (r.get("id"), r.get("name"))).collect(),
        Err(_) => vec![],
    };

    let mut context = Context::new();
    context.insert("offline_threshold", &offline_threshold);
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
        name: row.try_get("name").unwrap_or_default(),
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
                description: row.get("group_description"),
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


pub async fn systems_pending(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let rows_result = sqlx::query(
        r#"
        SELECT
            s.id AS system_id,
            COALESCE(s.name, 'NA') AS system_name,
            COALESCE(s.ver, 'NA') AS system_ver,
            COALESCE(s.ip, 'NA') AS system_ip,
            COALESCE(s.os, 'NA') AS system_os,
            COALESCE(s.arch, 'NA') AS system_arch,
            COALESCE(s.status, 'NA') AS system_status,
            COALESCE(GROUP_CONCAT(sg.name), 'none') AS group_names,
            COALESCE(s.created_date, '') AS created_date,
            COALESCE(s.last_seen, '') AS last_seen
        FROM systems AS s
        LEFT JOIN systems_in_groups AS sig ON s.id = sig.system_id
        LEFT JOIN system_groups AS sg ON sig.group_id = sg.id
        WHERE s.status = 'pending' AND s.tenant_id = ?
        GROUP BY s.id
        "#,
    )
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
            name: row.try_get("system_name").unwrap_or_default(),
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
            created_date: row.try_get::<DateTime<Utc>, _>("created_date").ok(),
            last_seen: row.try_get::<DateTime<Utc>, _>("last_seen").ok(),
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


// ============================================================
// SYSTEM GROUPS
// ============================================================

pub async fn system_groups(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let rows_result = sqlx::query(
        r#"
        SELECT
            sg.id,
            sg.name,
            sg.description,
            GROUP_CONCAT(s.name) AS systems
        FROM system_groups AS sg
        LEFT JOIN systems_in_groups AS sig ON sg.id = sig.group_id
        LEFT JOIN systems AS s ON sig.system_id = s.id
        WHERE sg.tenant_id = ?
        GROUP BY sg.id, sg.name, sg.description
        "#,
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let system_groups: Vec<SystemGroup> = match rows_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemGroup {
                id: Some(row.get("id")),
                name: row.get("name"),
                description: row.get("description"),
                systems: row.get("systems"),
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
                status: row.get("status"),
                groups: None,
                auth_signature: None,
                auth_public_key: None,
                trust_challenge: None,
                trust_proof: None,
                created_date: None,
                last_seen: None,
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
            let encoded =
                urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded))
                .into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    // Validate required fields
    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => {
            return Redirect::to("/system_groups?error_message=Group+name+is+required")
                .into_response();
        }
    };

    let description: Option<String> = form_data
        .get("description")
        .and_then(|v| v.first())
        .filter(|s| !s.is_empty())
        .cloned();

    let systems: Option<Vec<String>> = form_data.get("systems").cloned();

    let result = sqlx::query(
        "INSERT INTO system_groups (tenant_id, name, description) VALUES (?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&description)
    .execute(&mut *tx)
    .await;

    let group_id = match result {
        Ok(res) => res.last_insert_rowid(),
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/system_groups?error_message={}", encoded))
                .into_response();
        }
    };

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
                        let encoded =
                            urlencoding::encode(&format!("Failed to add system to group: {}", e))
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
                    let encoded =
                        urlencoding::encode(&format!("Invalid system ID: {}", system_id_str))
                            .to_string();
                    tx.rollback().await.ok();
                    return Redirect::to(&format!("/system_groups?error_message={}", encoded))
                        .into_response();
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
        name: row.try_get("name").unwrap_or_default(),
        description: row.try_get("description").unwrap_or(None),
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
                status: row.get("status"),
                groups: None,
                auth_signature: None,
                auth_public_key: None,
                trust_challenge: None,
                trust_proof: None,
                created_date: None,
                last_seen: None,
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

    // Validate required fields
    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.is_empty()) {
        Some(n) => n.clone(),
        None => {
            return Redirect::to("/system_groups?error_message=Group+name+is+required")
                .into_response();
        }
    };

    let description: Option<String> = form_data
        .get("description")
        .and_then(|v| v.first())
        .filter(|s| !s.is_empty())
        .cloned();

    let systems: Option<Vec<String>> = form_data.get("systems").cloned();

    if let Err(e) = sqlx::query(
        "UPDATE system_groups SET name = ?, description = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&name)
    .bind(&description)
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error updating group: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded)).into_response();
    }

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


    // Clean up results for tests no longer reachable through any policy
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


// ============================================================
// BULK ACTIONS
// ============================================================

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
