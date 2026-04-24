use axum::response::{Response, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{RawForm, Extension, Query, Path};
use tokio::sync::mpsc;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use std::collections::BTreeMap;
use tracing::{info, error};
use chrono::Local;
use genpdf::{fonts, elements, style, Element};

use crate::models::{
    ErrorQuery, SystemGroup, Test, Policy, PolicySchedule,
    SystemInsidePolicy, TestInsidePolicy, PolicyCompliance,
    ReportData, TestMeta, SystemReport, IndividualResult,
    UserRole, AuthSession,
};
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data, normalize_status};



// ============================================================
// HANDLERS
// ============================================================

pub async fn policies(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    // Check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    // Get applicable settings 
    let compliance_sat: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND key = 'compliance_sat'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&*pool)
    .await
    .unwrap_or(80);

    let compliance_marginal: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND key = 'compliance_marginal'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&*pool)
    .await
    .unwrap_or(60);


    // Get policies information
    let rows = match sqlx::query(r#"
        SELECT
            p.id AS policy_id,
            p.name AS policy_name,
            p.version AS policy_version,
            p.description AS policy_description,
            CAST(
                COALESCE(
                    ROUND(
                        SUM(CASE WHEN system_status = 'passed' THEN 1 ELSE 0 END) * 100.0
                        / NULLIF(COUNT(system_results.system_id), 0),
                        2
                    ),
                    -1.0
                ) AS REAL
            ) AS compliance,
            (SELECT COUNT(*) FROM tests_in_policy WHERE policy_id = p.id) as test_count,
            (SELECT COUNT(*) FROM systems_in_policy WHERE policy_id = p.id) as system_count
        FROM policies p
        LEFT JOIN (
            SELECT
                tip.policy_id,
                r.system_id,
                CASE
                    WHEN SUM(CASE WHEN r.result = 'FAIL' THEN 1 ELSE 0 END) > 0
                        THEN 'failed'
                    ELSE 'passed'
                END AS system_status
            FROM tests_in_policy tip
            JOIN results r ON r.test_id = tip.test_id
            GROUP BY tip.policy_id, r.system_id
        ) AS system_results ON p.id = system_results.policy_id
        WHERE p.tenant_id = ?
        GROUP BY p.id, p.name, p.version, p.description
        ORDER BY p.id ASC
    "#)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = ?e, "Failed to fetch policy compliance list");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let policies: Vec<PolicyCompliance> = rows
        .into_iter()
        .map(|row| PolicyCompliance {
            policy_id: row.get::<i64, _>("policy_id"),
            policy_name: row.get::<String, _>("policy_name"),
            policy_version: row.get::<String, _>("policy_version"),
            policy_description: Some(
                row.get::<Option<String>, _>("policy_description")
                    .unwrap_or_default(),
            ),
            compliance: row.get::<f64, _>("compliance"),
            test_count: row.get::<i64, _>("test_count"),
            system_count: row.get::<i64, _>("system_count"),
            systems_passed: None,
            systems_failed: None,
        })
        .collect();


    // Create context to send HTML
    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    context.insert("policies", &policies);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    render_template(&tera, Some(&pool), "policies.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn policies_add(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let tests_result = sqlx::query(
        "SELECT id, name, severity FROM tests WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let tests: Vec<Test> = match tests_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| Test {
                id: row.get("id"),
                name: row.get("name"),
                severity: row.get("severity"),
                ..Default::default()
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch tests for policy add: {}", e);
            vec![]
        }
    };

    let groups_result = sqlx::query(
        "SELECT id, name FROM system_groups WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let system_groups: Vec<SystemGroup> = match groups_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| SystemGroup {
                id: row.get("id"),
                name: row.get("name"),
                ..Default::default()
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch system groups for policy add: {}", e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("tests", &tests);
    context.insert("system_groups", &system_groups);
    render_template(&tera, Some(&pool), "policies_add.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn policies_add_save(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    RawForm(raw_form): RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    };

    let raw_string = match String::from_utf8(raw_form.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/policies?error_message=Policy+name+is+required").into_response(),
    };

    let version = match form_data.get("version").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/policies?error_message=Version+is+required").into_response(),
    };

    let description: Option<String> = form_data
        .get("description")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let tests = form_data.get("tests").cloned().unwrap_or_default();
    let system_groups = form_data.get("system_groups").cloned().unwrap_or_default();

    let schedule_enabled = form_data
        .get("schedule_enabled")
        .and_then(|v| v.first())
        .map(|v| v == "on")
        .unwrap_or(false);
    let frequency = form_data
        .get("frequency")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "daily".to_string());
    let cron_val = form_data.get("cron_val").and_then(|v| v.first()).cloned();
    let next_run = form_data.get("next_run").and_then(|v| v.first()).cloned();

    // Insert policy with tenant_id
    let result = sqlx::query(
        "INSERT INTO policies (tenant_id, name, version, description) VALUES (?, ?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&version)
    .bind(&description)
    .execute(&mut *tx)
    .await;

    let policy_id = match result {
        Ok(res) => res.last_insert_rowid(),
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    };

    // Insert schedule if enabled
    if schedule_enabled {
        let start_time = next_run
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Local::now().format("%Y-%m-%dT%H:%M").to_string());

        if let Err(e) = sqlx::query(
            "INSERT INTO policy_schedules (tenant_id, policy_id, enabled, frequency, cron_expression, next_run)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&auth.tenant_id)
        .bind(policy_id)
        .bind(1)
        .bind(&frequency)
        .bind(&cron_val)
        .bind(&start_time)
        .execute(&mut *tx)
        .await
        {
            let encoded = urlencoding::encode(&format!("Schedule error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    }

    // Insert tests
    for test_id_str in tests {
        if let Ok(test_id) = test_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES (?, ?, ?)",
            )
            .bind(&auth.tenant_id)
            .bind(policy_id)
            .bind(test_id)
            .execute(&mut *tx)
            .await
            {
                let encoded = urlencoding::encode(&format!("Failed to add test: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
            }
        }
    }

    // Insert system groups
    for group_id_str in system_groups {
        if let Ok(group_id) = group_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES (?, ?, ?)",
            )
            .bind(&auth.tenant_id)
            .bind(policy_id)
            .bind(group_id)
            .execute(&mut *tx)
            .await
            {
                let encoded =
                    urlencoding::encode(&format!("Failed to add system group: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
            }
        }
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    info!("Policy '{}' created by '{}'.", name, auth.username);
    Redirect::to("/policies").into_response()
}


pub async fn policies_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let row_result = sqlx::query(
        "SELECT id, name, version, description FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/policies?error_message=Policy+not+found").into_response(),
        Err(e) => {
            error!("Database error fetching policy {}: {}", id, e);
            return Redirect::to("/policies?error_message=Database+error").into_response();
        }
    };

    let policy = Policy {
        id: row.get("id"),
        name: row.get("name"),
        version: row.get("version"),
        description: row.get("description"),
    };

    let schedule_row = sqlx::query_as::<_, PolicySchedule>(
        "SELECT id, tenant_id, policy_id, enabled, frequency, cron_expression, next_run, last_run
         FROM policy_schedules WHERE policy_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await
    .unwrap_or(None);

    let tests_result = sqlx::query(
        "SELECT id, name, severity FROM tests WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let test_groups: Vec<Test> = match tests_result {
        Ok(rows) => rows
            .into_iter()
            .map(|r| Test {
                id: r.get("id"),
                name: r.get("name"),
                severity: r.get("severity"),
                ..Default::default()
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch tests for policy edit {}: {}", id, e);
            vec![]
        }
    };

    let groups_result = sqlx::query(
        "SELECT id, name FROM system_groups WHERE tenant_id = ?",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let system_groups: Vec<SystemGroup> = match groups_result {
        Ok(rows) => rows
            .into_iter()
            .map(|r| SystemGroup {
                id: r.get("id"),
                name: r.get("name"),
                ..Default::default()
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch system groups for policy edit {}: {}", id, e);
            vec![]
        }
    };

    let tip_result = sqlx::query(
        "SELECT policy_id, test_id FROM tests_in_policy WHERE policy_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let tests_in_policy: Vec<TestInsidePolicy> = match tip_result {
        Ok(rows) => rows
            .into_iter()
            .map(|r| TestInsidePolicy {
                policy_id: r.get("policy_id"),
                test_id: r.get("test_id"),
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch tests in policy {}: {}", id, e);
            vec![]
        }
    };

    let sip_result = sqlx::query(
        "SELECT policy_id, group_id FROM systems_in_policy WHERE policy_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let systems_in_policy: Vec<SystemInsidePolicy> = match sip_result {
        Ok(rows) => rows
            .into_iter()
            .map(|r| SystemInsidePolicy {
                policy_id: r.get("policy_id"),
                group_id: r.get("group_id"),
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch systems in policy {}: {}", id, e);
            vec![]
        }
    };

    let mut context = Context::new();
    context.insert("policy", &policy);
    context.insert("schedule", &schedule_row);
    context.insert("tests", &test_groups);
    context.insert("system_groups", &system_groups);
    context.insert("tests_in_policy", &tests_in_policy);
    context.insert("systems_in_policy", &systems_in_policy);
    render_template(&tera, Some(&pool), "policies_edit.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn policies_edit_save(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    RawForm(raw_form): RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
        }
    };

    let raw_string = String::from_utf8_lossy(&raw_form).to_string();
    let form_data = parse_form_data(&raw_string);

    let name = match form_data.get("name").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => {
            tx.rollback().await.ok();
            return Redirect::to("/policies?error_message=Policy+name+is+required").into_response();
        }
    };

    let version = match form_data.get("version").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => {
            tx.rollback().await.ok();
            return Redirect::to("/policies?error_message=Version+is+required").into_response();
        }
    };

    let description = form_data
        .get("description")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let schedule_enabled = form_data
        .get("schedule_enabled")
        .and_then(|v| v.first())
        .map(|v| v == "on")
        .unwrap_or(false);
    let frequency = form_data
        .get("frequency")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "daily".to_string());
    let cron_val = form_data.get("cron_val").and_then(|v| v.first()).cloned();
    let next_run = form_data.get("next_run").and_then(|v| v.first()).cloned();

    // Update policy metadata
    if let Err(e) = sqlx::query(
        "UPDATE policies SET name = ?, version = ?, description = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&name)
    .bind(&version)
    .bind(&description)
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error updating policy: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    // Upsert schedule
    let start_time = next_run
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| Local::now().format("%Y-%m-%dT%H:%M").to_string());

    if let Err(e) = sqlx::query(r#"
        INSERT INTO policy_schedules (tenant_id, policy_id, enabled, frequency, cron_expression, next_run)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(policy_id) DO UPDATE SET
            enabled = excluded.enabled,
            frequency = excluded.frequency,
            cron_expression = excluded.cron_expression,
            next_run = excluded.next_run
    "#)
    .bind(&auth.tenant_id)
    .bind(id)
    .bind(schedule_enabled)
    .bind(&frequency)
    .bind(&cron_val)
    .bind(&start_time)
    .execute(&mut *tx)
    .await
    {
        let encoded =
            urlencoding::encode(&format!("Schedule update error: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    // Clear and re-insert tests
    if let Err(e) = sqlx::query(
        "DELETE FROM tests_in_policy WHERE policy_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error clearing tests: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    for test_id_str in form_data.get("tests").cloned().unwrap_or_default() {
        if let Ok(test_id) = test_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES (?, ?, ?)",
            )
            .bind(&auth.tenant_id)
            .bind(id)
            .bind(test_id)
            .execute(&mut *tx)
            .await
            {
                let encoded =
                    urlencoding::encode(&format!("Error adding test: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
            }
        }
    }

    // Clear and re-insert system groups
    if let Err(e) = sqlx::query(
        "DELETE FROM systems_in_policy WHERE policy_id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded =
            urlencoding::encode(&format!("Error clearing system groups: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    for group_id_str in form_data.get("system_groups").cloned().unwrap_or_default() {
        if let Ok(group_id) = group_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query(
                "INSERT OR IGNORE INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES (?, ?, ?)",
            )
            .bind(&auth.tenant_id)
            .bind(id)
            .bind(group_id)
            .execute(&mut *tx)
            .await
            {
                let encoded =
                    urlencoding::encode(&format!("Error adding system group: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
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
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }





    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("Policy ID {} updated by '{}'.", id, auth.username);
    Redirect::to("/policies").into_response()
}


pub async fn policies_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }


    // Before DELETE FROM policies:
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
            AND tip.policy_id != ?
        )
    "#)
    .bind(&auth.tenant_id)
    .bind(&auth.tenant_id)
    .bind(id)
    .execute(&pool)
    .await
    {
        error!("Failed to clean up results for deleted policy {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error cleaning up results: {}", e)).to_string();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }


    // ON DELETE CASCADE handles related records automatically
    if let Err(e) = sqlx::query(
        "DELETE FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&pool)
    .await
    {
        error!("Failed to delete policy {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting policy: {}", e)).to_string();
        return Redirect::to(&format!("/policies?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("Policy ID {} deleted by '{}'.", id, auth.username);
    Redirect::to("/policies").into_response()
}


pub async fn policies_run(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    match execute_policy_run_logic(id, &pool, &auth.tenant_id).await {
        Ok(_) => {
            info!("Policy ID {} run by '{}'.", id, auth.username);
            Redirect::to("/policies?success_message=Policy+run+successfully").into_response()
        }
        Err(e) => {
            error!("Failed to run policy {}: {}", id, e);
            let encoded = urlencoding::encode(&format!("Error running policy: {}", e)).to_string();
            Redirect::to(&format!("/policies?error_message={}", encoded)).into_response()
        }
    }
}


pub async fn policies_report(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let policy_row = match sqlx::query(
        "SELECT id, name, version, description FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(error = ?e, policy_id = %id, "Failed to fetch policy details");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let test_rows = match sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation
        FROM tests t
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE tip.policy_id = ? AND tip.tenant_id = ?
    "#)
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = ?e, policy_id = %id, "Failed to fetch tests for policy report");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let tests_metadata: Vec<TestMeta> = test_rows
        .into_iter()
        .map(|row| TestMeta {
            name: row.get("name"),
            description: row.get("description"),
            rational: row.get("rational"),
            remediation: row.get("remediation"),
        })
        .collect();

    let result_rows = match sqlx::query(r#"
        SELECT
            s.name as system_name,
            t.name as test_name,
            r.result as status
        FROM results r
        JOIN systems s ON r.system_id = s.id AND r.tenant_id = s.tenant_id
        JOIN tests t ON r.test_id = t.id AND r.tenant_id = t.tenant_id
        WHERE r.tenant_id = ?
          AND r.test_id IN (
              SELECT test_id FROM tests_in_policy
              WHERE policy_id = ? AND tenant_id = ?
          )
          AND r.system_id IN (
              SELECT sig.system_id FROM systems_in_groups sig
              JOIN systems_in_policy sip ON sig.group_id = sip.group_id
                  AND sig.tenant_id = sip.tenant_id
              WHERE sip.policy_id = ? AND sip.tenant_id = ?
          )
    "#)
    .bind(&auth.tenant_id)
    .bind(id)
    .bind(&auth.tenant_id)
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = ?e, policy_id = %id, "Failed to fetch policy results");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut system_map: BTreeMap<String, Vec<IndividualResult>> = BTreeMap::new();
    for row in result_rows {
        let system_name = row
            .get::<Option<String>, _>("system_name")
            .unwrap_or_else(|| "Unknown System".to_string());
        let test_name: String = row.get("test_name");
        let status_raw: String = row.get("status");
        let status = normalize_status(&status_raw).to_string();
        system_map
            .entry(system_name)
            .or_insert_with(Vec::new)
            .push(IndividualResult { test_name, status });
    }

    let system_reports: Vec<SystemReport> = system_map
        .into_iter()
        .map(|(name, results)| {
            let is_passed = results.iter().all(|r| r.status == "PASS" || r.status == "NA")
                && results.iter().any(|r| r.status == "PASS");
            SystemReport { system_name: name, results, is_passed }
        })
        .collect();

    let fail_count = system_reports.iter().filter(|s| !s.is_passed && s.results.iter().any(|r| r.status != "NA")).count();

    let report_data = ReportData {
        policy_id: policy_row.get("id"),
        policy_name: policy_row.get("name"),
        version: policy_row.get("version"),
        description: policy_row
            .get::<Option<String>, _>("description")
            .unwrap_or_default(),
        submission_date: Local::now().format("%Y-%m-%d %H:%M").to_string(),
        submitter_name: auth.username.clone(),
        tests_metadata,
        system_reports,
    };

    let mut context = Context::new();
    context.insert("report", &report_data);
    context.insert("fail_count", &fail_count);
    render_template(&tera, Some(&pool), "policies_report.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn policies_report_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let policy_row = match sqlx::query(
        "SELECT id, name, version, description FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!("Failed to fetch policy {} for PDF: {}", id, e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let test_rows = match sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation
        FROM tests t
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE tip.policy_id = ? AND tip.tenant_id = ?
    "#)
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch tests for PDF {}: {}", id, e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let tests_metadata: Vec<TestMeta> = test_rows
        .into_iter()
        .map(|row| TestMeta {
            name: row.get("name"),
            description: row
                .get::<Option<String>, _>("description")
                .unwrap_or_default(),
            rational: row
                .get::<Option<String>, _>("rational")
                .unwrap_or_default(),
            remediation: row
                .get::<Option<String>, _>("remediation")
                .unwrap_or_default(),
        })
        .collect();

    let result_rows = match sqlx::query(r#"
        SELECT DISTINCT
            s.name as system_name,
            t.name as test_name,
            r.result as status
        FROM results r
        JOIN systems s ON r.system_id = s.id
        JOIN tests t ON r.test_id = t.id
        JOIN systems_in_groups sig ON s.id = sig.system_id
        JOIN systems_in_policy sip ON sig.group_id = sip.group_id
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE sip.policy_id = ?
          AND tip.policy_id = ?
          AND sip.tenant_id = ?
    "#)
    .bind(id)
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch results for PDF {}: {}", id, e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut system_map: BTreeMap<String, Vec<IndividualResult>> = BTreeMap::new();
    for row in result_rows {
        let system_name = row
            .get::<Option<String>, _>("system_name")
            .unwrap_or_else(|| "Unknown System".to_string());
        let test_name: String = row.get("test_name");
        let status_raw: String = row.get("status");
        let status = normalize_status(&status_raw).to_string();
        system_map
            .entry(system_name)
            .or_insert_with(Vec::new)
            .push(IndividualResult { test_name, status });
    }

    let system_reports: Vec<SystemReport> = system_map
        .into_iter()
        .map(|(name, results)| {
            let is_passed = results.iter().all(|r| r.status == "PASS" || r.status == "NA")
                && results.iter().any(|r| r.status == "PASS");
            SystemReport { system_name: name, results, is_passed }
        })
        .collect();

    let report_data = ReportData {
        policy_id: policy_row.get("id"),
        policy_name: policy_row.get("name"),
        version: policy_row.get("version"),
        description: policy_row
            .get::<Option<String>, _>("description")
            .unwrap_or_default(),
        submission_date: Local::now().format("%b %d, %Y %I:%M %p").to_string(),
        submitter_name: auth.username.clone(),
        tests_metadata,
        system_reports,
    };

    // PDF Generation
    const FONT_REGULAR: &[u8] =
        include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD: &[u8] =
        include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC: &[u8] =
        include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] =
        include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES: &[u8] =
        include_bytes!("../static/dist/img/Logo_report.jpg");

    let font_family = match (
        fonts::FontData::new(FONT_REGULAR.to_vec(), None),
        fonts::FontData::new(FONT_BOLD.to_vec(), None),
        fonts::FontData::new(FONT_ITALIC.to_vec(), None),
        fonts::FontData::new(FONT_BOLD_ITALIC.to_vec(), None),
    ) {
        (Ok(regular), Ok(bold), Ok(italic), Ok(bold_italic)) => fonts::FontFamily {
            regular,
            bold,
            italic,
            bold_italic,
        },
        _ => {
            error!("Failed to load PDF fonts");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut doc = genpdf::Document::new(font_family);

    let cursor = std::io::Cursor::new(LOGO_BYTES);
    let mut logo = match elements::Image::from_reader(cursor) {
        Ok(img) => img,
        Err(e) => {
            error!("Failed to load PDF logo: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    doc.set_title(format!(
        "OpenSCM Compliance Report - {}",
        report_data.policy_name
    ));
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // Title
    let mut title = elements::Paragraph::new("OpenSCM Compliance Report");
    title.set_alignment(genpdf::Alignment::Center);
    doc.push(title.styled(
        style::Style::new()
            .with_font_size(30)
            .bold()
            .with_color(style::Color::Rgb(0, 0, 128)),
    ));
    doc.push(elements::Break::new(2.0));

    let mut submitter = elements::Paragraph::new(format!(
        "Generated on {} by {}",
        report_data.submission_date, report_data.submitter_name
    ));
    submitter.set_alignment(genpdf::Alignment::Center);
    doc.push(submitter);
    doc.push(elements::Break::new(0.5));

    logo.set_dpi(40.0);
    logo.set_alignment(genpdf::Alignment::Center);
    doc.push(logo);
    doc.push(elements::Break::new(1.0));

    // Report details table
    doc.push(elements::Text::new("Report Details").styled(style::Style::new().bold().with_font_size(14)));
    doc.push(elements::Break::new(0.5));
    let mut details_table = elements::TableLayout::new(vec![1, 3]);
    details_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));

    if let Err(e) = details_table.push_row(vec![
        Box::new(elements::Text::new("Policy Name").styled(style::Style::new().bold())),
        Box::new(elements::Paragraph::new(format!(
            " {} v{}",
            report_data.policy_name, report_data.version
        ))),
    ]) {
        error!("Failed to add policy name row to PDF: {}", e);
    }

    if let Err(e) = details_table.push_row(vec![
        Box::new(elements::Text::new("Description").styled(style::Style::new().bold())),
        Box::new(elements::Paragraph::new(format!(" {}", report_data.description))),
    ]) {
        error!("Failed to add description row to PDF: {}", e);
    }

    doc.push(details_table);
    doc.push(elements::PageBreak::new());

    // Per-system audit section
    for system in report_data.system_reports {
        doc.push(
            elements::Text::new(format!("Host Name: {}", system.system_name))
                .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        let compliant_count = system.results.iter().filter(|r| r.status == "PASS").count();
        let violation_count = system.results.len() - compliant_count;

        let mut summary_table = elements::TableLayout::new(vec![1, 1]);
        summary_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));

        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Compliance Status").styled(style::Style::new().bold())),
            Box::new(
                elements::Text::new(if system.is_passed {
                    " Compliant"
                } else {
                    " Non-Compliant"
                })
                .styled(
                    style::Style::new()
                        .with_color(if system.is_passed {
                            style::Color::Rgb(0, 128, 0)
                        } else {
                            style::Color::Rgb(200, 0, 0)
                        })
                        .bold(),
                ),
            ),
        ]) {
            error!("Failed to add compliance status row to PDF: {}", e);
        }

        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Violation Rule Count").styled(style::Style::new().bold())),
            Box::new(elements::Text::new(format!(" Critical - {}", violation_count))),
        ]) {
            error!("Failed to add violation count row to PDF: {}", e);
        }

        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Compliant Rule Count").styled(style::Style::new().bold())),
            Box::new(elements::Text::new(format!(" {}", compliant_count))),
        ]) {
            error!("Failed to add compliant count row to PDF: {}", e);
        }

        doc.push(summary_table);
        doc.push(elements::Break::new(1.0));

        // Rules breakdown
        doc.push(
            elements::Text::new("Audit Rules Detailed Breakdown")
                    .styled(style::Style::new().bold().with_font_size(14)),    
        );
        doc.push(elements::Break::new(0.5));
        let mut rules_table = elements::TableLayout::new(vec![4, 1]);
        rules_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));

        if let Err(e) = rules_table.push_row(vec![
            Box::new(elements::Text::new("Rule Name").styled(style::Style::new().bold())),
            Box::new(elements::Text::new("Status").styled(style::Style::new().bold())),
        ]) {
            error!("Failed to add rules table header to PDF: {}", e);
        }

        for res in &system.results {
            let is_pass = res.status == "PASS";
            let (status_text, status_color) = if is_pass {
                ("PASS", style::Color::Rgb(0, 128, 0))
            } else {
                ("FAIL", style::Color::Rgb(200, 0, 0))
            };

            if let Err(e) = rules_table.push_row(vec![
                Box::new(elements::Paragraph::new(format!(" {}", res.test_name))),
                Box::new(
                    elements::Text::new(status_text)
                        .styled(style::Style::new().with_color(status_color).bold()),
                ),
            ]) {
                error!("Failed to add rule row to PDF: {}", e);
            }
        }

        doc.push(rules_table);
        doc.push(elements::PageBreak::new());
    }

    doc.push(elements::Break::new(2.0));
    doc.push(
        elements::Paragraph::new(
            "Note: This report contains confidential information about your infrastructure \
             and should be treated as such. Unauthorized distribution is strictly prohibited.",
        )
        .styled(
            style::Style::new()
                .with_font_size(10)
                .with_color(style::Color::Rgb(100, 100, 100)),
        ),
    );

    // Render PDF
    let mut buffer = Vec::new();
    if let Err(e) = doc.render(&mut buffer) {
        error!("Failed to render PDF for policy {}: {}", id, e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"OpenSCM_Report_{}.pdf\"", id),
        )
        .body(axum::body::Body::from(buffer))
        .unwrap_or_else(|e| {
            error!("Failed to build PDF response: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}


// ============================================================
// INTERNAL LOGIC
// ============================================================

pub async fn execute_policy_run_logic(
    id: i32,
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(r#"
        INSERT OR IGNORE INTO commands (tenant_id, system_id, test_id)
        SELECT ?, sig.system_id, tip.test_id
        FROM systems_in_policy sip
        JOIN systems_in_groups sig ON sip.group_id = sig.group_id
        JOIN tests_in_policy tip ON sip.policy_id = tip.policy_id
        WHERE sip.policy_id = ?
          AND sip.tenant_id = ?
    "#)
    .bind(tenant_id)
    .bind(id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}
