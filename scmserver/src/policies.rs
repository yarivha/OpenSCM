use axum::response::{Response, IntoResponse, Redirect};
use axum::http::{StatusCode,header} ;
use axum::extract::{RawForm, Extension, Query, Path};
use tokio::sync::mpsc;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use std::collections::BTreeMap;
use tracing::{info, warn,error};
use chrono::Local;
use genpdf::{fonts, elements, style, Element};


use crate::models::ErrorQuery;
use crate::models::SystemGroup;
use crate::models::Test;
use crate::models::Policy;
use crate::models::PolicySchedule;
use crate::models::SystemInsidePolicy;
use crate::models::TestInsidePolicy;
use crate::models::PolicyCompliance;
use crate::models::ReportData;
use crate::models::TestMeta;
use crate::models::SystemReport;
use crate::models::IndividualResult;
use crate::models::UserRole;
use crate::auth::{self, AuthSession};
use crate::handlers::render_template;
use crate::handlers::parse_form_data;



// policies
pub async fn policies(auth: AuthSession, Query(query): Query<ErrorQuery>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
-> impl IntoResponse  {
    
    // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
       return redir;
    }

    let rows = match sqlx::query(r#"
            SELECT 
                p.id AS policy_id,
                p.name AS policy_name,
                p.version AS policy_version,
                p.description AS policy_description,
                -- Existing Compliance Logic
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
                -- New: Subqueries for counts
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
            GROUP BY p.id, p.name, p.version, p.description
            ORDER BY p.id ASC
        "#)
        .fetch_all(&*pool)
        .await 
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = ?e, "Database query failed: Unable to calculate policy compliance list");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let policies: Vec<PolicyCompliance> = rows.into_iter().map(|row| {
        PolicyCompliance {
            policy_id: row.get::<i64, _>("policy_id"),
            policy_name: row.get::<String, _>("policy_name"),
            policy_version: row.get::<String, _>("policy_version"),
            policy_description: Some(row.get::<Option<String>, _>("policy_description").unwrap_or_default()),
            compliance: row.get::<f64, _>("compliance"),
            
            // Map the new count fields here
            test_count: row.get::<i64, _>("test_count"),
            system_count: row.get::<i64, _>("system_count"),

            systems_passed: None,
            systems_failed: None,
        }
    }).collect();

    // Prepare handler-specific context
    let mut context = Context::new();
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    if let Some(success_message) = query.success_message {
        context.insert("success_message", &success_message);
    }
    context.insert("policies", &policies);
    
    render_template(&tera, Some(&pool), "policies.html", context, Some(auth)).await.into_response()
}




// policies_add
pub async fn policies_add(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
    -> impl IntoResponse {

     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
       return redir;
    }
    

    let rows = sqlx::query("
        SELECT id,name,severity from tests")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let tests: Vec<Test> = rows.into_iter().map(|row| {
        Test {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
            rational: None,
            remediation: None,
            severity: row.get("severity"),
            filter: None,
            element_1: None,
            input_1: None,
            selement_1: None,
            condition_1: None,
            sinput_1: None,
            element_2: None,
            input_2: None,
            selement_2: None,
            condition_2: None,
            sinput_2: None,
            element_3: None,
            input_3: None,
            selement_3: None,
            condition_3: None,
            sinput_3: None,
            element_4: None,
            input_4: None,
            selement_4: None,
            condition_4: None,
            sinput_4: None,
            element_5: None,
            input_5: None,
            selement_5: None,
            condition_5: None,
            sinput_5: None,
        }
    }).collect();

    let rows = sqlx::query("
        SELECT id,name from system_groups")
        .fetch_all(&*pool)
        .await
        .unwrap();
    let system_groups: Vec<SystemGroup> = rows.into_iter().map(|row| {
        SystemGroup {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
            systems: None,
    }
    }).collect();

    let mut context = Context::new();
    context.insert("tests", &tests);
    context.insert("system_groups",&system_groups);
    render_template(&tera,Some(&pool), "policies_add.html", context, Some(auth)).await.into_response()
}



//policies_add_save

// policies_add_save
pub async fn policies_add_save(auth: AuthSession, Extension(pool): Extension<SqlitePool>, RawForm(raw_form): RawForm) 
        -> impl IntoResponse {
    
    // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
       return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message)).into_response();
        }
    };

    let raw_string = match String::from_utf8(raw_form.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message)).into_response();
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // Required fields
    let name = match form_data.get("name").and_then(|v| v.first()) {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => return Redirect::to("/policies?error_message=Name is required").into_response(),
    };

    let version = match form_data.get("version").and_then(|v| v.first()) {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => return Redirect::to("/policies?error_message=Version is required").into_response(),
    };

    let description: Option<String> = form_data
        .get("description")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Multi-selects
    let tests = form_data.get("tests").cloned().unwrap_or_default();
    let system_groups = form_data.get("system_groups").cloned().unwrap_or_default();

    // --- NEW: Automation Fields ---
    // Browsers send "on" for checked checkboxes in form data
    let schedule_enabled = form_data.get("schedule_enabled").and_then(|v| v.first()).map(|v| v == "on").unwrap_or(false);
    let frequency = form_data.get("frequency").and_then(|v| v.first()).cloned().unwrap_or_else(|| "daily".to_string());
    let cron_val = form_data.get("cron_val").and_then(|v| v.first()).cloned();
    let next_run = form_data.get("next_run").and_then(|v| v.first()).cloned();

    // Insert Policy
    let result = sqlx::query("INSERT INTO policies (name, version, description) VALUES (?, ?, ?)")
        .bind(&name).bind(&version).bind(&description)
        .execute(&mut *tx).await;

    let policy_id = match result {
        Ok(res) => res.last_insert_rowid(),
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message)).into_response();
        }
    };

    // --- NEW: Insert Schedule if enabled ---
    if schedule_enabled {
        // Fallback to current time if user didn't pick a specific start time
        let start_time = next_run.filter(|s| !s.is_empty())
            .unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%dT%H:%M").to_string());

        if let Err(e) = sqlx::query(
            "INSERT INTO policy_schedules (policy_id, enabled, frequency, cron_expression, next_run) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(policy_id)
        .bind(1) // enabled
        .bind(&frequency)
        .bind(&cron_val)
        .bind(&start_time)
        .execute(&mut *tx)
        .await 
        {
            let error_message = format!("Schedule error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message)).into_response();
        }
    }

    // Insert Tests
    for test_id_str in tests {
        if let Ok(test_id) = test_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query("INSERT OR IGNORE INTO tests_in_policy (policy_id, test_id) VALUES (?, ?)")
                .bind(policy_id).bind(test_id)
                .execute(&mut *tx).await {
                return Redirect::to(&format!("/policies?error_message={}", urlencoding::encode(&e.to_string()))).into_response();
            }
        }
    }

    // Insert System Groups
    for group_id_str in system_groups {
        if let Ok(group_id) = group_id_str.parse::<i32>() {
            if let Err(e) = sqlx::query("INSERT OR IGNORE INTO systems_in_policy (policy_id, group_id) VALUES (?, ?)")
                .bind(policy_id).bind(group_id)
                .execute(&mut *tx).await {
                return Redirect::to(&format!("/policies?error_message={}", urlencoding::encode(&e.to_string()))).into_response();
            }
        }
    }

    // Commit
    if let Err(e) = tx.commit().await {
        return Redirect::to(&format!("/policies?error_message={}", urlencoding::encode(&e.to_string()))).into_response();
    }

    Redirect::to("/policies").into_response()
}



// policies_edit
pub async fn policies_edit(
    auth: AuthSession, 
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>
) -> impl IntoResponse {

    // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
       return redir;
    }

    // 1. Fetch Policy Metadata
    let row_result = sqlx::query("SELECT id, name, version, description FROM policies WHERE id = ?")
        .bind(id)
        .fetch_optional(&*pool)
        .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/policies?error_message=Policy+not+found").into_response(),
        Err(e) => {
            error!("Database error: {}", e);
            return Redirect::to("/policies?error_message=Database+error").into_response();
        }
    };

    let policy = Policy {
        id: row.get("id"),
        name: row.get("name"),
        version: row.get("version"),
        description: row.get("description"),
    };

    // 2. NEW: Fetch Schedule Data
    let schedule_row = sqlx::query_as::<_, PolicySchedule>(
        "SELECT id, policy_id, enabled, frequency, cron_expression, next_run, last_run 
         FROM policy_schedules WHERE policy_id = ?"
    )
    .bind(id)
    .fetch_optional(&*pool)
    .await
    .unwrap_or(None); // If no schedule exists, we just pass None to the template

    // 3. Fetch All Available Tests (for the dual listbox)
    let test_rows = sqlx::query("SELECT id, name, severity FROM tests")
        .fetch_all(&*pool)
        .await
        .unwrap();
        
    let test_groups: Vec<Test> = test_rows.into_iter().map(|r| {
        Test { id: r.get("id"), name: r.get("name"), severity: r.get("severity"), ..Default::default() }
    }).collect();

    // 4. Fetch All Available System Groups (for the dual listbox)
    let group_rows = sqlx::query("SELECT id, name FROM system_groups")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let system_groups: Vec<SystemGroup> = group_rows.into_iter().map(|r| {
        SystemGroup { id: r.get("id"), name: r.get("name"), ..Default::default() }
    }).collect();

    // 5. Fetch existing connections (Tests in this policy)
    let tip_rows = sqlx::query("SELECT policy_id, test_id FROM tests_in_policy WHERE policy_id = ?")
        .bind(id)
        .fetch_all(&*pool)
        .await
        .unwrap();

    let tests_in_policy: Vec<TestInsidePolicy> = tip_rows.into_iter().map(|r| {
        TestInsidePolicy { policy_id: r.get("policy_id"), test_id: r.get("test_id") }
    }).collect();

    // 6. Fetch existing connections (Systems in this policy)
    let sip_rows = sqlx::query("SELECT policy_id, group_id FROM systems_in_policy WHERE policy_id = ?")
        .bind(id)
        .fetch_all(&*pool)
        .await
        .unwrap();

    let systems_in_policy: Vec<SystemInsidePolicy> = sip_rows.into_iter().map(|r| { 
        SystemInsidePolicy { policy_id: r.get("policy_id"), group_id: r.get("group_id") }
    }).collect();

    // 7. Build Context
    let mut context = Context::new();
    context.insert("policy", &policy);
    context.insert("schedule", &schedule_row); // Pass the schedule (Option)
    context.insert("tests", &test_groups);
    context.insert("system_groups", &system_groups);
    context.insert("tests_in_policy", &tests_in_policy);
    context.insert("systems_in_policy", &systems_in_policy);

    render_template(&tera, Some(&pool), "policies_edit.html", context, Some(auth)).await.into_response()
}



// policies_edit_save
pub async fn policies_edit_save(
    auth: AuthSession, 
    Path(id): Path<i32>, 
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    RawForm(raw_form): RawForm
) -> impl IntoResponse {
    
    // Check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
       return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return Redirect::to(&format!("/policies?error_message={}", urlencoding::encode(&e.to_string()))).into_response(),
    };

    let raw_string = String::from_utf8_lossy(&raw_form).to_string();
    let form_data = parse_form_data(&raw_string);

    // Metadata extraction
    let name = form_data.get("name").and_then(|v| v.first()).cloned().unwrap_or_default();
    let version = form_data.get("version").and_then(|v| v.first()).cloned().unwrap_or_default();
    let description = form_data.get("description").and_then(|v| v.first()).map(|s| s.trim().to_string());

    // --- Automation Fields ---
    let schedule_enabled = form_data.get("schedule_enabled").and_then(|v| v.first()).map(|v| v == "on").unwrap_or(false);
    let frequency = form_data.get("frequency").and_then(|v| v.first()).cloned().unwrap_or_else(|| "daily".to_string());
    let cron_val = form_data.get("cron_val").and_then(|v| v.first()).cloned();
    let next_run = form_data.get("next_run").and_then(|v| v.first()).cloned();

    // 1. Update Policy Metadata
    if let Err(e) = sqlx::query("UPDATE policies SET name=?, version=?, description=? WHERE id=?")
        .bind(&name).bind(&version).bind(&description).bind(id)
        .execute(&mut *tx).await {
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message={}", urlencoding::encode(&e.to_string()))).into_response();
    }

    // 2. Sync Schedule (UPSERT logic)
    // We attempt to update, or insert if it doesn't exist. SQLite 3.24+ supports ON CONFLICT
    let schedule_query = r#"
        INSERT INTO policy_schedules (policy_id, enabled, frequency, cron_expression, next_run)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(policy_id) DO UPDATE SET
            enabled = excluded.enabled,
            frequency = excluded.frequency,
            cron_expression = excluded.cron_expression,
            next_run = excluded.next_run
    "#;

    let start_time = next_run.filter(|s| !s.is_empty())
        .unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%dT%H:%M").to_string());

    if let Err(e) = sqlx::query(schedule_query)
        .bind(id)
        .bind(schedule_enabled) // This will be 1 or 0
        .bind(&frequency)
        .bind(&cron_val)
        .bind(&start_time)
        .execute(&mut *tx)
        .await {
            tx.rollback().await.ok();
            return Redirect::to(&format!("/policies?error_message=Schedule Update Error: {}", urlencoding::encode(&e.to_string()))).into_response();
    }

    // 3. Clear and Re-insert Tests
    sqlx::query("DELETE FROM tests_in_policy WHERE policy_id=?").bind(id).execute(&mut *tx).await.ok();
    let tests = form_data.get("tests").cloned().unwrap_or_default();
    for test_id_str in tests {
        if let Ok(test_id) = test_id_str.parse::<i32>() {
            sqlx::query("INSERT OR IGNORE INTO tests_in_policy (policy_id, test_id) VALUES (?, ?)")
                .bind(id).bind(test_id).execute(&mut *tx).await.ok();
        }
    }

    // 4. Clear and Re-insert System Groups
    sqlx::query("DELETE FROM systems_in_policy WHERE policy_id=?").bind(id).execute(&mut *tx).await.ok();
    let system_groups = form_data.get("system_groups").cloned().unwrap_or_default();
    for group_id_str in system_groups {
        if let Ok(group_id) = group_id_str.parse::<i32>() {
            sqlx::query("INSERT OR IGNORE INTO systems_in_policy (policy_id, group_id) VALUES (?, ?)")
                .bind(id).bind(group_id).execute(&mut *tx).await.ok();
        }
    }

    // Commit
    if let Err(e) = tx.commit().await {
        return Redirect::to(&format!("/policies?error_message={}", urlencoding::encode(&e.to_string()))).into_response();
    }


    // RECALCULATE GLOBAL SCORES
    let _ = sync_tx.send(()).await;

    info!("System ID {} updated successfully. Compliance scores recalculated.", id);


    Redirect::to("/policies").into_response()
}



// policies_delete
pub async fn policies_delete(
    auth: AuthSession, 
    Path(id): Path<i32>, 
    Extension(pool): Extension<SqlitePool>,          // Destructured for consistency
    Extension(sync_tx): Extension<mpsc::Sender<()>>, // Grouped Extensions
) -> impl IntoResponse {

    
     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
       return redir;
    }


    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message)).into_response();
        }
    };

    
    let delete_policy_result = sqlx::query(
        "DELETE FROM policies WHERE id=?"
    )
    .bind(&id) 
    .execute(&mut *tx)
    .await; 
            
    if let Err(e) = delete_policy_result {
        let error_message = format!("Error deleting system group: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); // Ensure the transaction is rolled back
        return Redirect::to(&format!("/policies?error_message={}", encoded_message)).into_response();
    }

    // Commit the transaction if all queries were successful
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error committing transaction: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/policies?error_message={}", encoded_message)).into_response();
    }


    // RECALCULATE GLOBAL SCORES
    let _ = sync_tx.send(()).await;

    info!("System ID {} deleted successfully. Compliance scores recalculated.", id);


    Redirect::to("/policies").into_response()
}

// policies_run
pub async fn policies_run(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
       return redir;
    }

    // Call the shared logic
    match execute_policy_run_logic(id, &pool).await {
        Ok(_) => Redirect::to("/policies?success_message=Policy run successfully").into_response(),
        Err(e) => {
            let msg = format!("Error running policy: {}", e);
            let encoded_message = urlencoding::encode(&msg).to_string();
            Redirect::to(&format!("/policies?error_message={}", encoded_message)).into_response()
        }

    }
}





// policies_report
pub async fn policies_report(auth: AuthSession,  Path(id): Path<i32>,pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>)
    -> impl IntoResponse {

     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
       return redir;
    }

    // Safely get the username
    let submitter_name = auth.username.clone();

    // Fetch Policy
    let policy_row = match sqlx::query("SELECT id, name, version, description FROM policies WHERE id = ?")
            .bind(id)
            .fetch_one(&*pool)
            .await 
    {
        Ok(row) => row,
        Err(e) => {
            // Log the specific error and the ID that failed
            error!(error = ?e, policy_id = %id, "Database Error: Failed to fetch policy details");
            return StatusCode::NOT_FOUND.into_response();
        }
    };


    //  Fetch Tests
    let test_rows = match sqlx::query(r#"
            SELECT t.name, t.description, t.rational, t.remediation
            FROM tests t
            JOIN tests_in_policy tip ON t.id = tip.test_id
            WHERE tip.policy_id = ?"#)
            .bind(id)
            .fetch_all(&*pool)
            .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = ?e, policy_id = %id, "Database Error: Failed to fetch tests for policy");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };


    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| {
        TestMeta {
            name: row.get("name"),
            description: row.get("description"),
            rational: row.get("rational"),
            remediation: row.get("remediation"),
        }
    }).collect();

    // Fetch Results
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
            AND tip.policy_id = ?"#)
            .bind(id)
            .bind(id)
            .fetch_all(&*pool)
            .await
    {
        Ok(rows) => rows,
        Err(e) => {
            // Structured logging allows you to add context easily
            error!(error = ?e, policy_id = %id, "Failed to fetch policy results from database");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };


    // Group results by System Name
    let mut system_map: BTreeMap<String, Vec<IndividualResult>> = BTreeMap::new();
    for row in result_rows {
        let system_name = row.get::<Option<String>, _>("system_name")
            .unwrap_or_else(|| "Unknown System".to_string());

        let test_name: String = row.get("test_name");
        let status_raw: String = row.get("status");

        // 1. Determine the boolean state (handling old "true" and new "PASS")
        let is_pass = status_raw.to_uppercase() == "PASS" || status_raw.to_lowercase() == "true";

        // 2. Convert that back to the String the struct expects
        let status = if is_pass { "PASS".to_string() } else { "FAIL".to_string() };

        system_map
            .entry(system_name)
            .or_insert_with(Vec::new)
            .push(IndividualResult { test_name, status }); // Now status is a String
    }


    // Convert the BTreeMap into a Vec<SystemReport>
    let system_reports: Vec<SystemReport> = system_map
    .into_iter()
    .map(|(name, results)| {
        // A system is passed ONLY if all its results are "PASS"
        // We compare the String to "PASS" to get the bool that .all() needs
        let is_passed = results.iter().all(|r| r.status == "PASS" || r.status == "true");

        SystemReport {
            system_name: name,
            results,
            is_passed, 
        }
    })
    .collect();


    let fail_count = system_reports.iter().filter(|s| !s.is_passed).count();


    // Build context
    let report_data = ReportData {
        policy_id: policy_row.get("id"),
        policy_name: policy_row.get("name"),
        version: policy_row.get("version"),
        description: policy_row.get::<Option<String>, _>("description").unwrap_or_default(),
        submission_date: Local::now().format("%Y-%m-%d %H:%M").to_string(),
        submitter_name,
        tests_metadata,
        system_reports, // Now this variable exists!
    };


    let mut context = Context::new();
    context.insert("report", &report_data);
    context.insert("fail_count", &fail_count); 
    render_template(&tera,Some(&pool),"policies_report.html", context, Some(auth)).await.into_response()
}



pub async fn policies_report_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {


     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
       return redir;
    }

    // 1. DATA ACQUISITION
    let submitter_name = auth.username.clone();

    // Fetch Policy Header
    let policy_row = match sqlx::query("SELECT id, name, version, description FROM policies WHERE id = ?")
        .bind(id)
        .fetch_one(&pool)
        .await
    {
        Ok(row) => row,
        Err(e) => {
            eprintln!("Database Error (Policy): {}", e);
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // Fetch Test Definitions (Metadata)
    let test_rows = match sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation
        FROM tests t
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE tip.policy_id = ?"#)
        .bind(id)
        .fetch_all(&pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("Database Error (Tests): {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| TestMeta {
        name: row.get("name"),
        description: row.get::<Option<String>, _>("description").unwrap_or_default(),
        rational: row.get::<Option<String>, _>("rational").unwrap_or_default(),
        remediation: row.get::<Option<String>, _>("remediation").unwrap_or_default(),
    }).collect();

    // Fetch Raw Audit Results
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
          AND tip.policy_id = ?"#)
        .bind(id)
        .bind(id)
        .fetch_all(&pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("Database Error (Results): {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Group results by System
    let mut system_map: BTreeMap<String, Vec<IndividualResult>> = BTreeMap::new();
    for row in result_rows {
        let system_name = row.get::<Option<String>, _>("system_name")
            .unwrap_or_else(|| "Unknown System".to_string());
    
        let test_name: String = row.get("test_name");
        let status_str: String = row.get("status");

        // 1. Calculate the boolean logic (supporting all legacy formats)
        let is_pass = status_str.to_lowercase() == "pass" 
                || status_str == "true" 
                || status_str == "1";

        // 2. Convert that boolean back to a String ("PASS" or "FAIL")
        let status = if is_pass { "PASS".to_string() } else { "FAIL".to_string() };

        // 3. Now the types match: String -> String
        system_map.entry(system_name).or_default().push(IndividualResult { test_name, status });
    }


    let system_reports: Vec<SystemReport> = system_map.into_iter().map(|(name, results)| {
        // We compare each result string to "PASS" to get a boolean
        let is_passed = results.iter().all(|r| r.status == "PASS");

        SystemReport { 
            system_name: name, 
            results, 
            is_passed 
        }
    }).collect();


    let report_data = ReportData {
        policy_id: policy_row.get("id"),
        policy_name: policy_row.get("name"),
        version: policy_row.get("version"),
        description: policy_row.get::<Option<String>, _>("description").unwrap_or_default(),
        submission_date: Local::now().format("%b %d, %Y %I:%M %p").to_string(),
        submitter_name,
        tests_metadata,
        system_reports,
    };

    // PDF GENERATION - load fonts
    const FONT_REGULAR: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES: &[u8] = include_bytes!("../static/dist/img/Logo_report.jpg");

    // Load Fonts
    let font_family = fonts::FontFamily {
        regular: fonts::FontData::new(FONT_REGULAR.to_vec(), None)
            .expect("Failed to load regular font"),
        bold: fonts::FontData::new(FONT_BOLD.to_vec(), None)
            .expect("Failed to load bold font"),
        italic: fonts::FontData::new(FONT_ITALIC.to_vec(), None)
            .expect("Failed to load italic font"),
        bold_italic: fonts::FontData::new(FONT_BOLD_ITALIC.to_vec(), None)
            .expect("Failed to load bold-italic font"),
    };

    let mut doc = genpdf::Document::new(font_family);
    let cursor = std::io::Cursor::new(LOGO_BYTES);
    let mut logo = elements::Image::from_reader(cursor).expect("Failed to load logo");

    doc.set_title(format!("OpenSCM Compliance Report - {}", report_data.policy_name));
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // Main Title
    let mut title = elements::Paragraph::new("OpenSCM Compliance Report");
    title.set_alignment(genpdf::Alignment::Center);
    doc.push(title.styled(style::Style::new().with_font_size(30).bold().with_color(style::Color::Rgb(0, 0, 128))));
    doc.push(elements::Break::new(2.0));
    let mut submitter = elements::Paragraph::new(format!("Generated on {} by {}", report_data.submission_date, report_data.submitter_name));
    submitter.set_alignment(genpdf::Alignment::Center);
    doc.push(submitter);
    doc.push(elements::Break::new(0.5));
   
    // Put logo to openscm
    logo.set_dpi(40.0);
    logo.set_alignment(genpdf::Alignment::Center);
    doc.push(logo);
    doc.push(elements::Break::new(1.0));


    // policy information
    // Report Details Table
    doc.push(elements::Text::new("Report Details").styled(style::Style::new().bold()));
    let mut details_table = elements::TableLayout::new(vec![1, 3]);
    details_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));
    
    if let Err(e) = details_table.push_row(vec![
        Box::new(elements::Text::new("Policy Name")),
        Box::new(elements::Text::new(format!(": {} v{}", report_data.policy_name, report_data.version))),
    ])  {
        error!("Failed to add summary row to PDF: {}", e);
    }
    
    if let Err(e) = details_table.push_row(vec![
        Box::new(elements::Text::new("Description")),
        Box::new(elements::Text::new(format!(": {}", report_data.description))),
    ])  {
        error!("Failed to add summary row to PDF: {}", e);
    }

    doc.push(details_table);


    doc.push(elements::PageBreak::new());

    // Per-System Audit Section
    for system in report_data.system_reports {
        doc.push(elements::Text::new(format!("Host Name: {}", system.system_name)).styled(style::Style::new().bold().with_font_size(14)));
        doc.push(elements::Break::new(0.5));

        // System Compliance Summary
        let compliant_count = system.results.iter().filter(|r| r.status == "PASS" || r.status == "true").count();
        let violation_count = system.results.len() - compliant_count;


        let mut summary_table = elements::TableLayout::new(vec![1, 1]);
        summary_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));
        
        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Compliance Status")),
            Box::new(elements::Text::new(if system.is_passed { ": Compliant" } else { ": Non-Compliant" })
                .styled(style::Style::new().with_color(if system.is_passed { style::Color::Rgb(0, 128, 0) } else { style::Color::Rgb(200, 0, 0) }).bold())),
        ])  {
            error!("Failed to add summary row to PDF: {}", e);
        }

        
        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Violation Rule Count")),
            Box::new(elements::Text::new(format!(": Critical - {}", violation_count))),
        ])  {
            error!("Failed to add summary row to PDF: {}", e);
        }

        
        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Compliant Rule Count")),
            Box::new(elements::Text::new(format!(": {}", compliant_count))),
        ])  {
            error!("Failed to add summary row to PDF: {}", e);
        }

        doc.push(summary_table);
        doc.push(elements::Break::new(1.0));

        // Detailed Rules Breakdown
        doc.push(elements::Text::new("Audit Rules Detailed Breakdown").styled(style::Style::new().bold()));
        let mut rules_table = elements::TableLayout::new(vec![2, 1, 4]);
        rules_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));
        
        if let Err(e) = rules_table.push_row(vec![
            Box::new(elements::Text::new("Rule Name").styled(style::Style::new().bold())),
            Box::new(elements::Text::new("Status").styled(style::Style::new().bold())),
            Box::new(elements::Text::new("Description").styled(style::Style::new().bold())),
        ])  {
            error!("Failed to add summary row to PDF: {}", e);
        }


        for res in &system.results {
            let desc = report_data.tests_metadata.iter()
                .find(|t| t.name == res.test_name)
                .map(|t| t.description.as_str())
                .unwrap_or("No description provided");

            // Compare the string to determine the boolean state for the IF block
            let is_pass = res.status == "PASS" || res.status == "true";

            let (status_text, status_color) = if is_pass {
                ("PASS", style::Color::Rgb(0, 128, 0))
            } else {
                ("FAIL", style::Color::Rgb(200, 0, 0))
            };

            if let Err(e) = rules_table.push_row(vec![
                Box::new(elements::Text::new(&res.test_name)),
                Box::new(elements::Text::new(status_text).styled(style::Style::new().with_color(status_color).bold())),
                Box::new(elements::Text::new(desc)),
            ])  {
            error!("Failed to add summary row to PDF: {}", e);
            }

        }
        doc.push(rules_table);
        doc.push(elements::PageBreak::new());
    }

    // Confidentiality Footer
    doc.push(elements::Break::new(2.0));
    doc.push(elements::Paragraph::new("Note: This report contains confidential information about your infrastructure and should be treated as such. Unauthorized distribution is strictly prohibited.")
        .styled(style::Style::new().with_font_size(10).with_color(style::Color::Rgb(100, 100, 100))));

    // 3. RENDER & RESPONSE
    let mut buffer = Vec::new();
    doc.render(&mut buffer).unwrap();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"OpenSCM_Report_{}.pdf\"", id))
        .body(axum::body::Body::from(buffer))
        .unwrap()
        .into_response()
}



// Internal logic that actually triggers the scan
pub async fn execute_policy_run_logic(id: i32, pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT OR IGNORE INTO commands (system_id, test_id)
        SELECT sig.system_id, tip.test_id
        FROM systems_in_policy sip
        JOIN systems_in_groups sig ON sip.group_id = sig.group_id
        JOIN tests_in_policy tip ON sip.policy_id = tip.policy_id
        WHERE sip.policy_id = ?
        "#
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}



