use axum::response::{Html, IntoResponse, Redirect};
use axum::http::StatusCode;
use axum::extract::{Extension, Query, Path};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use tracing::error;
use serde_json;
use std::collections::HashMap;

use crate::auth::AuthSession;
use crate::handlers::render_template;
use crate::models::ReportData;
use crate::models::TestMeta;
use crate::models::SystemReport;
use crate::models::IndividualResult;
use crate::models::Report;
use crate::models::ErrorQuery;

//////////////////// Reports /////////////////////////
// reports
pub async fn reports(auth: AuthSession, Query(query): Query<ErrorQuery>,pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
            -> Result<Html<String>, StatusCode> {
    let rows = sqlx::query("
        SELECT
                id, submission_date, policy_name, policy_version, submitter_name from reports")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let reports: Vec<Report> = rows.into_iter().map(|row| {
        Report {
            id: row.get("id"),
            submission_date: row.get("submission_date"),
            policy_name: row.get("policy_name"),
            policy_version: row.get("policy_version"),
            policy_description: None, 
            submitter_name: row.get("submitter_name"),
            tests_metadata: None,
            report_results: None,
        }
    }).collect();

    // Prepare handler-specific context
    let mut context = Context::new();
    
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    context.insert("reports", &reports);

    // Use the generic render function to render the template with global data
    render_template(&tera, Some(&pool), "reports.html", context, Some(auth)).await
}



// reports_save
pub async fn reports_save(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    // 1. Fetch Policy Header
    let policy_row = match sqlx::query("SELECT name, version, description FROM policies WHERE id = ?")
        .bind(id)
        .fetch_one(&pool)
        .await {
            Ok(row) => row,
            Err(_) => return Redirect::to("/policies?error_message=Policy+not+found").into_response(),
        };

    // 2. Fetch Tests Metadata (Join tests_in_policy + tests)
    let test_rows = sqlx::query(
        r#"
        SELECT t.name, t.description, t.rational, t.remediation 
        FROM tests t
        JOIN tests_in_policy tp ON t.id = tp.test_id
        WHERE tp.policy_id = ?
        "#
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| TestMeta {
        name: row.get("name"),
        description: row.get("description"),
        rational: row.get("rational"),
        remediation: row.get("remediation"),
    }).collect();

    // 3. Fetch System Results (Join tests_in_policy + results + systems)
    let raw_results = sqlx::query(
        r#"
        SELECT 
            s.name AS system_name, 
            t.name AS test_name, 
            res.result AS status_text
        FROM tests_in_policy tip
        JOIN tests t ON tip.test_id = t.id
        JOIN results res ON t.id = res.test_id
        JOIN systems s ON res.system_id = s.id
        WHERE tip.policy_id = ?
        "#
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    // 4. Group results by system
    let mut reports_map: HashMap<String, SystemReport> = HashMap::new();
    for row in raw_results {
        let s_name: String = row.get("system_name");
        let t_name: String = row.get("test_name");
        let status_str: String = row.get("status_text");
        
        // Match your agent's pass/fail string (assuming "Pass")
        let t_status: bool = status_str.to_lowercase() == "true";

        let entry = reports_map.entry(s_name.clone()).or_insert(SystemReport {
            system_name: s_name,
            results: Vec::new(),
            is_passed: true,
        });

        entry.results.push(IndividualResult { test_name: t_name, status: t_status });
        if !t_status { entry.is_passed = false; }
    }
    let system_reports: Vec<SystemReport> = reports_map.into_values().collect();

    // 5. Serialize to JSON
    // We serialize the vectors directly to match your 'reports' table columns
    let tests_json = serde_json::to_string(&tests_metadata).unwrap_or_else(|_| "[]".to_string());
    let results_json = serde_json::to_string(&system_reports).unwrap_or_else(|_| "[]".to_string());

    // 6. Archive the snapshot
    let insert_result = sqlx::query(
        r#"
        INSERT INTO reports 
        (policy_name, policy_version, policy_description, submitter_name, tests_metadata, report_results) 
        VALUES (?, ?, ?, ?, ?, ?)
        "#
    )
    .bind(policy_row.get::<String, _>("name"))
    .bind(policy_row.get::<String, _>("version"))
    .bind(policy_row.get::<String, _>("description"))
    .bind(&auth.username)
    .bind(tests_json)
    .bind(results_json)
    .execute(&pool)
    .await;

    match insert_result {
        Ok(_) => Redirect::to("/policies?success_message=Report+saved").into_response(),
        Err(e) => {
            eprintln!("Archive Error: {}", e);
            Redirect::to("/policies?error_message=Failed+to+save+report").into_response()
        }
    }
}



// reports_view
pub async fn reports_view(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> Result<Html<String>, StatusCode> {

    // 1. Fetch the single report row
    let row = sqlx::query(
        "SELECT id, submission_date, policy_name, policy_version, policy_description, submitter_name, tests_metadata, report_results 
         FROM reports WHERE id = ?"
    )
    .bind(id)
    .fetch_one(&*pool)
    .await
    .map_err(|e| {
        eprintln!("Database Error (Report View): {}", e);
        StatusCode::NOT_FOUND
    })?;

    // 2. Deserialize the JSON columns
    // SQLite returns these as Strings, so we parse them into our Rust Vecs
    let tests_metadata_raw: String = row.get("tests_metadata");
    let system_reports_raw: String = row.get("report_results");

    let tests_metadata: Vec<TestMeta> = serde_json::from_str(&tests_metadata_raw).map_err(|e| {
        eprintln!("JSON Deserialization Error (Tests): {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let system_reports: Vec<SystemReport> = serde_json::from_str(&system_reports_raw).map_err(|e| {
        eprintln!("JSON Deserialization Error (Systems): {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 3. Reconstruct the ReportData for the template
    let report_data = ReportData {
        policy_id: row.get("id"), // Or keep as 0 if the original policy ID isn't in this table
        policy_name: row.get("policy_name"),
        version: row.get("policy_version"),
        description: row.get::<Option<String>, _>("policy_description").unwrap_or_default(),
        submission_date: row.get("submission_date"),
        submitter_name: row.get("submitter_name"),
        tests_metadata,
        system_reports,
    };

    // 4. Render using the same template
    let mut context = Context::new();
    context.insert("report", &report_data);
    
    render_template(&tera, Some(&pool), "reports_view.html", context, Some(auth)).await
}



// reports_delete
pub async fn reports_delete(auth: AuthSession, Path(id): Path<i32>, pool: Extension<SqlitePool>) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/reports?error_message={}", encoded_message));
        }
    };


    let delete_report_result = sqlx::query(
        "DELETE FROM reports WHERE id=?"
    )
    .bind(&id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = delete_report_result {
        let error_message = format!("Error deleting report: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); // Ensure the transaction is rolled back
        return Redirect::to(&format!("/reports?error_message={}", encoded_message));
    }

    // Commit the transaction if all queries were successful
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error committing transaction: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/reports?error_message={}", encoded_message));
    }

    Redirect::to("/reports")
}


