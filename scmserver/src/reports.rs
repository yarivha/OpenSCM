use axum::response::{Html, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{RawForm, Extension, Query, Path};
use http_body_util::Full;
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
                id, report_date, policy_name, policy_version, publisher_name from reports")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let reports: Vec<Report> = rows.into_iter().map(|row| {
        Report {
            id: row.get("id"),
            report_date: row.get("report_date"),
            policy_name: row.get("policy_name"),
            policy_version: row.get("policy_version"),
            description: None, 
            publisher_name: row.get("publisher_name"),
            tests_metadata_json: None,
            report_results_json: None,
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
        let t_status: bool = status_str.to_lowercase() == "pass";

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
        (policy_name, policy_version, description, publisher_name, tests_metadata_json, report_results_json) 
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


