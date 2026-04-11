use axum::response::{Html, IntoResponse};
use axum::http::StatusCode;
use axum::extract::{Extension, Query};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use tracing::error;

use crate::models::ErrorQuery;
use crate::models::SystemCompliance;
use crate::models::PolicyCompliance;
use crate::models::ComplianceHistoryRow;
use crate::models::PolicyFailRow;
use crate::models::SystemFailRow;
use crate::auth::AuthSession;
use crate::handlers::render_template;



/////////////////////////////////// Handlers Functions /////////////////////////////////

// dashboard
pub async fn dashboard(auth: AuthSession, Query(params): Query<ErrorQuery>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
    -> impl IntoResponse {

    let mut context = Context::new();
    
    // Get systems count
    let systems_count_row = sqlx::query("SELECT COUNT(*) as count FROM systems WHERE status= 'active'")
        .fetch_one(&*pool)
        .await
        .unwrap();
    
    let systems_count: i64 = systems_count_row.get("count");
    

    // Get policies count
    let policies_count_row = sqlx::query("SELECT COUNT(*) as count FROM policies")
        .fetch_one(&*pool)
        .await
        .unwrap();

    let policies_count: i64 = policies_count_row.get("count");


    // Get reports count
    let reports_count_row = sqlx::query("SELECT COUNT(*) as count FROM reports")
        .fetch_one(&*pool)
        .await
        .unwrap();

    let reports_count: i64 = reports_count_row.get("count");


    // Get Critical Policy Failures
    let top_failed_policies = sqlx::query_as::<_, PolicyFailRow>(
        r#"
        SELECT 
            p.name as policy_name, 
            p.version as policy_version,
            AVG(t.compliance_score) as compliance,
            SUM(t.systems_passed) as systems_passed,
            SUM(t.systems_failed) as systems_failed
        FROM policies p
        JOIN tests_in_policy tip ON p.id = tip.policy_id
        JOIN tests t ON tip.test_id = t.id
        GROUP BY p.id
        ORDER BY compliance ASC
        LIMIT 5
        "#
    )
    .fetch_all(&*pool)
    .await
    .map_err(|e| { 
        error!("Dashboard Policy Aggregation Error: {}", e); 
        StatusCode::INTERNAL_SERVER_ERROR 
    })?;



    // Get Highest Risk Assets
    let top_failed_systems = sqlx::query_as::<_, SystemFailRow>(
        "SELECT name as system_name, os, compliance_score as compliance, tests_passed, tests_failed 
        FROM systems WHERE status='active' ORDER BY compliance_score ASC LIMIT 5"
    ).fetch_all(&*pool).await.map_err(|e| { error!("{}", e); StatusCode::INTERNAL_SERVER_ERROR })?; 



    let history: Vec<ComplianceHistoryRow> = sqlx::query_as::<_, ComplianceHistoryRow>(
        "SELECT check_date, global_score FROM compliance_history ORDER BY id DESC LIMIT 10"
    )
    .fetch_all(&*pool)
    .await
    .map_err(|e| {
        // Using the log crate macro for structured logging
        error!("Failed to fetch compliance history: {}", e); 
        StatusCode::INTERNAL_SERVER_ERROR
    })?;


    let mut labels = Vec::new();
    let mut scores = Vec::new();

    for rec in history.into_iter().rev() {
        labels.push(rec.check_date); 
        scores.push(rec.global_score); 
    }




    if let Some(msg) = &params.error_message {
        context.insert("error_message", msg);
    }
    if let Some(msg) = &params.success_message {
        context.insert("success_message", msg);
    }
    context.insert("systems_count", &systems_count.to_string());
    context.insert("policies_count", &policies_count.to_string());
    context.insert("reports_count", &reports_count.to_string());
    context.insert("top_failed_systems", &top_failed_systems); 
    context.insert("top_failed_policies", &top_failed_policies);
    context.insert("trend_labels", &labels);
    context.insert("trend_scores", &scores);
    render_template(&tera,Some(&pool), "dashboard.html", context, Some(auth)).await
}



