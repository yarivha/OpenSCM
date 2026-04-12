use axum::response::{Html, IntoResponse};
use axum::http::StatusCode;
use axum::extract::{Extension, Query};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::collections::HashMap;
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



#[derive(serde::Deserialize, serde::Serialize)] // Add Serialize if passing to template
pub struct DashboardParams {
    #[serde(default)] // Helps handle empty strings/missing keys
    pub error_message: Option<String>,
    #[serde(default)]
    pub success_message: Option<String>,
    #[serde(default)]
    pub range: Option<String>,
}


// dashboard
pub async fn dashboard(auth: AuthSession, Query(params): Query<DashboardParams>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
    -> impl IntoResponse {

    
    let range = params.range.clone().unwrap_or_else(|| "daily".to_string()).to_lowercase();

    let mut context = Context::new();
    
    // 1. Get counts for the Small Boxes
    let systems_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM systems WHERE status = 'active'")
        .fetch_one(&*pool).await.unwrap_or(0);
    
    let pending_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM systems WHERE status = 'pending'")
        .fetch_one(&*pool).await.unwrap_or(0);

    let policies_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies")
        .fetch_one(&*pool).await.unwrap_or(0);

    let reports_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports")
        .fetch_one(&*pool).await.unwrap_or(0);

    // 2. Get Critical Policy Failures
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

    // 3. Get Highest Risk Assets
    let top_failed_systems = sqlx::query_as::<_, SystemFailRow>(
        "SELECT name as system_name, os, compliance_score as compliance, tests_passed, tests_failed 
        FROM systems WHERE status='active' ORDER BY compliance_score ASC LIMIT 5"
    ).fetch_all(&*pool).await.map_err(|e| { error!("{}", e); StatusCode::INTERNAL_SERVER_ERROR })?; 

    // 4. Fetch History including POLICY_SCORE
    
    let history_query = match range.as_str() {
        "yearly" =>
            "SELECT strftime('%Y', check_date) as check_date, AVG(global_score) as global_score, AVG(policy_score) as policy_score
            FROM compliance_history GROUP BY 1 ORDER BY check_date DESC LIMIT 10",
        "weekly" =>
            "SELECT strftime('%Y-W%W', check_date) as check_date, AVG(global_score) as global_score, AVG(policy_score) as policy_score
            FROM compliance_history GROUP BY 1 ORDER BY check_date DESC LIMIT 12",
        "monthly" =>
            "SELECT strftime('%m-%Y', check_date) as check_date, AVG(global_score) as global_score, AVG(policy_score) as policy_score
            FROM compliance_history GROUP BY 1 ORDER BY check_date DESC LIMIT 12",
        _ => // daily (default)
            "SELECT strftime('%m-%d %H:%M', check_date) as check_date, global_score, policy_score 
            FROM compliance_history ORDER BY id DESC LIMIT 14"
    };

    
    let history = sqlx::query_as::<_, ComplianceHistoryRow>(history_query)
        .fetch_all(&*pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch compliance history: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;


    let mut labels = Vec::new();
    let mut scores = Vec::new();
    let mut policy_scores = Vec::new(); // NEW: For the second line on the graph

    for rec in history.into_iter().rev() {
        labels.push(rec.check_date); 
        scores.push(rec.global_score); 
        policy_scores.push(rec.policy_score); // NEW
    }

    let current_global_score = scores.last().cloned().unwrap_or(0.0);
    let formatted_score = format!("{:.1}", current_global_score);

    context.insert("range", &range);
    context.insert("global_score", &formatted_score);
    context.insert("systems_count", &systems_count);
    context.insert("pending_count", &pending_count); // Added for the red/green box
    context.insert("policies_count", &policies_count);
    context.insert("reports_count", &reports_count);
    context.insert("top_failed_systems", &top_failed_systems); 
    context.insert("top_failed_policies", &top_failed_policies);
    
    // Graph Data
    context.insert("trend_labels", &labels);
    context.insert("trend_scores", &scores);
    context.insert("trend_policy_scores", &policy_scores); // THE MISSING VARIABLE FIXED


    // 5. Fill Context
    if let Some(msg) = &params.error_message {
        context.insert("error_message", msg);
    }
    if let Some(msg) = &params.success_message {
        context.insert("success_message", msg);
    }


    render_template(&tera, Some(&pool), "dashboard.html", context, Some(auth)).await
}

