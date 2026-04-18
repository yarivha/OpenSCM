use axum::response::IntoResponse;
use axum::http::StatusCode;
use axum::extract::{Extension, Query};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use tracing::error;

use crate::models::{ComplianceHistoryRow, PolicyFailRow, SystemFailRow, AuthSession,  Notification};
use crate::handlers::render_template;



#[derive(serde::Deserialize)] // Add Serialize if passing to template
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


    let range: &str = match params.range.as_deref() {
        Some("yearly") => "yearly",
        Some("weekly") => "weekly",
        Some("monthly") => "monthly",
        _ => "daily",
    };


    let mut context = Context::new();
    
    // 1. Get counts for the Small Boxes
    let systems_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM systems WHERE status = 'active' AND tenant_id = ?")
        .bind(&auth.tenant_id)
        .fetch_one(&*pool)
        .await
        .unwrap_or_else(|e| { error!("Failed to fetch systems count: {}", e); 0 });

    
    let pending_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM systems WHERE status = 'pending' AND tenant_id=?")
        .bind(&auth.tenant_id)
        .fetch_one(&*pool)
        .await
        .unwrap_or_else(|e| { error!("Failed to fetch pending systems count: {}", e); 0 });

    let policies_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE tenant_id=?")
        .bind(&auth.tenant_id)
        .fetch_one(&*pool)
        .await
        .unwrap_or_else(|e| { error!("Failed to fetch policies count: {}", e); 0 });

    let reports_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports  WHERE tenant_id=?")
        .bind(&auth.tenant_id)
        .fetch_one(&*pool)
        .await
        .unwrap_or_else(|e| { error!("Failed to fetch reports count: {}", e); 0 });


    
    let notifications = sqlx::query_as::<_, Notification>(
        "SELECT * FROM notify WHERE tenant_id = ? AND owner_id = ? ORDER BY id DESC LIMIT 10"
    )
    .bind(&auth.tenant_id)
    .bind(auth.userid)
    .fetch_all(&*pool).await.unwrap_or_default();



    // 2. Get Critical Policy Failures
    let top_failed_policies = sqlx::query_as::<_, PolicyFailRow>(
        r#"
        SELECT 
            name as policy_name, 
            version as policy_version,
            compliance_score as compliance,
            systems_passed as systems_passed,
            systems_failed as systems_failed
        FROM policies 
        WHERE tenant_id = ? 
        ORDER BY compliance_score ASC 
        LIMIT 5
        "#
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    .map_err(|e| {
        error!("Dashboard Policy Fetch Error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 3. Get Highest Risk Assets
    let top_failed_systems = sqlx::query_as::<_, SystemFailRow>(
        "SELECT name as system_name, os, compliance_score as compliance, tests_passed, tests_failed 
        FROM systems WHERE status='active' AND tenant_id = ? ORDER BY compliance_score ASC LIMIT 5"
        ).bind(&auth.tenant_id)
        .fetch_all(&*pool)
        .await.map_err(|e| { error!("{}", e); StatusCode::INTERNAL_SERVER_ERROR })?; 

    // 4. Fetch History including POLICY_SCORE
    
    let history_query = match range {
        "yearly" =>
            "SELECT strftime('%Y', check_date) as check_date, AVG(systems_score) as systems_score, AVG(policies_score) as policies_score
            FROM compliance_history WHERE tenant_id = ? GROUP BY 1 ORDER BY check_date DESC LIMIT 10",
        "weekly" =>
            "SELECT strftime('%Y-W%W', check_date) as check_date, AVG(systems_score) as systems_score, AVG(policies_score) as policies_score
            FROM compliance_history WHERE tenant_id = ? GROUP BY 1 ORDER BY check_date DESC LIMIT 12",
        "monthly" =>
            "SELECT strftime('%m-%Y', check_date) as check_date, AVG(systems_score) as systems_score, AVG(policies_score) as policies_score
            FROM compliance_history WHERE tenant_id = ? GROUP BY 1 ORDER BY check_date DESC LIMIT 12",
        _ => // daily (average per hour)
            "SELECT strftime('%m-%d %H:00', check_date) as check_date, AVG(systems_score) as systems_score, AVG(policies_score) as policies_score
            FROM compliance_history WHERE tenant_id = ? GROUP BY 1 ORDER BY id DESC LIMIT 24"

    };

    
    let history = sqlx::query_as::<_, ComplianceHistoryRow>(history_query)
        .bind(&auth.tenant_id)
        .fetch_all(&*pool)
        .await
        .map_err(|e| {
            error!("Failed to fetch compliance history: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;


    let mut labels = Vec::new();
    let mut systems_scores= Vec::new();
    let mut policies_scores = Vec::new(); 

    for rec in history.into_iter().rev() {
        labels.push(rec.check_date); 
        systems_scores.push(rec.systems_score); 
        policies_scores.push(rec.policies_score); // NEW
    }


    context.insert("range", &range);
    context.insert("systems_count", &systems_count);
    context.insert("pending_count", &pending_count); // Added for the red/green box
    context.insert("policies_count", &policies_count);
    context.insert("reports_count", &reports_count);
    context.insert("top_failed_systems", &top_failed_systems); 
    context.insert("top_failed_policies", &top_failed_policies);
    context.insert("notifications", &notifications);

    // Graph Data
    context.insert("trend_labels", &labels);
    context.insert("trend_systems_scores", &systems_scores);
    context.insert("trend_policies_scores", &policies_scores); 


    // 5. Fill Context
    if let Some(msg) = &params.error_message {
        context.insert("error_message", msg);
    }
    if let Some(msg) = &params.success_message {
        context.insert("success_message", msg);
    }


    render_template(&tera, Some(&pool), "dashboard.html", context, Some(auth)).await
}

