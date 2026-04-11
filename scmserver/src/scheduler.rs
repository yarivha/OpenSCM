use tokio::time::{self, Duration};
use axum::response::{Html, IntoResponse, Redirect};
use axum::http::StatusCode;
use axum::extract::{RawForm, Extension, Query, Path};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use std::str::FromStr;
use urlencoding;
use tracing::{info,warn,error};
use bytes::Bytes;
use chrono::NaiveDateTime;

use crate::models::ErrorQuery;
use crate::models::ScheduledJob;
use crate::models::ComplianceHistoryRow;
use crate::auth::{self, UserRole, AuthSession};
use crate::handlers::render_template;
use crate::handlers::parse_form_data;



pub async fn scheduler(auth: AuthSession, Extension(pool): Extension<SqlitePool>, Extension(tera): Extension<Arc<Tera>>,)
 ->  impl IntoResponse {

     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    
    // Fetch jobs joined with policy names
    let jobs_result = sqlx::query_as::<_, ScheduledJob>(
        r#"
        SELECT 
            s.*, 
            p.name as policy_name 
        FROM scheduler s
        JOIN policies p ON s.policy_id = p.id
        ORDER BY s.job_type DESC, s.next_run ASC
        "#
    )
    .fetch_all(&pool)
    .await;

    let jobs = match jobs_result {
        Ok(j) => j,
        Err(_) => Vec::new(),
    };

    // Split jobs into two vectors for the tabbed UI
    let scan_jobs: Vec<&ScheduledJob> = jobs.iter().filter(|j| j.job_type == "command").collect();
    let report_jobs: Vec<&ScheduledJob> = jobs.iter().filter(|j| j.job_type == "report").collect();

    let mut context = Context::new();
    context.insert("scan_jobs", &scan_jobs);
    context.insert("report_jobs", &report_jobs);

    // Render using your Tera engine
    // (Assuming you have a render function or template manager)
     render_template(&tera,Some(&pool), "scheduler.html", context, Some(auth)).await.into_response()
}



pub async fn capture_compliance_snapshot(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    info!("Starting full compliance aggregation...");

    // 1. Update TEST stats - changed scan_results to results
    sqlx::query(r#"
        UPDATE tests SET 
            systems_passed = (SELECT COUNT(*) FROM results WHERE test_id = tests.id AND result = 'PASS'),
            systems_failed = (SELECT COUNT(*) FROM results WHERE test_id = tests.id AND result = 'FAIL'),
            compliance_score = (
                SELECT CASE WHEN COUNT(*) = 0 THEN 100.0 
                ELSE (CAST(SUM(CASE WHEN result = 'PASS' THEN 1 ELSE 0 END) AS REAL) / COUNT(*)) * 100 
                END FROM results WHERE test_id = tests.id
            )
    "#).execute(pool).await?;

    // 2. Update SYSTEM stats - changed scan_results to results
    sqlx::query(r#"
        UPDATE systems SET 
            passed_tests = (SELECT COUNT(*) FROM results WHERE system_id = systems.id AND result = 'PASS'),
            failed_tests = (SELECT COUNT(*) FROM results WHERE system_id = systems.id AND result = 'FAIL'),
            total_tests  = (SELECT COUNT(*) FROM results WHERE system_id = systems.id),
            compliance_score = (
                SELECT CASE WHEN COUNT(*) = 0 THEN 0.0 
                ELSE (CAST(SUM(CASE WHEN result = 'PASS' THEN 1 ELSE 0 END) AS REAL) / COUNT(*)) * 100 
                END FROM results WHERE system_id = systems.id
            )
    "#).execute(pool).await?;

    // 3. Global Stats for Trend Graph
    let stats = sqlx::query("SELECT AVG(compliance_score) as avg_score, COUNT(*) as sys_count FROM systems")
        .fetch_one(pool).await?;

    sqlx::query("INSERT INTO compliance_history (global_score, total_systems, failed_systems) 
                 VALUES (?, ?, (SELECT COUNT(*) FROM systems WHERE compliance_score < 100))")
        .bind(stats.try_get::<f64, _>("avg_score").unwrap_or(0.0))
        .bind(stats.try_get::<i32, _>("sys_count").unwrap_or(0))
        .execute(pool).await?;

    Ok(())
}




// This matches the function name you built for the trend table
pub async fn start_background_scheduler(pool: SqlitePool) {
    // 1. Run once immediately on startup
    // This ensures your graph has at least one dot as soon as you open the dashboard
    let startup_pool = pool.clone();
    tokio::spawn(async move {
        info!("Initiating startup compliance snapshot...");
        if let Err(e) = capture_compliance_snapshot(&startup_pool).await {
            error!("Startup compliance snapshot failed: {}", e);
        }
    });

    // 2. Set the 24-hour loop
    let mut interval = time::interval(Duration::from_secs(86400));

    // Skip the first tick of the interval because we handled it above
    interval.tick().await;

    tokio::spawn(async move {
        loop {
            interval.tick().await;
            info!("Running scheduled daily compliance aggregation...");
            if let Err(e) = capture_compliance_snapshot(&pool).await {
                error!("Daily scheduler task failed: {}", e);
            }
        }
    });
}
