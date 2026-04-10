
use axum::response::{Html, IntoResponse, Redirect};
use axum::http::StatusCode;
use axum::extract::{RawForm, Extension, Query, Path};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use std::str::FromStr;
use urlencoding;
use tracing::error;
use bytes::Bytes;
use chrono::NaiveDateTime;

use crate::models::ErrorQuery;
use crate::models::ScheduledJob;
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
