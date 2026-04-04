use axum::response::Html;
use axum::http::StatusCode;
use axum::extract::Extension;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use tracing::error;

use crate::models::SystemCompliance;
use crate::models::PolicyCompliance;
use crate::auth::AuthSession;
use crate::handlers::render_template;



/////////////////////////////////// Handlers Functions /////////////////////////////////

// dashboard
pub async fn dashboard(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
    -> Result<Html<String>, StatusCode> {

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

    // Get Top failed systems
    let rows = sqlx::query(r#"
        SELECT
            s.name AS system_name,
            s.os,

            CASE 
                WHEN COUNT(r.test_id) = 0 THEN 0.0 -- Using 0.0 to keep sqlx happy (f64)
                ELSE ROUND(
                    (SUM(CASE WHEN r.result = 'true' THEN 1 ELSE 0 END) * 100.0) 
                    / COUNT(r.test_id),
                    2)
            END AS compliance,

            COALESCE(SUM(CASE WHEN r.result = 'true' THEN 1 ELSE 0 END), 0) AS passed_tests,
            COALESCE(SUM(CASE WHEN r.result = 'false' THEN 1 ELSE 0 END), 0) AS failed_tests

        FROM systems s
        JOIN results r ON s.id = r.system_id

        GROUP BY s.id, s.name, s.os

        ORDER BY compliance ASC
        LIMIT 5
    "#)
    .fetch_all(&*pool)
    .await
    .map_err(|e| {
        error!("Systems stats DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let top_failed_systems: Vec<SystemCompliance> = rows.into_iter().map(|row| {
        SystemCompliance {
            system_name: row.get::<String, _>("system_name"),
            os: row.get::<String, _>("os"),
            compliance: row.get::<f64, _>("compliance"),
            passed_tests: row.get::<i64, _>("passed_tests"),
            failed_tests: row.get::<i64, _>("failed_tests"),
        }
    }).collect();


  

    // Get Top failed policies
    let rows = sqlx::query(r#"
        SELECT
            p.id AS policy_id,
            p.name AS policy_name,
            p.version AS policy_version,
            ROUND(
                SUM(CASE WHEN system_status = 'passed' THEN 1 ELSE 0 END) * 100.0
                / COUNT(*),
                2
            ) AS compliance,
            SUM(CASE WHEN system_status = 'passed' THEN 1 ELSE 0 END) AS passed_systems,
            SUM(CASE WHEN system_status = 'failed' THEN 1 ELSE 0 END) AS failed_systems
        FROM (
            SELECT
                tip.policy_id,
                r.system_id,
                CASE
                    WHEN SUM(CASE WHEN r.result = 'false' THEN 1 ELSE 0 END) > 0
                        THEN 'failed'
                    ELSE 'passed'
                END AS system_status
            FROM tests_in_policy tip
            JOIN results r ON r.test_id = tip.test_id
            GROUP BY tip.policy_id, r.system_id
        ) AS system_results
        JOIN policies p ON p.id = system_results.policy_id
        GROUP BY p.id, p.name, p.version
        ORDER BY compliance ASC
        LIMIT 5
    "#)
    .fetch_all(&*pool)
    .await
    .map_err(|e| {
        error!("Dashboard stats DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    
    let top_failed_policies: Vec<PolicyCompliance> = rows.into_iter().map(|row| {
        PolicyCompliance {
            policy_id: row.get::<i64, _>("policy_id"),
            policy_name: row.get::<String, _>("policy_name"),
            policy_version: row.get::<String, _>("policy_version"),
            policy_description: None,
            compliance: row.get::<f64, _>("compliance"),
            passed_systems: Some(row.get::<i64, _>("passed_systems")),
            failed_systems: Some(row.get::<i64, _>("failed_systems")),
        }
    }).collect();



    context.insert("systems_count", &systems_count.to_string());
    context.insert("policies_count", &policies_count.to_string());
    context.insert("top_failed_systems", &top_failed_systems); 
    context.insert("top_failed_policies", &top_failed_policies);
    render_template(&tera,Some(&pool), "dashboard.html", context, Some(auth)).await
}



