use tokio::time::{self, Duration};
use axum::response::{Html, Response, IntoResponse};
use axum::http::{StatusCode, header};
use http_body_util::Full;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use urlencoding;
use std::collections::HashMap;
use urlencoding::decode;
use tracing::{info,warn,error};
use crate::models::Notification;
use crate::auth::UserRole;
use crate::auth::AuthSession;



//////////////////////////////// Helper Functions ///////////////////////////////////
pub async fn render_template(
    tera: &Tera,
    pool: Option<&SqlitePool>,
    template_name: &str,
    mut context: Context,
    auth: Option<AuthSession>,
) -> Result<Html<String>, StatusCode> {
    // Add common context values
    context.insert("version", env!("CARGO_PKG_VERSION"));
    if let Some(session) = &auth {
        context.insert("username", &session.username);
         context.insert("userid", &session.userid);
        context.insert("role", &session.role);
    }

    if let Some(pool) = pool {
        
        // Add notify count
        let notify_row = sqlx::query("SELECT COUNT(*) as count FROM notify")
                  .fetch_one(pool)
                  .await
                  .map_err(|e| {
                    error!("DB error getting notify count: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                  })?;

        let notify_count: i64 = notify_row.get("count");
        context.insert("notify_count", &notify_count);

        // Add notify list
        let notifications = sqlx::query("SELECT id, type, timestamp, message FROM notify ORDER BY timestamp DESC LIMIT 10")
            .map(|row: sqlx::sqlite::SqliteRow| Notification {
                id: row.get("id"),
                r#type: row.get("type"),
                timestamp: row.get("timestamp"),
                message: row.get("message"),
            })
            .fetch_all(pool)
            .await
            .map_err(|e| {
                error!("Failed to fetch notifications: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        context.insert("notifications", &notifications);

        // Add pending registrations count 
        let pending_row = sqlx::query("SELECT COUNT(*) as count FROM systems WHERE status = 'pending'")
                  .fetch_one(pool)
                  .await
                  .map_err(|e| {
                    error!("DB error getting pending count: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                  })?;

        let pending_count: i64 = pending_row.get("count");
        context.insert("pending_count", &pending_count);
    }
   
    // Add authorization functions
    if let Some(session) = &auth {
        // 2. Now 'session' is the actual AuthSession, so we can access .role
        let role_enum = UserRole::from(session.role.as_str());

        // 3. Insert the specific strings for the template
        context.insert("username", &session.username);
        context.insert("role", &session.role);

        // 4. Calculate permissions based on your hierarchy
        context.insert("is_admin", &(role_enum >= UserRole::Admin));
        context.insert("is_editor", &(role_enum >= UserRole::Editor));
        context.insert("is_runner", &(role_enum >= UserRole::Runner));
        context.insert("is_viewer", &(role_enum >= UserRole::Viewer));

    } else {
        // Optional: Logic for when NO user is logged in (Guest mode)
        context.insert("is_admin", &false);
        context.insert("is_editor", &false);
        context.insert("is_runner", &false);
        context.insert("is_viewer", &false);
    }


    // Render template with detailed error reporting
    let rendered = tera.render(template_name, &context).map_err(|e| {
        // The {:?} is critical here to see the "Caused by" chain from Tera
        error!("Template render error ({}): {:?}", template_name, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Html(rendered))

}


// Helper function to parse URL-encoded form data
pub fn parse_form_data(raw_string: &str) -> HashMap<String, Vec<String>> {
    let mut form_data: HashMap<String, Vec<String>> = HashMap::new();
    
    for pair in raw_string.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            // Replace '+' with spaces before decoding
            let key = key.replace('+', " ");
            let value = value.replace('+', " ");

            // Decode percent-encoded values safely
            let key_decoded = decode(&key)
                .unwrap_or_else(|_| key.clone().into())
                .to_string();
            let value_decoded = decode(&value)
                .unwrap_or_else(|_| value.clone().into())
                .to_string();

            form_data
                .entry(key_decoded)
                .or_insert_with(Vec::new)
                .push(value_decoded);
        }
    }

    form_data
}



pub async fn not_found() -> impl IntoResponse {
    // Body content
    let body = "404 - Not Found";

    // Build the response
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Full::from(body))  // Use Full or Boxed body type
        .unwrap()
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
            tests_passed = (SELECT COUNT(*) FROM results WHERE system_id = systems.id AND result = 'PASS'),
            tests_failed = (SELECT COUNT(*) FROM results WHERE system_id = systems.id AND result = 'FAIL'),
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
