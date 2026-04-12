use sqlx::{SqlitePool, Row};
use tokio::time::{self, Duration};
use chrono::{Utc, Timelike};
use tracing::{info,warn,error};


use crate::models::PolicySchedule;
use crate::policies::execute_policy_run_logic;

/// Internal helper for date math
fn calculate_next_run(frequency: &str, last_planned_run: &str) -> String {
    let current = chrono::NaiveDateTime::parse_from_str(last_planned_run, "%Y-%m-%dT%H:%M")
        .unwrap_or_else(|_| Utc::now().naive_utc());

    let next = match frequency {
        "daily" => current + chrono::Duration::days(1),
        "weekly" => current + chrono::Duration::weeks(1),
        "biweekly" => current + chrono::Duration::days(14),
        "monthly" => current + chrono::Duration::days(30),
        _ => current + chrono::Duration::days(1),
    };

    next.format("%Y-%m-%dT%H:%M").to_string()
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



// start_background_scheduler
pub async fn start_background_scheduler(pool: SqlitePool) {
    // 1. Initial Startup Snapshot
    // Runs once as soon as the server starts to ensure the dashboard has data.
    let startup_pool = pool.clone();
    tokio::spawn(async move {
        info!("Initiating startup compliance snapshot...");
        if let Err(e) = capture_compliance_snapshot(&startup_pool).await {
            error!("Startup compliance snapshot failed: {}", e);
        }
    });

    // 2. The Main "Heartbeat" Loop (Every 60 Seconds)
    let mut interval = time::interval(Duration::from_secs(60));

    // Clone the pool for the long-running loop
    let loop_pool = pool.clone();

    tokio::spawn(async move {
        loop {
            // Wait for the next 60-second tick
            interval.tick().await;

            let now = Utc::now();
            let now_str = now.format("%Y-%m-%dT%H:%M").to_string();

            // --- TASK A: POLICY SCAN SCHEDULER ---
            // Find all enabled policies that have reached their 'next_run' time
            let due_policies = sqlx::query_as::<_, PolicySchedule>(
                "SELECT * FROM policy_schedules WHERE enabled = 1 AND next_run <= ?"
            )
            .bind(&now_str)
            .fetch_all(&loop_pool)
            .await
            .unwrap_or_default();

            for schedule in due_policies {
                info!("Scheduler: Triggering Policy ID {} ('{}')", schedule.policy_id, now_str);

                // Execute the shared logic to insert commands into the queue
                match execute_policy_run_logic(schedule.policy_id, &loop_pool).await {
                    Ok(_) => {
                        // On success, calculate the NEXT time this should run
                        let next_run_time = calculate_next_run(&schedule.frequency, &schedule.next_run);

                        // Update the database: set the new next_run and update last_run to now
                        let update_res = sqlx::query(
                            "UPDATE policy_schedules SET next_run = ?, last_run = ? WHERE id = ?"
                        )
                        .bind(&next_run_time)
                        .bind(&now_str)
                        .bind(schedule.id)
                        .execute(&loop_pool)
                        .await;

                        if let Err(e) = update_res {
                            error!("Failed to update schedule for policy {}: {}", schedule.policy_id, e);
                        } else {
                            info!("Policy {} scheduled next for: {}", schedule.policy_id, next_run_time);
                        }
                    },
                    Err(e) => {
                        error!("Scheduled execution failed for policy {}: {}", schedule.policy_id, e);
                    }
                }
            }

            // --- TASK B: DAILY COMPLIANCE SNAPSHOT (For Trend Graphs) ---
            // Triggered only once per day at exactly Midnight (00:00)
            if now.hour() == 0 && now.minute() == 0 {
                info!("Running daily compliance aggregation snapshot...");
                if let Err(e) = capture_compliance_snapshot(&loop_pool).await {
                    error!("Daily compliance snapshot failed: {}", e);
                }
            }
        }
    });
}

