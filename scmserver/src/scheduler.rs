use sqlx::{SqlitePool, Row};
use tokio::time::{self, Duration};
use chrono::{Utc, Timelike};
use tracing::{info,warn,error};


use crate::models::PolicySchedule;
use crate::policies::execute_policy_run_logic;
use crate::handlers::add_notification;


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




pub async fn capture_compliance_snapshot(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    info!("Starting compliance aggregation using Strict Policy methodology...");

    // 1. Update TEST stats
    // Updates the health of each individual test across the whole environment
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

    // 2. Update SYSTEM stats
    // System Score = (Passed Tests / Total Tests) * 100
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



    // 3. Update POLICY stats (Strict Scoped Binary)
    sqlx::query(r#"
        UPDATE policies SET
            compliance_score = COALESCE((
                SELECT
                    (CAST(SUM(CASE WHEN policy_failures = 0 THEN 1 ELSE 0 END) AS REAL) / COUNT(*)) * 100
                FROM (
                    SELECT
                        s.id,
                        (SELECT COUNT(*) FROM results r
                         JOIN tests_in_policy tip ON r.test_id = tip.test_id
                         WHERE r.system_id = s.id AND tip.policy_id = policies.id AND r.result = 'FAIL'
                        ) as policy_failures
                    FROM systems s
                    JOIN systems_in_groups sig ON s.id = sig.system_id
                    JOIN systems_in_policy sip ON sig.group_id = sip.group_id
                    WHERE sip.policy_id = policies.id
                    GROUP BY s.id
                ) as scoped_results
            ), 0.0)
    "#).execute(pool).await?;

    // 4. Gather metrics for history
    let sys_stats = sqlx::query("SELECT AVG(compliance_score) as avg_score, COUNT(*) as total FROM systems")
        .fetch_one(pool).await?;
    let pol_stats = sqlx::query("SELECT AVG(compliance_score) as avg_score, COUNT(*) as total FROM policies")
        .fetch_one(pool).await?;

    let systems_score = sys_stats.try_get::<f64, _>("avg_score").unwrap_or(0.0);
    let total_systems = sys_stats.try_get::<i32, _>("total").unwrap_or(0);

    let policies_score = pol_stats.try_get::<f64, _>("avg_score").unwrap_or(0.0);
    let total_policies = pol_stats.try_get::<i32, _>("total").unwrap_or(0);

    // 5. Record History with full context
    sqlx::query(
        r#"
        INSERT INTO compliance_history (
            systems_score,
            policies_score,
            total_systems,
            failed_systems,
            total_policies,
            failed_policies
        )
        VALUES (?, ?, ?,
            (SELECT COUNT(*) FROM systems WHERE compliance_score < 100),
            ?,
            (SELECT COUNT(*) FROM policies WHERE compliance_score < 100)
        )
        "#
    )
    .bind(systems_score)
    .bind(policies_score)
    .bind(total_systems)
    .bind(total_policies)
    .execute(pool).await?;

    info!("Snapshot saved: {} Systems ({}% avg), {} Policies ({}% avg)",
        total_systems, systems_score, total_policies, policies_score);

    Ok(())
}



// start_background_scheduler
pub async fn start_background_scheduler(pool: SqlitePool) {
    // 1. Initial Startup Snapshot
    let startup_pool = pool.clone();
    tokio::spawn(async move {
        info!("Initiating startup compliance snapshot...");
        if let Err(e) = capture_compliance_snapshot(&startup_pool).await {
            error!("Startup compliance snapshot failed: {}", e);
        }
    });

    // 2. The Main "Heartbeat" Loop (Every 60 Seconds)
    let mut interval = time::interval(Duration::from_secs(60));
    let loop_pool = pool.clone();

    tokio::spawn(async move {
        // Variable to prevent double-firing Task B within the same minute
        let mut last_snapshot_hour: i32 = -1;

        loop {
            interval.tick().await;

            let now = Utc::now();
            let now_str = now.format("%Y-%m-%dT%H:%M").to_string();
            let current_hour = now.hour() as i32;

            // --- TASK A: POLICY SCAN SCHEDULER (Every 60s) ---
            let due_policies = sqlx::query_as::<_, PolicySchedule>(
                "SELECT * FROM policy_schedules WHERE enabled = 1 AND next_run <= ?"
            )
            .bind(&now_str)
            .fetch_all(&loop_pool)
            .await
            .unwrap_or_default();

            for schedule in due_policies {
                info!("Scheduler: Triggering Policy ID {} ('{}')", schedule.policy_id, now_str);

                match execute_policy_run_logic(schedule.policy_id, &loop_pool).await {
                    Ok(_) => {
                        let next_run_time = calculate_next_run(&schedule.frequency, &schedule.next_run);
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
                            info!("Scheduled scan successfully initiated for Policy ID: {}", schedule.policy_id);
                        }
                    },
                    Err(e) => {
                        error!("Scheduled execution failed for policy {}: {}", schedule.policy_id, e);
                        let msg = format!("Automation Error: Failed to run Policy ID {}. Error: {}", schedule.policy_id, e);
                        add_notification(&loop_pool, "error", 0, &msg).await;
                    }
                }
            }

            // --- TASK B: HOURLY COMPLIANCE SNAPSHOT (For Trend Graphs) ---
            // Triggered whenever the minute is 00 (once per hour)
            if now.minute() == 0 && current_hour != last_snapshot_hour {
                info!("Running hourly compliance aggregation snapshot for trend graph...");
                if let Err(e) = capture_compliance_snapshot(&loop_pool).await {
                    error!("Hourly compliance snapshot failed: {}", e);
                } else {
                    // Update guard variable to ensure we don't run again until next hour
                    last_snapshot_hour = current_hour;
                }
            }
        }
    });
}


