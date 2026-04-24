use sqlx::{SqlitePool, Row};
use tokio::time::{self, Duration};
use chrono::{Utc, Timelike};
use tracing::{info, error};

use crate::models::PolicySchedule;
use crate::policies::execute_policy_run_logic;
use crate::handlers::add_notification;


/// Internal helper for date math
fn calculate_next_run(frequency: &str, last_planned_run: &str) -> String {
    let current = chrono::NaiveDateTime::parse_from_str(last_planned_run, "%Y-%m-%dT%H:%M")
        .unwrap_or_else(|_| Utc::now().naive_utc());

    let next = match frequency {
        "daily"    => current + chrono::Duration::days(1),
        "weekly"   => current + chrono::Duration::weeks(1),
        "biweekly" => current + chrono::Duration::days(14),
        "monthly"  => current + chrono::Duration::days(30),
        _          => current + chrono::Duration::days(1),
    };

    next.format("%Y-%m-%dT%H:%M").to_string()
}


/// Fetch all admin user IDs for a given tenant to notify on scheduled events.
async fn get_policy_owners(pool: &SqlitePool, tenant_id: &str) -> Vec<i32> {
    sqlx::query(
        "SELECT id FROM users WHERE tenant_id = ? AND role = 'admin'",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|row| row.get("id"))
    .collect()
}



pub async fn recalculate_current_compliance(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    info!("Starting compliance aggregation (Active Systems Only)...");

    let mut tx = pool.begin().await?;

    // =========================================================
    // 0. PURGE GHOST RESULTS
    // Delete results for tests no longer assigned to a system
    // =========================================================
    sqlx::query(r#"
        DELETE FROM results
        WHERE NOT EXISTS (
            SELECT 1
            FROM systems_in_groups sig
            JOIN systems_in_policy sip ON sig.group_id = sip.group_id
                AND sig.tenant_id = sip.tenant_id
            JOIN tests_in_policy tip ON sip.policy_id = tip.policy_id
                AND sip.tenant_id = tip.tenant_id
            WHERE sig.system_id = results.system_id
              AND tip.test_id   = results.test_id
              AND sig.tenant_id = results.tenant_id
        )
    "#)
    .execute(&mut *tx)
    .await?;

    // =========================================================
    // 1. Update TEST stats (active systems only, per tenant)
    // =========================================================
    sqlx::query(r#"
        UPDATE tests SET
            systems_passed = (
                SELECT COUNT(*) FROM results r
                JOIN systems s ON r.system_id = s.id AND r.tenant_id = s.tenant_id
                WHERE r.test_id    = tests.id
                  AND r.tenant_id  = tests.tenant_id
                  AND r.result     = 'PASS'
                  AND s.status     = 'active'
            ),
            systems_failed = (
                SELECT COUNT(*) FROM results r
                JOIN systems s ON r.system_id = s.id AND r.tenant_id = s.tenant_id
                WHERE r.test_id    = tests.id
                  AND r.tenant_id  = tests.tenant_id
                  AND r.result     = 'FAIL'
                  AND s.status     = 'active'
            ),
            compliance_score = (
                SELECT CASE WHEN COUNT(*) = 0 THEN -1.0
                ELSE (CAST(SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) AS REAL) / COUNT(*)) * 100
                END
                FROM results r
                JOIN systems s ON r.system_id = s.id AND r.tenant_id = s.tenant_id
                WHERE r.test_id   = tests.id
                  AND r.tenant_id = tests.tenant_id
                  AND s.status    = 'active'
            )
    "#)
    .execute(&mut *tx)
    .await?;

    // =========================================================
    // 2. Update SYSTEM stats (active systems only, per tenant)
    // =========================================================
    sqlx::query(r#"
        UPDATE systems SET
            tests_passed = (
                SELECT COUNT(*) FROM results
                WHERE system_id = systems.id
                  AND tenant_id = systems.tenant_id
                  AND result    = 'PASS'
            ),
            tests_failed = (
                SELECT COUNT(*) FROM results
                WHERE system_id = systems.id
                  AND tenant_id = systems.tenant_id
                  AND result    = 'FAIL'
            ),
            total_tests = (
                SELECT COUNT(*) FROM results
                WHERE system_id = systems.id
                  AND tenant_id = systems.tenant_id
            ),
            compliance_score = (
                SELECT CASE WHEN COUNT(*) = 0 THEN -1.0
                ELSE (CAST(SUM(CASE WHEN result = 'PASS' THEN 1 ELSE 0 END) AS REAL) / COUNT(*)) * 100
                END
                FROM results
                WHERE system_id = systems.id
                  AND tenant_id = systems.tenant_id
            )
        WHERE status = 'active'
    "#)
    .execute(&mut *tx)
    .await?;

    // =========================================================
    // 3. Update POLICY stats (SQLite compatible, per tenant)
    // =========================================================
    sqlx::query(r#"
        UPDATE policies SET
            systems_passed = (
                SELECT COUNT(CASE WHEN total_results > 0 AND fails = 0 THEN 1 END)
                FROM (
                    SELECT
                        s.id as system_id,
                        COUNT(r.result) as total_results,
                        SUM(CASE WHEN r.result = 'FAIL' THEN 1 ELSE 0 END) as fails
                    FROM systems_in_policy sip
                    JOIN systems_in_groups sig ON sip.group_id = sig.group_id
                        AND sip.tenant_id = sig.tenant_id
                    JOIN systems s ON sig.system_id = s.id
                        AND sig.tenant_id = s.tenant_id
                    LEFT JOIN results r ON r.system_id = s.id
                        AND r.tenant_id = s.tenant_id
                        AND r.test_id IN (
                            SELECT test_id FROM tests_in_policy
                            WHERE policy_id = policies.id
                              AND tenant_id = policies.tenant_id
                        )
                    WHERE sip.policy_id = policies.id
                      AND sip.tenant_id = policies.tenant_id
                      AND s.status = 'active'
                    GROUP BY s.id
                ) sub
            ),
            systems_failed = (
                SELECT COUNT(CASE WHEN fails > 0 THEN 1 END)
                FROM (
                    SELECT
                        s.id as system_id,
                        SUM(CASE WHEN r.result = 'FAIL' THEN 1 ELSE 0 END) as fails
                    FROM systems_in_policy sip
                    JOIN systems_in_groups sig ON sip.group_id = sig.group_id
                        AND sip.tenant_id = sig.tenant_id
                    JOIN systems s ON sig.system_id = s.id
                        AND sig.tenant_id = s.tenant_id
                    LEFT JOIN results r ON r.system_id = s.id
                        AND r.tenant_id = s.tenant_id
                        AND r.test_id IN (
                            SELECT test_id FROM tests_in_policy
                            WHERE policy_id = policies.id
                              AND tenant_id = policies.tenant_id
                        )
                    WHERE sip.policy_id = policies.id
                      AND sip.tenant_id = policies.tenant_id
                      AND s.status = 'active'
                    GROUP BY s.id
                ) sub
            ),
            compliance_score = (
                SELECT CASE
                    WHEN COUNT(CASE WHEN total_results > 0 THEN 1 END) = 0 THEN -1.0
                    ELSE (
                        CAST(COUNT(CASE WHEN total_results > 0 AND fails = 0 THEN 1 END) AS REAL) /
                        COUNT(CASE WHEN total_results > 0 THEN 1 END)
                    ) * 100
                END
                FROM (
                    SELECT
                        s.id as system_id,
                        COUNT(r.result) as total_results,
                        SUM(CASE WHEN r.result = 'FAIL' THEN 1 ELSE 0 END) as fails
                    FROM systems_in_policy sip
                    JOIN systems_in_groups sig ON sip.group_id = sig.group_id
                        AND sip.tenant_id = sig.tenant_id
                    JOIN systems s ON sig.system_id = s.id
                        AND sig.tenant_id = s.tenant_id
                    LEFT JOIN results r ON r.system_id = s.id
                        AND r.tenant_id = s.tenant_id
                        AND r.test_id IN (
                            SELECT test_id FROM tests_in_policy
                            WHERE policy_id = policies.id
                              AND tenant_id = policies.tenant_id
                        )
                    WHERE sip.policy_id = policies.id
                      AND sip.tenant_id = policies.tenant_id
                      AND s.status = 'active'
                    GROUP BY s.id
                ) sub
            )
    "#)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    info!("Compliance recalculation complete.");
    Ok(())
}




pub async fn record_compliance_history(pool: &SqlitePool) -> Result<(), sqlx::Error> {

    // Get all active tenants
    let tenants: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM tenants",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for tenant_id in tenants {

        // Average only scanned active systems (exclude -1.0)
        let sys_stats = sqlx::query(
            "SELECT AVG(compliance_score) as avg_score, COUNT(*) as total
             FROM systems
             WHERE tenant_id = ?
             AND status = 'active'
             AND compliance_score >= 0",
        )
        .bind(&tenant_id)
        .fetch_one(pool)
        .await?;

        // Average only scanned policies (exclude -1.0)
        let pol_stats = sqlx::query(
            "SELECT AVG(compliance_score) as avg_score, COUNT(*) as total
             FROM policies
             WHERE tenant_id = ?
             AND compliance_score >= 0",
        )
        .bind(&tenant_id)
        .fetch_one(pool)
        .await?;

        let systems_score  = sys_stats.try_get::<f64, _>("avg_score").unwrap_or(0.0);
        let systems_score = (systems_score * 100.0).round() / 100.0; 
        let policies_score = pol_stats.try_get::<f64, _>("avg_score").unwrap_or(0.0);
        let policies_score = (policies_score * 100.0).round() / 100.0; 
        let total_systems  = sys_stats.try_get::<i32, _>("total").unwrap_or(0);
        let total_policies = pol_stats.try_get::<i32, _>("total").unwrap_or(0);

        sqlx::query(r#"
            INSERT INTO compliance_history (
                tenant_id, systems_score, policies_score, total_systems,
                total_policies, failed_systems, failed_policies
            )
            VALUES (?, ?, ?, ?, ?,
                (SELECT COUNT(*) FROM systems
                 WHERE compliance_score < 100
                 AND compliance_score >= 0
                 AND tenant_id = ?
                 AND status = 'active'),
                (SELECT COUNT(*) FROM policies
                 WHERE compliance_score < 100
                 AND compliance_score >= 0
                 AND tenant_id = ?)
            )
        "#)
        .bind(&tenant_id)
        .bind(systems_score)
        .bind(policies_score)
        .bind(total_systems)
        .bind(total_policies)
        .bind(&tenant_id)
        .bind(&tenant_id)
        .execute(pool)
        .await?;

        info!(
            "Compliance trend snapshot recorded for tenant '{}': Sys {}%, Pol {}%",
            tenant_id, systems_score, policies_score
        );
    }

    Ok(())
}


pub async fn start_background_scheduler(pool: SqlitePool) {
    // Startup compliance sync
    let startup_pool = pool.clone();
    tokio::spawn(async move {
        info!("Initiating startup compliance synchronization...");
        if let Err(e) = recalculate_current_compliance(&startup_pool).await {
            error!("Startup compliance recalculation failed: {}", e);
        } else {
            info!("Compliance status successfully synchronized on startup.");
        }
    });

    // Main heartbeat loop — every 60 seconds
    let mut interval = time::interval(Duration::from_secs(60));
    let loop_pool = pool.clone();

    tokio::spawn(async move {
        let mut last_snapshot_hour: i32 = Utc::now().hour() as i32;

        loop {
            interval.tick().await;

            let now = Utc::now();
            let now_str = now.format("%Y-%m-%dT%H:%M").to_string();
            let current_hour = now.hour() as i32;

            // --- TASK A: POLICY SCAN SCHEDULER (every 60s) ---
            let due_policies = match sqlx::query_as::<_, PolicySchedule>(
                "SELECT * FROM policy_schedules WHERE enabled = 1 AND next_run <= ?",
            )
            .bind(&now_str)
            .fetch_all(&loop_pool)
            .await
            {
                Ok(policies) => policies,
                Err(e) => {
                    error!("Failed to fetch due policies from scheduler: {}", e);
                    vec![]
                }
            };

            for schedule in due_policies {
                info!(
                    "Scheduler: Triggering Policy ID {} at '{}'",
                    schedule.policy_id, now_str
                );

                match execute_policy_run_logic(
                    schedule.policy_id,
                    &loop_pool,
                    &schedule.tenant_id,
                )
                .await
                {
                    Ok(_) => {
                        // Update next run time
                        let next_run_time =
                            calculate_next_run(&schedule.frequency, &schedule.next_run);

                        if let Err(e) = sqlx::query(
                            "UPDATE policy_schedules SET next_run = ?, last_run = ? WHERE id = ?",
                        )
                        .bind(&next_run_time)
                        .bind(&now_str)
                        .bind(schedule.id)
                        .execute(&loop_pool)
                        .await
                        {
                            error!(
                                "Failed to update schedule for policy {}: {}",
                                schedule.policy_id, e
                            );
                        } else {
                            info!(
                                "Scheduled scan successfully initiated for Policy ID: {}",
                                schedule.policy_id
                            );
                        }

                        // Notify all tenant admins of successful scheduled run
                        for owner_id in get_policy_owners(&loop_pool, &schedule.tenant_id).await {
                            add_notification(
                                &loop_pool,
                                &schedule.tenant_id,
                                "info",
                                owner_id,
                                &format!(
                                    "Scheduled policy run completed for Policy ID {}.",
                                    schedule.policy_id
                                ),
                            )
                            .await;
                        }
                    }

                    Err(e) => {
                        error!(
                            "Scheduled execution failed for policy {}: {}",
                            schedule.policy_id, e
                        );

                        // Notify all tenant admins of failed scheduled run
                        for owner_id in get_policy_owners(&loop_pool, &schedule.tenant_id).await {
                            add_notification(
                                &loop_pool,
                                &schedule.tenant_id,
                                "warning",
                                owner_id,
                                &format!(
                                    "Scheduled policy run FAILED for Policy ID {}. Error: {}",
                                    schedule.policy_id, e
                                ),
                            )
                            .await;
                        }
                    }
                }
            }


            // --- TASK B: HOURLY COMPLIANCE SNAPSHOT (for trend graphs) ---
            if now.minute() == 0 && current_hour != last_snapshot_hour {
                info!("Running hourly compliance aggregation snapshot...");
                if let Err(e) = record_compliance_history(&loop_pool).await {
                    error!("Hourly compliance snapshot failed: {}", e);
                } else {
                    last_snapshot_hour = current_hour;
                    info!("Hourly compliance snapshot recorded successfully.");
                }
            }
        }
    });
}
