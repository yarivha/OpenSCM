use sqlx::{SqlitePool, Row};
use tokio::time::{self, Duration};
use chrono::{Utc, Timelike};
use tracing::{info, error};
use reqwest::Client;

use crate::models::PolicySchedule;
use crate::policies::execute_policy_run_logic;
use crate::handlers::add_notification;
use crate::reports::save_policy_report_logic;

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
                  AND r.result    != 'NA'
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
                  AND result != 'NA'
            )
        WHERE status = 'active'
    "#)
    .execute(&mut *tx)
    .await?;

    // =========================================================
    // 3. Update POLICY stats (SQLite compatible, per tenant)
    // NA-aware: systems with only NA results are excluded from
    // both numerator and denominator of compliance score
    // =========================================================
    sqlx::query(r#"
        UPDATE policies SET
            systems_passed = (
                SELECT COUNT(CASE WHEN passes > 0 AND fails = 0 THEN 1 END)
                FROM (
                    SELECT
                        s.id as system_id,
                        SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) as passes,
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
                    -- No systems with PASS or FAIL results → Not Scanned
                    WHEN COUNT(CASE WHEN passes > 0 OR fails > 0 THEN 1 END) = 0 THEN -1.0
                    ELSE (
                        CAST(COUNT(CASE WHEN passes > 0 AND fails = 0 THEN 1 END) AS REAL) /
                        COUNT(CASE WHEN passes > 0 OR fails > 0 THEN 1 END)
                    ) * 100
                END
                FROM (
                    SELECT
                        s.id as system_id,
                        SUM(CASE WHEN r.result = 'PASS' THEN 1 ELSE 0 END) as passes,
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
        // COUNT(*) returns i64 in SQLite — use i64 to avoid overflow
        let total_systems  = sys_stats.try_get::<i64, _>("total").unwrap_or(0);
        let total_policies = pol_stats.try_get::<i64, _>("total").unwrap_or(0);

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

            // --- TASK A: POLICY SCHEDULER (scan + report) ---
            let due_schedules = match sqlx::query_as::<_, PolicySchedule>(
                "SELECT * FROM policy_schedules WHERE enabled = 1 AND next_run <= ?",
            )
            .bind(&now_str)
            .fetch_all(&loop_pool)
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to fetch due schedules: {}", e);
                    vec![]
                }
            };

            for schedule in due_schedules {
                info!(
                    "Scheduler: Triggering Policy ID {} type='{}' at '{}'",
                    schedule.policy_id, schedule.schedule_type, now_str
                );

                let result = match schedule.schedule_type.as_str() {
                    "report" => {
                        save_policy_report_logic(
                            schedule.policy_id as i64,
                            &loop_pool,
                            &schedule.tenant_id,
                            "Scheduler",
                        )
                        .await
                    }
                    _ => {
                        execute_policy_run_logic(
                            schedule.policy_id,
                            &loop_pool,
                            &schedule.tenant_id,
                        )
                        .await
                    }
                };

                match result {
                    Ok(_) => {
                        let next_run_time = calculate_next_run(&schedule.frequency, &schedule.next_run);
                        if let Err(e) = sqlx::query(
                            "UPDATE policy_schedules SET next_run = ?, last_run = ? WHERE id = ?",
                        )
                        .bind(&next_run_time)
                        .bind(&now_str)
                        .bind(schedule.id)
                        .execute(&loop_pool)
                        .await
                        {
                            error!("Failed to update schedule for policy {}: {}", schedule.policy_id, e);
                        } else {
                            let msg = match schedule.schedule_type.as_str() {
                                "report" => format!("Scheduled report saved for Policy ID {}.", schedule.policy_id),
                                _ => format!("Scheduled scan completed for Policy ID {}.", schedule.policy_id),
                            };
                            info!("{}", msg);
                            for owner_id in get_policy_owners(&loop_pool, &schedule.tenant_id).await {
                                add_notification(&loop_pool, &schedule.tenant_id, "info", owner_id, &msg).await;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Scheduled {} failed for policy {}: {}", schedule.schedule_type, schedule.policy_id, e);
                        let msg = format!(
                            "Scheduled {} FAILED for Policy ID {}. Error: {}",
                            schedule.schedule_type, schedule.policy_id, e
                        );
                        for owner_id in get_policy_owners(&loop_pool, &schedule.tenant_id).await {
                            add_notification(&loop_pool, &schedule.tenant_id, "warning", owner_id, &msg).await;
                        }
                    }
                }
            }

            // --- TASK B: HOURLY COMPLIANCE SNAPSHOT ---
            if now.minute() == 0 && current_hour != last_snapshot_hour {
                info!("Running hourly compliance aggregation snapshot...");
                if let Err(e) = record_compliance_history(&loop_pool).await {
                    error!("Hourly compliance snapshot failed: {}", e);
                } else {
                    last_snapshot_hour = current_hour;
                    info!("Hourly compliance snapshot recorded successfully.");
                }

                // --- TASK C: VERSION UPDATE CHECK ---
                check_for_updates(&loop_pool).await;
            }
        }
    });
}



// ============================================================
// VERSION UPDATE CHECK
// ============================================================

async fn check_for_updates(pool: &SqlitePool) {
    let current = env!("CARGO_PKG_VERSION");

    let client = match Client::builder()
        .user_agent("OpenSCM-Server")
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => { error!("Version check: failed to build HTTP client: {}", e); return; }
    };

    let resp = match client
        .get("https://api.github.com/repos/yarivha/OpenSCM/releases/latest")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => { error!("Version check: request failed: {}", e); return; }
    };

    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => { error!("Version check: failed to parse response: {}", e); return; }
    };

    let latest_tag = match json.get("tag_name").and_then(|v| v.as_str()) {
        Some(t) => t.trim_start_matches('v').to_string(),
        None => { error!("Version check: tag_name missing from GitHub response"); return; }
    };

    if !is_newer(&latest_tag, current) {
        info!("Version check: up to date ({})", current);
        return;
    }

    info!("Version check: new version {} available (current: {})", latest_tag, current);

    let msg = format!(
        "OpenSCM {} is available. You are running {}. Visit https://openscm.io to update.",
        latest_tag, current
    );

    // Notify all admin users in all tenants (skip if already notified about this version)
    let admin_rows = match sqlx::query(
        "SELECT id, tenant_id FROM users WHERE role = 'admin'",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => { error!("Version check: failed to fetch admin users: {}", e); return; }
    };

    for row in admin_rows {
        let user_id: i32 = row.get("id");
        let tenant_id: String = row.get("tenant_id");

        // Skip if already notified about this version
        let already: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notify WHERE owner_id = ? AND message LIKE ?",
        )
        .bind(user_id)
        .bind(format!("%{}%", latest_tag))
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        if already == 0 {
            add_notification(pool, &tenant_id, "warning", user_id, &msg).await;
        }
    }
}

/// Returns true if `latest` is a higher semver than `current`.
fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> (u32, u32, u32) {
        let parts: Vec<u32> = v.split('.').filter_map(|p| p.parse().ok()).collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    }
    parse(latest) > parse(current)
}
