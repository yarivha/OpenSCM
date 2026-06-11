// Integration tests for the per-entity compliance trend history (0.7.2).
//
// Exercises the real schema + recorder + retention prune against an in-memory
// SQLite DB: snapshots carry BOTH compliance axes, not-scanned entities are
// skipped (gap, not a -1 row), and the prune trims by check_date per the
// entity/fleet retention settings.

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{SqlitePool, Row};

// max_connections(1) so every query hits the SAME in-memory database.
async fn fresh_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory pool");
    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("migrations");
    pool
}

#[tokio::test]
async fn recorder_snapshots_both_axes_and_skips_not_scanned() {
    let pool = fresh_pool().await;

    // Two scanned systems (one with a divergent strict axis), one not-scanned,
    // one scanned policy.
    sqlx::query(
        "INSERT INTO systems (id, tenant_id, name, status, compliance_score, score_test, score_policy, tests_passed, tests_failed) VALUES
            (1,'default','h1','active', 90.0, 90.0,  0.0, 9, 1),
            (2,'default','h2','active', -1.0, -1.0, -1.0, 0, 0),
            (3,'default','h3','active', 50.0, 50.0, 50.0, 1, 1)",
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO policies (id, tenant_id, name, compliance_score, score_test, score_system, systems_passed, systems_failed)
         VALUES (1,'default','p1', 75.0, 75.0, 0.0, 3, 1)",
    ).execute(&pool).await.unwrap();

    scmserver::scheduler::record_entity_history(&pool).await.expect("recorder");

    // Not-scanned system 2 is skipped: 2 system rows + 1 policy row.
    let n: i64 = sqlx::query("SELECT COUNT(*) AS c FROM entity_compliance_history")
        .fetch_one(&pool).await.unwrap().get("c");
    assert_eq!(n, 3, "scanned entities only");

    // System 1 carries BOTH axes (per-test 90, strict/per-policy 0).
    let r = sqlx::query(
        "SELECT score_test, score_strict, tests_passed, tests_failed
         FROM entity_compliance_history WHERE entity_type='system' AND entity_id=1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(r.get::<f64, _>("score_test"), 90.0);
    assert_eq!(r.get::<f64, _>("score_strict"), 0.0);
    assert_eq!(r.get::<i64, _>("tests_passed"), 9);
    assert_eq!(r.get::<i64, _>("tests_failed"), 1);

    // Policy row maps score_system → score_strict and the systems_* tallies.
    let p = sqlx::query(
        "SELECT score_test, score_strict, tests_passed
         FROM entity_compliance_history WHERE entity_type='policy' AND entity_id=1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(p.get::<f64, _>("score_test"), 75.0);
    assert_eq!(p.get::<f64, _>("score_strict"), 0.0);
    assert_eq!(p.get::<i64, _>("tests_passed"), 3);
}

#[tokio::test]
async fn prune_trims_entity_and_fleet_history_by_retention() {
    let pool = fresh_pool().await;

    // One old + one fresh row in each table. Defaults seeded by the schema:
    // entity_trend_retention_days = 90, fleet_trend_retention_days = 365.
    sqlx::query(
        "INSERT INTO entity_compliance_history (tenant_id, entity_type, entity_id, check_date, score_test, score_strict) VALUES
            ('default','system',1, strftime('%Y-%m-%d %H:%M:%S','now','-100 days'), 80.0, 80.0),
            ('default','system',1, strftime('%Y-%m-%d %H:%M:%S','now','-1 day'),    85.0, 85.0)",
    ).execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO compliance_history (tenant_id, check_date, systems_score, policies_score) VALUES
            ('default', strftime('%Y-%m-%d %H:%M:%S','now','-400 days'), 70.0, 70.0),
            ('default', strftime('%Y-%m-%d %H:%M:%S','now','-1 day'),    75.0, 75.0)",
    ).execute(&pool).await.unwrap();

    scmserver::scheduler::prune_trends(&pool).await;

    let e: i64 = sqlx::query("SELECT COUNT(*) AS c FROM entity_compliance_history")
        .fetch_one(&pool).await.unwrap().get("c");
    assert_eq!(e, 1, "entity row older than 90 days should be pruned");
    let f: i64 = sqlx::query("SELECT COUNT(*) AS c FROM compliance_history")
        .fetch_one(&pool).await.unwrap().get("c");
    assert_eq!(f, 1, "fleet row older than 365 days should be pruned");

    // Retention 0 = keep forever: re-add an old row, disable, prune again.
    sqlx::query("UPDATE settings SET value='0' WHERE skey='entity_trend_retention_days'")
        .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO entity_compliance_history (tenant_id, entity_type, entity_id, check_date, score_test, score_strict)
         VALUES ('default','system',1, strftime('%Y-%m-%d %H:%M:%S','now','-100 days'), 80.0, 80.0)",
    ).execute(&pool).await.unwrap();
    scmserver::scheduler::prune_trends(&pool).await;
    let e2: i64 = sqlx::query("SELECT COUNT(*) AS c FROM entity_compliance_history")
        .fetch_one(&pool).await.unwrap().get("c");
    assert_eq!(e2, 2, "retention 0 must keep everything");
}
