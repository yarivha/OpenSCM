// Integration tests for auto-prune of inactive systems.
//
// Regression guard for the data-loss bug where a server outage longer than
// auto_prune_inactive deleted the entire fleet on the first tick after
// restart: while the server is down no agent can report, so every last_seen
// goes stale. The prune must therefore only judge a system inactive once the
// server itself has been up at least as long as the tenant's threshold.

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{SqlitePool, Row};
use std::time::Duration;

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

// Two active systems whose last_seen is far older than any threshold — the
// state the whole fleet is in right after a long server outage.
async fn seed_stale_fleet(pool: &SqlitePool, threshold_minutes: i64) {
    sqlx::query(
        "INSERT INTO systems (id, tenant_id, name, status, last_seen) VALUES
            (1,'default','h1','active', datetime('now','-1 day')),
            (2,'default','h2','active', datetime('now','-1 day'))",
    ).execute(pool).await.unwrap();

    sqlx::query(
        "INSERT OR REPLACE INTO settings (tenant_id, skey, value)
         VALUES ('default','auto_prune_inactive', ?)",
    )
    .bind(threshold_minutes.to_string())
    .execute(pool).await.unwrap();
}

async fn active_count(pool: &SqlitePool) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM systems")
        .fetch_one(pool).await.unwrap().get("c")
}

#[tokio::test]
async fn outage_does_not_wipe_fleet_before_agents_can_check_in() {
    let pool = fresh_pool().await;
    seed_stale_fleet(&pool, 30).await; // prune after 30 minutes inactive

    // Server has only been up 5 minutes after the outage — far less than the
    // 30-minute threshold, so the agents simply haven't had a chance to report.
    scmserver::scheduler::prune_inactive_systems(&pool, Duration::from_secs(5 * 60)).await;

    assert_eq!(
        active_count(&pool).await, 2,
        "systems must survive: stale last_seen here means the server was down, not the agents"
    );
}

#[tokio::test]
async fn genuinely_inactive_systems_are_pruned_once_server_has_been_up() {
    let pool = fresh_pool().await;
    seed_stale_fleet(&pool, 30).await;

    // Server has now been up longer than the threshold, so a system that STILL
    // hasn't checked in is provably absent rather than a victim of downtime.
    scmserver::scheduler::prune_inactive_systems(&pool, Duration::from_secs(31 * 60)).await;

    assert_eq!(
        active_count(&pool).await, 0,
        "systems still silent after a full threshold of server uptime are pruned"
    );
}

#[tokio::test]
async fn recently_seen_systems_survive_even_after_long_uptime() {
    let pool = fresh_pool().await;
    seed_stale_fleet(&pool, 30).await;
    // h2 checked in just now — it must never be pruned.
    sqlx::query("UPDATE systems SET last_seen = datetime('now') WHERE id = 2")
        .execute(&pool).await.unwrap();

    scmserver::scheduler::prune_inactive_systems(&pool, Duration::from_secs(24 * 60 * 60)).await;

    let remaining: Vec<i64> = sqlx::query("SELECT id FROM systems ORDER BY id")
        .fetch_all(&pool).await.unwrap()
        .iter().map(|r| r.get::<i64, _>("id")).collect();
    assert_eq!(remaining, vec![2], "only the system that never reported is pruned");
}
