// Integration tests for the per-system policy re-run (the "Run" button on each
// policy card in the system report).
//
// The important property is scoping: the helper must queue tests ONLY for the
// requested system, and must queue nothing at all when the policy doesn't
// cover that system — the join is what stops a crafted request from pushing a
// policy's tests onto an unrelated host.

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

// Systems 1 and 2 are in group 10, which policy 100 targets. System 3 is in
// group 20, which no policy targets. Policy 100 carries tests 1000 and 1001.
async fn seed(pool: &SqlitePool) {
    sqlx::query(
        "INSERT INTO systems (id, tenant_id, name, status) VALUES
            (1,'default','covered-a','active'),
            (2,'default','covered-b','active'),
            (3,'default','uncovered','active')",
    ).execute(pool).await.unwrap();

    // Parent rows the join/FKs require.
    sqlx::query(
        "INSERT INTO system_groups (id, tenant_id, name) VALUES
            (10,'default','targeted'),(20,'default','untargeted')",
    ).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO policies (id, tenant_id, name) VALUES (100,'default','p1')")
        .execute(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO tests (id, tenant_id, name) VALUES
            (1000,'default','t1'),(1001,'default','t2')",
    ).execute(pool).await.unwrap();

    sqlx::query(
        "INSERT INTO systems_in_groups (tenant_id, system_id, group_id) VALUES
            ('default',1,10),('default',2,10),('default',3,20)",
    ).execute(pool).await.unwrap();

    sqlx::query(
        "INSERT INTO systems_in_policy (tenant_id, policy_id, group_id)
         VALUES ('default',100,10)",
    ).execute(pool).await.unwrap();

    sqlx::query(
        "INSERT INTO tests_in_policy (tenant_id, policy_id, test_id)
         VALUES ('default',100,1000),('default',100,1001)",
    ).execute(pool).await.unwrap();
}

async fn queued_for(pool: &SqlitePool, system_id: i32) -> i64 {
    sqlx::query("SELECT COUNT(*) AS c FROM commands WHERE system_id = ?")
        .bind(system_id)
        .fetch_one(pool).await.unwrap().get("c")
}

#[tokio::test]
async fn queues_the_policys_tests_for_that_system_only() {
    let pool = fresh_pool().await;
    seed(&pool).await;

    let queued = scmserver::policies::execute_policy_run_for_system(100, 1, &pool, "default")
        .await.expect("run");

    assert_eq!(queued, 2, "both of the policy's tests are queued");
    assert_eq!(queued_for(&pool, 1).await, 2, "target system got the tests");
    assert_eq!(queued_for(&pool, 2).await, 0, "the other covered system is untouched");
}

#[tokio::test]
async fn queues_nothing_when_the_policy_does_not_cover_the_system() {
    let pool = fresh_pool().await;
    seed(&pool).await;

    let queued = scmserver::policies::execute_policy_run_for_system(100, 3, &pool, "default")
        .await.expect("run");

    assert_eq!(queued, 0, "policy 100 does not target system 3's group");
    assert_eq!(queued_for(&pool, 3).await, 0, "no commands leaked onto an uncovered host");
}

#[tokio::test]
async fn does_not_cross_tenant_boundaries() {
    let pool = fresh_pool().await;
    seed(&pool).await;

    let queued = scmserver::policies::execute_policy_run_for_system(100, 1, &pool, "other-tenant")
        .await.expect("run");

    assert_eq!(queued, 0, "another tenant cannot queue scans against this system");
    assert_eq!(queued_for(&pool, 1).await, 0, "no commands written");
}

#[tokio::test]
async fn re_running_is_idempotent() {
    let pool = fresh_pool().await;
    seed(&pool).await;

    scmserver::policies::execute_policy_run_for_system(100, 1, &pool, "default").await.unwrap();
    // A second click before the agent checks in must not duplicate the queue
    // (INSERT OR IGNORE against the commands primary key).
    let second = scmserver::policies::execute_policy_run_for_system(100, 1, &pool, "default")
        .await.expect("run");

    assert_eq!(second, 0, "already-queued tests are not re-inserted");
    assert_eq!(queued_for(&pool, 1).await, 2, "queue still holds exactly the two tests");
}
