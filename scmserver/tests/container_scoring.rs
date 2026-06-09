// Integration test for the per-container compliance axis (0.7.0).
//
// Verifies the correctness-critical claim of the container work: per-container
// results (results.container_id > 0) are scored on their OWN axis and never
// fold into the host's system/test/policy scores. Runs the real schema +
// recalc against an in-memory SQLite DB — no Docker/agent needed.

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

// Wire system 1 into group 1 and policy 1, with the given test ids assigned to
// the policy. Without this, recalc's purge_ghost_results deletes the results.
async fn wire_policy(pool: &SqlitePool, test_ids: &[i64]) {
    sqlx::query("INSERT INTO system_groups (id, tenant_id, name) VALUES (1,'default','g1')")
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO policies (id, tenant_id, name) VALUES (1,'default','p1')")
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO systems_in_groups (tenant_id, system_id, group_id) VALUES ('default',1,1)")
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO systems_in_policy (tenant_id, policy_id, group_id) VALUES ('default',1,1)")
        .execute(pool).await.unwrap();
    for tid in test_ids {
        sqlx::query("INSERT INTO tests_in_policy (tenant_id, policy_id, test_id) VALUES ('default',1,?)")
            .bind(tid).execute(pool).await.unwrap();
    }
}

#[tokio::test]
async fn container_results_do_not_distort_host_scores() {
    let pool = fresh_pool().await;

    // One active host, two tests, one container on that host.
    sqlx::query("INSERT INTO systems (id, tenant_id, name, status) VALUES (1,'default','host1','active')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO tests (id, tenant_id, name) VALUES (1,'default','t-host'),(2,'default','t-both')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO containers (id, tenant_id, host_system_id, runtime, runtime_id, name)
                 VALUES (1,'default',1,'docker','abc123','nginx')")
        .execute(&pool).await.unwrap();
    // Wire the system+tests through a group→policy so results survive the
    // ghost-result purge that runs at the start of every recalc.
    wire_policy(&pool, &[1, 2]).await;

    // Host axis: t1 PASS, t2 FAIL  → 1/2 = 50%.
    // Container axis: t1 PASS, t2 PASS → 2/2 = 100%.
    // If the axes were NOT separated the host would see 3 PASS / 1 FAIL = 75%.
    sqlx::query(
        "INSERT INTO results (tenant_id, system_id, test_id, container_id, result) VALUES
            ('default',1,1,0,'PASS'),
            ('default',1,2,0,'FAIL'),
            ('default',1,1,1,'PASS'),
            ('default',1,2,1,'PASS')",
    ).execute(&pool).await.unwrap();

    scmserver::scheduler::recalculate_current_compliance(&pool).await.expect("recalc");

    // System (host) axis counts host-only results → 50, not 75.
    let sys_score: f64 = sqlx::query("SELECT score_test FROM systems WHERE id=1")
        .fetch_one(&pool).await.unwrap().get("score_test");
    assert!((sys_score - 50.0).abs() < 1e-6,
        "system score_test should be 50 (host only); container results leaked in → got {sys_score}");

    // Per-test stats are host-only: t2 has just the host FAIL → 0 (container PASS ignored).
    let t2: f64 = sqlx::query("SELECT compliance_score FROM tests WHERE id=2")
        .fetch_one(&pool).await.unwrap().get("compliance_score");
    assert!((t2 - 0.0).abs() < 1e-6,
        "test 2 compliance should be 0 (host FAIL only); container PASS leaked in → got {t2}");

    // Container axis = the container's own results → 100, 2 pass / 0 fail.
    let crow = sqlx::query("SELECT compliance_score, tests_passed, tests_failed FROM containers WHERE id=1")
        .fetch_one(&pool).await.unwrap();
    let c_score: f64 = crow.get("compliance_score");
    let c_pass: i64 = crow.get("tests_passed");
    let c_fail: i64 = crow.get("tests_failed");
    assert!((c_score - 100.0).abs() < 1e-6, "container score should be 100, got {c_score}");
    assert_eq!(c_pass, 2, "container tests_passed");
    assert_eq!(c_fail, 0, "container tests_failed");
}

#[tokio::test]
async fn fresh_install_seeds_exec_element_and_categorizes_it() {
    // A freshly initialized DB must have EXEC in the elements table (so it shows
    // in the test editor's Container optgroup).
    let pool = fresh_pool().await;
    let c: i64 = sqlx::query("SELECT COUNT(*) AS c FROM elements WHERE name = 'EXEC'")
        .fetch_one(&pool).await.unwrap().get("c");
    assert_eq!(c, 1, "fresh install should seed the EXEC element");
    // And the server categorizes it as a container element (Container optgroup).
    assert!(scmserver::tests::is_container_element("EXEC"), "EXEC must be a container element");
}

#[tokio::test]
async fn migration_v36_seeds_exec_and_drops_orphan_target_type() {
    // Simulate a DB at v35 that somehow carries an orphan tests.target_type
    // column (from an earlier 0.7.0 design). v36 must seed EXEC and drop it.
    let pool = SqlitePoolOptions::new().max_connections(1)
        .connect("sqlite::memory:").await.unwrap();
    sqlx::query("CREATE TABLE schema_info (id INTEGER PRIMARY KEY, version INTEGER)")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO schema_info (id, version) VALUES (1, 35)")
        .execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE elements (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)")
        .execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE tests (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, name TEXT NOT NULL, target_type TEXT)")
        .execute(&pool).await.unwrap();

    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    let exec: i64 = sqlx::query("SELECT COUNT(*) AS c FROM elements WHERE name = 'EXEC'")
        .fetch_one(&pool).await.unwrap().get("c");
    assert_eq!(exec, 1, "EXEC element should be seeded by v36");
    assert!(sqlx::query("SELECT target_type FROM tests").fetch_all(&pool).await.is_err(),
        "orphan tests.target_type column should be dropped");
    let v: i64 = sqlx::query("SELECT version FROM schema_info")
        .fetch_one(&pool).await.unwrap().get("version");
    assert!(v >= 36, "schema version should advance to >= 36, got {v}");
}

#[tokio::test]
async fn container_only_host_has_not_scanned_host_axis_but_scored_container() {
    // A host whose ONLY results are per-container: its host axis is "Not Scanned"
    // (-1), while the container still scores. Proves container results never
    // synthesize a host score.
    let pool = fresh_pool().await;
    sqlx::query("INSERT INTO systems (id, tenant_id, name, status) VALUES (1,'default','host1','active')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO tests (id, tenant_id, name) VALUES (1,'default','t-cont')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO containers (id, tenant_id, host_system_id, runtime, runtime_id, name)
                 VALUES (1,'default',1,'docker','def456','redis')")
        .execute(&pool).await.unwrap();
    wire_policy(&pool, &[1]).await;
    sqlx::query("INSERT INTO results (tenant_id, system_id, test_id, container_id, result)
                 VALUES ('default',1,1,1,'FAIL')")
        .execute(&pool).await.unwrap();

    scmserver::scheduler::recalculate_current_compliance(&pool).await.expect("recalc");

    let sys_score: f64 = sqlx::query("SELECT score_test FROM systems WHERE id=1")
        .fetch_one(&pool).await.unwrap().get("score_test");
    assert!((sys_score - (-1.0)).abs() < 1e-6,
        "host with only container results should be Not Scanned (-1), got {sys_score}");

    let c_score: f64 = sqlx::query("SELECT compliance_score FROM containers WHERE id=1")
        .fetch_one(&pool).await.unwrap().get("compliance_score");
    assert!((c_score - 0.0).abs() < 1e-6, "container with one FAIL should be 0, got {c_score}");

    // Pure-container policy: host axis is Not Scanned, but score_container holds
    // the container-axis value the list/report headline falls back to.
    let prow = sqlx::query("SELECT score_test, score_container FROM policies WHERE id=1")
        .fetch_one(&pool).await.unwrap();
    let p_test: f64 = prow.get("score_test");
    let p_cont: f64 = prow.get("score_container");
    assert!((p_test - (-1.0)).abs() < 1e-6, "policy host axis should be Not Scanned, got {p_test}");
    assert!((p_cont - 0.0).abs() < 1e-6, "policy score_container should be 0, got {p_cont}");
}
