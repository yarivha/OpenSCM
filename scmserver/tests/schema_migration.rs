/// Integration tests for schema initialization and migration v3 → v4.
///
/// These tests use an in-memory SQLite database so they run in isolation
/// without touching any real data files.
use sqlx::{SqlitePool, Row};

async fn in_memory_pool() -> SqlitePool {
    SqlitePool::connect("sqlite::memory:").await.expect("in-memory pool")
}

// ============================================================
// FRESH INSTALL
// ============================================================

/// A fresh install should seed schema_info at v4 and create the tests
/// table WITHOUT any flat condition columns.
#[tokio::test]
async fn fresh_install_seeds_version_4() {
    let pool = in_memory_pool().await;

    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    let version: i64 = sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(&pool).await.expect("version");

    assert_eq!(version, 4, "fresh install should be at schema v4");
}

#[tokio::test]
async fn fresh_install_tests_table_has_no_flat_columns() {
    let pool = in_memory_pool().await;

    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    // PRAGMA table_info returns one row per column
    let has_flat: bool = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM pragma_table_info('tests') WHERE name = 'element_1'"
    )
    .fetch_one(&pool).await.expect("pragma") > 0;

    assert!(!has_flat, "fresh install: tests table must not have element_1 column");
}

#[tokio::test]
async fn fresh_install_test_conditions_table_exists() {
    let pool = in_memory_pool().await;

    scmserver::schema::initialize_database(&pool).await.expect("init");
    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    // Should be able to query test_conditions without error
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM test_conditions")
        .fetch_one(&pool).await.expect("test_conditions query");

    assert_eq!(count, 0);
}

// ============================================================
// MIGRATION v3 → v4 (upgrading from old flat-column schema)
// ============================================================

/// Applies the old v3 schema to an empty database, inserts test data
/// using the flat columns, then runs migration and verifies that:
/// - The data lands in test_conditions with type='condition'
/// - The tests table no longer has flat columns
/// - schema_info version = 4
async fn setup_old_v3_schema(pool: &SqlitePool) {
    // Minimal prerequisite tables
    sqlx::query("CREATE TABLE IF NOT EXISTS schema_info (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)")
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO schema_info (id, version) VALUES (1, 3)")
        .execute(pool).await.unwrap();

    sqlx::query("CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE)")
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO tenants (id, name) VALUES ('default', 'Default')")
        .execute(pool).await.unwrap();

    // Old tests table WITH flat columns
    sqlx::query(r#"CREATE TABLE tests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        description TEXT,
        rational TEXT,
        remediation TEXT,
        severity TEXT,
        app_filter TEXT DEFAULT 'all',
        filter TEXT DEFAULT 'all',
        element_1 TEXT, input_1 TEXT, selement_1 TEXT, condition_1 TEXT, sinput_1 TEXT,
        element_2 TEXT, input_2 TEXT, selement_2 TEXT, condition_2 TEXT, sinput_2 TEXT,
        element_3 TEXT, input_3 TEXT, selement_3 TEXT, condition_3 TEXT, sinput_3 TEXT,
        element_4 TEXT, input_4 TEXT, selement_4 TEXT, condition_4 TEXT, sinput_4 TEXT,
        element_5 TEXT, input_5 TEXT, selement_5 TEXT, condition_5 TEXT, sinput_5 TEXT,
        compliance_score REAL DEFAULT 0.0,
        systems_passed INTEGER DEFAULT 0,
        systems_failed INTEGER DEFAULT 0,
        FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
    )"#).execute(pool).await.unwrap();

    // test_conditions table (already existed for applicability in v3)
    sqlx::query(r#"CREATE TABLE test_conditions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        test_id INTEGER NOT NULL,
        name TEXT,
        description TEXT,
        type TEXT NOT NULL,
        element TEXT NOT NULL,
        input TEXT NOT NULL,
        selement TEXT NOT NULL,
        condition TEXT,
        sinput TEXT,
        FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
    )"#).execute(pool).await.unwrap();

    // Insert a test with 3 conditions in flat slots + 1 empty slot
    sqlx::query(
        "INSERT INTO tests (id, tenant_id, name, severity, filter,
         element_1, input_1, selement_1, condition_1, sinput_1,
         element_2, input_2, selement_2, condition_2, sinput_2,
         element_3, input_3, selement_3, condition_3, sinput_3,
         element_4, input_4, selement_4, condition_4, sinput_4,
         element_5, input_5, selement_5, condition_5, sinput_5)
         VALUES (1, 'default', 'SSH root login disabled', 'High', 'all',
         'FILE', '/etc/ssh/sshd_config', 'CONTENT', 'CONTAINS', 'PermitRootLogin no',
         'FILE', '/etc/ssh/sshd_config', 'EXISTS', NULL, NULL,
         'OS', NULL, 'CONTENT', 'CONTAINS', 'Ubuntu',
         NULL, NULL, NULL, NULL, NULL,
         NULL, NULL, NULL, NULL, NULL)"
    ).execute(pool).await.unwrap();

    // Insert a second test with only 1 condition
    sqlx::query(
        "INSERT INTO tests (id, tenant_id, name, severity, filter,
         element_1, input_1, selement_1, condition_1, sinput_1)
         VALUES (2, 'default', 'SSH service running', 'Medium', 'all',
         'PROCESS', 'sshd', 'EXISTS', NULL, NULL)"
    ).execute(pool).await.unwrap();

    // Existing applicability condition for test 1 (already in test_conditions)
    sqlx::query(
        "INSERT INTO test_conditions (tenant_id, test_id, type, element, input, selement, condition, sinput)
         VALUES ('default', 1, 'applicability', 'OS', '', 'CONTENT', 'CONTAINS', 'Linux')"
    ).execute(pool).await.unwrap();
}

#[tokio::test]
async fn migration_v4_migrates_flat_conditions() {
    let pool = in_memory_pool().await;
    setup_old_v3_schema(&pool).await;

    // Run only the migrations (skip initialize_database — old schema already set up)
    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    // Version should now be 4
    let version: i64 = sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(version, 4);

    // Test 1 had 3 non-null condition slots → 3 rows with type='condition'
    let cond_count_t1: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM test_conditions WHERE test_id = 1 AND type = 'condition'"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(cond_count_t1, 3, "test 1 should have 3 migrated conditions");

    // Test 2 had 1 non-null condition slot → 1 row
    let cond_count_t2: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM test_conditions WHERE test_id = 2 AND type = 'condition'"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(cond_count_t2, 1, "test 2 should have 1 migrated condition");

    // The pre-existing applicability condition must survive
    let app_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM test_conditions WHERE type = 'applicability'"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(app_count, 1, "pre-existing applicability condition must be preserved");
}

#[tokio::test]
async fn migration_v4_correct_condition_values() {
    let pool = in_memory_pool().await;
    setup_old_v3_schema(&pool).await;

    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    // Check the first condition of test 1 (element_1 = FILE)
    let row = sqlx::query(
        "SELECT element, input, selement, condition, sinput
         FROM test_conditions WHERE test_id = 1 AND type = 'condition' ORDER BY id ASC LIMIT 1"
    ).fetch_one(&pool).await.unwrap();

    let element: String  = row.get("element");
    let input: String    = row.get("input");
    let selement: String = row.get("selement");
    let condition: Option<String> = row.get("condition");
    let sinput: Option<String>    = row.get("sinput");

    assert_eq!(element,   "FILE");
    assert_eq!(input,     "/etc/ssh/sshd_config");
    assert_eq!(selement,  "CONTENT");
    assert_eq!(condition.as_deref(), Some("CONTAINS"));
    assert_eq!(sinput.as_deref(),    Some("PermitRootLogin no"));
}

#[tokio::test]
async fn migration_v4_removes_flat_columns() {
    let pool = in_memory_pool().await;
    setup_old_v3_schema(&pool).await;

    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    let has_flat: bool = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM pragma_table_info('tests') WHERE name = 'element_1'"
    ).fetch_one(&pool).await.unwrap() > 0;

    assert!(!has_flat, "after migration, tests table must not have element_1 column");
}

#[tokio::test]
async fn migration_v4_preserves_test_metadata() {
    let pool = in_memory_pool().await;
    setup_old_v3_schema(&pool).await;

    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    // Both tests should still be in the tests table
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tests")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 2);

    let name: String = sqlx::query_scalar("SELECT name FROM tests WHERE id = 1")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(name, "SSH root login disabled");
}

#[tokio::test]
async fn migration_v4_skips_none_slots() {
    let pool = in_memory_pool().await;
    setup_old_v3_schema(&pool).await;

    scmserver::schema::run_migrations(&pool).await.expect("migrations");

    // Test 1 had slots 4 and 5 as NULL — those must NOT appear in test_conditions
    // Total type='condition' rows should be 4 (3 from test1 + 1 from test2)
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM test_conditions WHERE type = 'condition'"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(total, 4);
}

// ============================================================
// IDEMPOTENCE — running migrations twice is safe
// ============================================================

#[tokio::test]
async fn migration_is_idempotent() {
    let pool = in_memory_pool().await;
    setup_old_v3_schema(&pool).await;

    scmserver::schema::run_migrations(&pool).await.expect("first run");
    // Second run should be a no-op (version already 4)
    scmserver::schema::run_migrations(&pool).await.expect("second run");

    let version: i64 = sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(version, 4);

    // No duplicate conditions created
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM test_conditions WHERE type = 'condition'"
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(total, 4);
}
