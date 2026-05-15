// =============================================================================
// schema.rs — database initialisation and incremental migrations
//
// initialize_database creates all tables and seeds default data on a fresh
// install. run_migrations applies version-gated ALTER TABLE / data fixes to
// existing databases without re-running the full schema.
//
// Every CREATE TABLE and INSERT OR IGNORE is wrapped with db_compat::adapt_sql()
// so that the same source compiles and runs on SQLite, MySQL, and PostgreSQL.
// =============================================================================
use sqlx::AnyPool;
use sqlx::Row;
use tracing::info;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine as _};
use crate::db_compat;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: initialize_database
// Creates all tables, indexes, triggers, and seed data for a fresh install.
// Stamps schema_info.version = 9 so run_migrations skips all steps.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn initialize_database(pool: &AnyPool) -> Result<(), sqlx::Error> {

    info!("Init Database......");

    // Tenants Table (no AUTOINCREMENT — VARCHAR(191) PK so MySQL can index it)
    // status and plan are EE/SaaS fields present in base schema so all editions
    // share an identical table structure.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenants (
            id         VARCHAR(191) PRIMARY KEY,
            name       VARCHAR(191) NOT NULL UNIQUE,
            status     TEXT    NOT NULL DEFAULT 'active',
            plan       TEXT    NOT NULL DEFAULT 'free',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(pool)
    .await?;

    // Tenant Keys Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS tenant_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS settings (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            skey VARCHAR(191) NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            PRIMARY KEY (tenant_id, skey),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Notify Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS notify (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            ntype TEXT,
            nts TEXT,
            owner_id INTEGER,
            message TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // Users Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            username VARCHAR(191) NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            email TEXT,
            role TEXT,
            email_verified INTEGER NOT NULL DEFAULT 1,
            UNIQUE(username, tenant_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // Systems Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name TEXT,
            ver TEXT,
            key TEXT,
            ip TEXT,
            os TEXT,
            arch TEXT,
            status VARCHAR(32),
            groups TEXT,
            auth_public_key TEXT,
            auth_signature TEXT,
            trust_challenge TEXT,
            trust_proof TEXT,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            compliance_score REAL DEFAULT -1.0,
            tests_passed INTEGER DEFAULT 0,
            tests_failed INTEGER DEFAULT 0,
            total_tests INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // System Groups Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS system_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name VARCHAR(191) NOT NULL,
            description TEXT,
            UNIQUE(name, tenant_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // Systems-in-Groups join table (no AUTOINCREMENT — composite PK)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems_in_groups (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            system_id INTEGER,
            group_id INTEGER,
            PRIMARY KEY (tenant_id, system_id, group_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES system_groups (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Tests Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name TEXT NOT NULL,
            description TEXT,
            rational TEXT,
            remediation TEXT,
            severity TEXT,
            app_filter TEXT DEFAULT 'all',
            filter TEXT DEFAULT 'all',
            compliance_score REAL DEFAULT -1.0,
            systems_passed INTEGER DEFAULT 0,
            systems_failed INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // Test Conditions Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS test_conditions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            test_id INTEGER NOT NULL,
            name TEXT,
            description TEXT,
            ctype TEXT NOT NULL,
            element TEXT NOT NULL,
            input TEXT NOT NULL,
            selement TEXT NOT NULL,
            comparison TEXT,
            sinput TEXT,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // Policies Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            name TEXT NOT NULL,
            description TEXT,
            version TEXT,
            compliance_score REAL DEFAULT -1.0,
            systems_passed INTEGER DEFAULT 0,
            systems_failed INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // Policy Schedules Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS policy_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            policy_id INTEGER NOT NULL,
            schedule_type VARCHAR(32) NOT NULL DEFAULT 'scan',
            enabled BOOLEAN NOT NULL DEFAULT 1,
            frequency TEXT NOT NULL,
            cron_expression TEXT,
            next_run DATETIME NOT NULL,
            last_run DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(policy_id, schedule_type),
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // Tests-in-Policy join table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tests_in_policy (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            policy_id INTEGER,
            test_id INTEGER,
            PRIMARY KEY (tenant_id, policy_id, test_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Systems-in-Policy join table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems_in_policy (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            policy_id INTEGER,
            group_id INTEGER,
            PRIMARY KEY (tenant_id, policy_id, group_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES system_groups (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Commands table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS commands (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            system_id INTEGER,
            test_id INTEGER,
            PRIMARY KEY (tenant_id, system_id, test_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Results table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS results (
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            system_id INTEGER,
            test_id INTEGER,
            result TEXT,
            last_updated TEXT,
            PRIMARY KEY (tenant_id, system_id, test_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Reports table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            submission_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            policy_name TEXT NOT NULL,
            policy_version TEXT,
            policy_description TEXT,
            submitter_name TEXT,
            tests_metadata TEXT NOT NULL,
            report_results TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // System Reports table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS system_reports (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id        VARCHAR(191) NOT NULL DEFAULT 'default',
            submission_date  DATETIME DEFAULT CURRENT_TIMESTAMP,
            system_id        INTEGER NOT NULL,
            system_name      TEXT    NOT NULL,
            submitter_name   TEXT,
            report_data      TEXT    NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_system_reports_tenant_date
         ON system_reports (tenant_id, submission_date)",
    )
    .execute(pool)
    .await?;

    // Compliance History table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS compliance_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
            check_date DATE DEFAULT CURRENT_TIMESTAMP,
            systems_score REAL DEFAULT 0.0,
            policies_score REAL DEFAULT 0.0,
            total_systems INTEGER,
            failed_systems INTEGER,
            total_policies INTEGER,
            failed_policies INTEGER,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    ))
    .execute(pool)
    .await?;

    // Elements Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS elements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(191) NOT NULL UNIQUE,
            description TEXT
        )",
    ))
    .execute(pool)
    .await?;

    // Selements Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS selements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(191) NOT NULL UNIQUE,
            description TEXT
        )",
    ))
    .execute(pool)
    .await?;

    // Conditions Table
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS conditions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(191) NOT NULL UNIQUE,
            description TEXT
        )",
    ))
    .execute(pool)
    .await?;

    // ── INDEXES ──────────────────────────────────────────────────────────────
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_next_run ON policy_schedules (enabled, next_run)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_results_tenant_test ON results (tenant_id, test_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_test_conditions_tenant_test ON test_conditions (tenant_id, test_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_systems_tenant_status ON systems (tenant_id, status)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_systems_tenant_score ON systems (tenant_id, compliance_score)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sig_tenant_group ON systems_in_groups (tenant_id, group_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_sip_tenant_group ON systems_in_policy (tenant_id, group_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tip_tenant_test ON tests_in_policy (tenant_id, test_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_compliance_history_tenant_date ON compliance_history (tenant_id, check_date)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_notify_tenant_owner ON notify (tenant_id, owner_id)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant_active ON tenant_keys (tenant_id, is_active)")
        .execute(pool).await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_reports_tenant_date ON reports (tenant_id, submission_date)")
        .execute(pool).await?;

    // Email Verification Tokens (used by SaaS registration; harmless in CE/EE)
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS email_verifications (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            tenant_id  VARCHAR(191) NOT NULL,
            token      VARCHAR(191) NOT NULL UNIQUE,
            expires_at TEXT    NOT NULL,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    ))
    .execute(pool).await?;

    // Password Reset Tokens (used by SaaS; harmless in CE/EE)
    sqlx::query(&db_compat::adapt_sql(
        "CREATE TABLE IF NOT EXISTS password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token      VARCHAR(191) NOT NULL UNIQUE,
            expires_at TEXT    NOT NULL,
            used       INTEGER NOT NULL DEFAULT 0,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )",
    ))
    .execute(pool).await?;

    // Plan Limits (used by SaaS to enforce per-plan resource caps; harmless in CE/EE)
    // max_count = 0 means unlimited
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS plan_limits (
            plan      VARCHAR(191) NOT NULL,
            resource  VARCHAR(191) NOT NULL,
            max_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (plan, resource)
        )",
    )
    .execute(pool).await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_email_verif_token ON email_verifications (token)")
        .execute(pool).await.ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets (token)")
        .execute(pool).await.ok();

    // ── SEED DATA ─────────────────────────────────────────────────────────────

    // Default tenant
    sqlx::query(&db_compat::adapt_sql(
        "INSERT OR IGNORE INTO tenants (id, name) VALUES ('default', 'Default Tenant')"
    ))
    .execute(pool)
    .await?;

    // NOTE: the admin user is NOT seeded here — created by /install with the
    // administrator's chosen password so no default credentials exist on disk.

    // Default settings
    sqlx::query(&db_compat::adapt_sql(
        "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description) VALUES
        ('default', 'offline_threshold', '3600', 'Seconds without activity before system is marked offline'),
        ('default', 'compliance_sat', '80', 'Minimum compliance percentage for SAT status'),
        ('default', 'compliance_marginal', '60', 'Minimum compliance percentage for MARGINAL status'),
        ('default', 'smtp_host', '', 'SMTP relay hostname'),
        ('default', 'smtp_port', '587', 'SMTP relay port'),
        ('default', 'smtp_username', '', 'SMTP relay username'),
        ('default', 'smtp_password', '', 'SMTP relay password'),
        ('default', 'smtp_from', '', 'From address for outgoing emails'),
        ('default', 'smtp_tls', 'starttls', 'TLS mode: starttls, tls, or none'),
        ('default', 'app_url', '', 'Public URL of this installation (used in email links)')"
    ))
    .execute(pool)
    .await?;

    // Elements
    for name in &[
        "AGENT", "OS", "HOSTNAME", "IP", "DOMAIN", "ARCHITECTURE", "USER", "GROUP",
        "FILE", "DIRECTORY", "PROCESS", "PACKAGE", "REGISTRY", "PORT", "CMD",
    ] {
        sqlx::query(&db_compat::adapt_sql(
            "INSERT OR IGNORE INTO elements (name) VALUES (?)"
        ))
        .bind(name)
        .execute(pool)
        .await?;
    }

    // Selements
    for name in &[
        "EXISTS", "NOT EXISTS", "CONTENT", "VERSION", "PERMISSION",
        "OWNER", "GROUP", "SHA1", "SHA2", "OUTPUT",
    ] {
        sqlx::query(&db_compat::adapt_sql(
            "INSERT OR IGNORE INTO selements (name) VALUES (?)"
        ))
        .bind(name)
        .execute(pool)
        .await?;
    }

    // Conditions
    for name in &[
        "CONTAINS", "NOT CONTAINS", "EQUALS", "NOT EQUALS",
        "MORE THAN", "LESS THAN", "REGEX",
    ] {
        sqlx::query(&db_compat::adapt_sql(
            "INSERT OR IGNORE INTO conditions (name) VALUES (?)"
        ))
        .bind(name)
        .execute(pool)
        .await?;
    }

    // Generate Ed25519 keypair for the default tenant if it doesn't exist yet
    let existing_key = sqlx::query("SELECT id FROM tenant_keys WHERE tenant_id = 'default' LIMIT 1")
        .fetch_optional(pool)
        .await?;

    if existing_key.is_none() {
        info!("Generating new Ed25519 pair for default tenant...");
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let public_base64  = general_purpose::STANDARD.encode(verifying_key.as_bytes());
        let private_base64 = general_purpose::STANDARD.encode(signing_key.to_bytes());

        sqlx::query(
            "INSERT INTO tenant_keys (tenant_id, public_key, private_key) VALUES ('default', ?, ?)"
        )
        .bind(public_base64)
        .bind(private_base64)
        .execute(pool)
        .await?;

        info!("Default keys generated and secured in database.");
    }

    // schema_info table (no AUTOINCREMENT — single-row sentinel)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_info (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Bootstrap admin role protection trigger (SQLite only; application-level
    // enforcement covers MySQL and PostgreSQL where this trigger is skipped).
    if let Some(trigger_sql) = db_compat::admin_role_trigger_sql() {
        sqlx::query(trigger_sql).execute(pool).await?;
    }

    sqlx::query(&db_compat::adapt_sql(
        "INSERT OR IGNORE INTO schema_info (id, version) VALUES (1, 11)"
    ))
    .execute(pool)
    .await?;

    info!("Schema version stamped at 11 (fresh install).");

    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: seed_plan_limits
// Inserts the default per-plan resource caps into `plan_limits`.
// Uses INSERT OR IGNORE so it is safe to call on every startup (idempotent).
// Called by SaaS on every startup; CE/EE deliberately do NOT call this so
// the table stays empty and the dashboard hides the limit counters.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn seed_plan_limits(pool: &AnyPool) -> Result<(), sqlx::Error> {
    for (plan, resource, max_count) in &[
        ("free",       "systems",   5i64),
        ("free",       "groups",    3),
        ("free",       "policies",  3),
        ("free",       "reports",   10),
        ("starter",    "systems",   25),
        ("starter",    "groups",    10),
        ("starter",    "policies",  10),
        ("starter",    "reports",   100),
        ("pro",        "systems",   100),
        ("pro",        "groups",    50),
        ("pro",        "policies",  50),
        ("pro",        "reports",   500),
        ("enterprise", "systems",   0),
        ("enterprise", "groups",    0),
        ("enterprise", "policies",  0),
        ("enterprise", "reports",   0),
    ] {
        let _ = sqlx::query(&db_compat::adapt_sql(
            "INSERT OR IGNORE INTO plan_limits (plan, resource, max_count) VALUES (?, ?, ?)",
        ))
        .bind(plan)
        .bind(resource)
        .bind(*max_count)
        .execute(pool)
        .await;
    }
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: run_migrations
// Applies incremental schema migrations (v0→v9) to existing installations.
// Each step is guarded by a version check so it runs exactly once.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn run_migrations(pool: &AnyPool) -> Result<(), sqlx::Error> {
    // schema_info sentinel table (no AUTOINCREMENT)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_info (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Seed with version 0 if the table is empty
    sqlx::query(&db_compat::adapt_sql(
        "INSERT OR IGNORE INTO schema_info (id, version) VALUES (1, 0)"
    ))
    .execute(pool)
    .await?;

    // ── Pre-migration: rename settings.key → settings.skey ────────────────────
    // `key` is a MySQL/MariaDB reserved word.  The rename was applied to the
    // CREATE TABLE in initialize_database (so fresh installs are fine), but
    // existing SQLite/PostgreSQL databases still carry the old column name.
    // This must run BEFORE any version-gated INSERT into settings so that
    // "no such column: skey" errors can never occur at any schema version.
    // On MySQL the old column never existed, so column_exists returns false
    // and the block is skipped.
    if db_compat::column_exists(pool, "settings", "key").await {
        let _ = sqlx::query(
            "ALTER TABLE settings RENAME COLUMN \"key\" TO skey"
        ).execute(pool).await;
        info!("Pre-migration: renamed settings.key → settings.skey");
    }
    // ──────────────────────────────────────────────────────────────────────────

    let version: i64 = sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(pool)
        .await?;

    info!("Current schema version: {}", version);

    // v0 → v1: bump only; base schema already applied by initialize_database
    if version < 1 {
        sqlx::query("UPDATE schema_info SET version = 1")
            .execute(pool)
            .await?;
        info!("Schema version set to 1.");
    }

    // v1 → v2 (0.1.5 → 0.1.6): add app_filter to tests
    if version < 2 {
        info!("Running schema migration v1 → v2...");

        // Ignore error if column already exists (fresh install)
        let _ = sqlx::query("ALTER TABLE tests ADD COLUMN app_filter TEXT DEFAULT 'all'")
            .execute(pool)
            .await;

        sqlx::query("UPDATE schema_info SET version = 2")
            .execute(pool)
            .await?;

        info!("Schema migration v1 → v2 complete.");
    }

    // v2 → v3: rebuild policy_schedules with schedule_type column
    if version < 3 {
        info!("Running schema migration v2 → v3...");

        let mut migration_tx = pool.begin().await?;

        sqlx::query("DROP TABLE IF EXISTS policy_schedules_old")
            .execute(&mut *migration_tx).await?;
        sqlx::query(&db_compat::rename_table_sql("policy_schedules", "policy_schedules_old"))
            .execute(&mut *migration_tx).await?;

        sqlx::query(&db_compat::adapt_sql(
            "CREATE TABLE policy_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id VARCHAR(191) NOT NULL DEFAULT 'default',
                policy_id INTEGER NOT NULL,
                schedule_type VARCHAR(32) NOT NULL DEFAULT 'scan',
                enabled BOOLEAN NOT NULL DEFAULT 1,
                frequency TEXT NOT NULL,
                cron_expression TEXT,
                next_run DATETIME NOT NULL,
                last_run DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(policy_id, schedule_type),
                FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )"
        ))
        .execute(&mut *migration_tx).await?;

        sqlx::query(
            "INSERT INTO policy_schedules
                (id, tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run, last_run, created_at)
             SELECT id, tenant_id, policy_id, 'scan', enabled, frequency, cron_expression, next_run, last_run, created_at
             FROM policy_schedules_old"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query("DROP TABLE policy_schedules_old")
            .execute(&mut *migration_tx).await?;
        sqlx::query("UPDATE schema_info SET version = 3")
            .execute(&mut *migration_tx).await?;

        migration_tx.commit().await?;
        info!("Schema migration v2 → v3 complete.");
    }

    // v3 → v4: move flat condition columns into test_conditions table
    if version < 4 {
        info!("Running schema migration v3 → v4...");

        let mut migration_tx = pool.begin().await?;

        // Use db_compat::column_exists so this works on all backends
        // (replaces the SQLite-only pragma_table_info check).
        // Read-only schema check — safe to run against the pool, not the tx.
        let has_flat_columns = db_compat::column_exists(pool, "tests", "element_1").await;

        if has_flat_columns {
            info!("Migrating flat condition columns into test_conditions...");

            let test_rows = sqlx::query(
                "SELECT id, tenant_id,
                 element_1, input_1, selement_1, condition_1, sinput_1,
                 element_2, input_2, selement_2, condition_2, sinput_2,
                 element_3, input_3, selement_3, condition_3, sinput_3,
                 element_4, input_4, selement_4, condition_4, sinput_4,
                 element_5, input_5, selement_5, condition_5, sinput_5
                 FROM tests"
            )
            .fetch_all(&mut *migration_tx)
            .await?;

            for row in &test_rows {
                let test_id: i64    = row.get("id");
                let tenant_id: String = row.get("tenant_id");

                for (ecol, icol, scol, ccol, sicol) in [
                    ("element_1","input_1","selement_1","condition_1","sinput_1"),
                    ("element_2","input_2","selement_2","condition_2","sinput_2"),
                    ("element_3","input_3","selement_3","condition_3","sinput_3"),
                    ("element_4","input_4","selement_4","condition_4","sinput_4"),
                    ("element_5","input_5","selement_5","condition_5","sinput_5"),
                ] {
                    let element: Option<String> = row.try_get(ecol).ok().flatten();
                    let element = match element {
                        Some(e) if !e.is_empty() && e != "None" => e,
                        _ => continue,
                    };
                    let input: String = row.try_get(icol).ok().flatten().unwrap_or_default();
                    let selement: String = row.try_get(scol).ok().flatten()
                        .filter(|s: &String| !s.is_empty() && s != "None")
                        .unwrap_or_else(|| "None".to_string());
                    let condition: Option<String> = row.try_get(ccol).ok().flatten()
                        .filter(|s: &String| !s.is_empty() && s != "None");
                    let sinput: Option<String> = row.try_get(sicol).ok().flatten()
                        .filter(|s: &String| !s.is_empty());

                    sqlx::query(
                        "INSERT INTO test_conditions
                             (tenant_id, test_id, ctype, element, input, selement, comparison, sinput)
                         VALUES (?, ?, 'condition', ?, ?, ?, ?, ?)"
                    )
                    .bind(&tenant_id)
                    .bind(test_id)
                    .bind(&element)
                    .bind(&input)
                    .bind(&selement)
                    .bind(condition)
                    .bind(sinput)
                    .execute(&mut *migration_tx)
                    .await?;
                }
            }

            for sql in [
                "ALTER TABLE tests DROP COLUMN element_1",
                "ALTER TABLE tests DROP COLUMN input_1",
                "ALTER TABLE tests DROP COLUMN selement_1",
                "ALTER TABLE tests DROP COLUMN condition_1",
                "ALTER TABLE tests DROP COLUMN sinput_1",
                "ALTER TABLE tests DROP COLUMN element_2",
                "ALTER TABLE tests DROP COLUMN input_2",
                "ALTER TABLE tests DROP COLUMN selement_2",
                "ALTER TABLE tests DROP COLUMN condition_2",
                "ALTER TABLE tests DROP COLUMN sinput_2",
                "ALTER TABLE tests DROP COLUMN element_3",
                "ALTER TABLE tests DROP COLUMN input_3",
                "ALTER TABLE tests DROP COLUMN selement_3",
                "ALTER TABLE tests DROP COLUMN condition_3",
                "ALTER TABLE tests DROP COLUMN sinput_3",
                "ALTER TABLE tests DROP COLUMN element_4",
                "ALTER TABLE tests DROP COLUMN input_4",
                "ALTER TABLE tests DROP COLUMN selement_4",
                "ALTER TABLE tests DROP COLUMN condition_4",
                "ALTER TABLE tests DROP COLUMN sinput_4",
                "ALTER TABLE tests DROP COLUMN element_5",
                "ALTER TABLE tests DROP COLUMN input_5",
                "ALTER TABLE tests DROP COLUMN selement_5",
                "ALTER TABLE tests DROP COLUMN condition_5",
                "ALTER TABLE tests DROP COLUMN sinput_5",
            ] {
                // Ignore error — column may have been dropped in a previous
                // partial run (the migration is designed to be re-entrant).
                let _ = sqlx::query(sql).execute(&mut *migration_tx).await;
            }
        }

        sqlx::query("UPDATE schema_info SET version = 4")
            .execute(&mut *migration_tx).await?;
        migration_tx.commit().await?;
        info!("Schema migration v3 → v4 complete.");
    }

    // v4 → v5: fix compliance_score DEFAULT 0.0 → -1.0 for unscanned rows
    if version < 5 {
        info!("Running schema migration v4 → v5 (fix unscanned compliance_score 0.0 → -1.0)...");

        let mut migration_tx = pool.begin().await?;

        sqlx::query(
            "UPDATE systems SET compliance_score = -1.0
             WHERE compliance_score = 0.0
               AND total_tests = 0
               AND NOT EXISTS (
                   SELECT 1 FROM results
                   WHERE results.system_id = systems.id
                     AND results.tenant_id = systems.tenant_id
               )"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query(
            "UPDATE tests SET compliance_score = -1.0
             WHERE compliance_score = 0.0
               AND systems_passed = 0
               AND systems_failed = 0
               AND NOT EXISTS (
                   SELECT 1 FROM results
                   WHERE results.test_id  = tests.id
                     AND results.tenant_id = tests.tenant_id
               )"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query(
            "UPDATE policies SET compliance_score = -1.0
             WHERE compliance_score = 0.0
               AND systems_passed = 0
               AND systems_failed = 0
               AND NOT EXISTS (
                   SELECT 1 FROM results r
                   JOIN tests_in_policy tip ON tip.test_id  = r.test_id
                     AND tip.tenant_id = r.tenant_id
                   WHERE tip.policy_id  = policies.id
                     AND r.tenant_id    = policies.tenant_id
               )"
        )
        .execute(&mut *migration_tx).await?;

        sqlx::query("UPDATE schema_info SET version = 5")
            .execute(&mut *migration_tx).await?;
        migration_tx.commit().await?;
        info!("Schema migration v4 → v5 complete.");
    }

    // v5 → v6: add email_verified to users (default 1 — CE/EE users unaffected)
    if version < 6 {
        info!("Running schema migration v5 → v6 (email_verified)...");

        let _ = sqlx::query(
            "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1"
        )
        .execute(pool)
        .await;

        sqlx::query("UPDATE schema_info SET version = 6")
            .execute(pool).await?;
        info!("Schema migration v5 → v6 complete.");
    }

    // v6 → v7: system_reports table + all composite indexes
    if version < 7 {
        info!("Running schema migration v6 → v7 (system_reports + indexes)...");

        sqlx::query(&db_compat::adapt_sql(
            "CREATE TABLE IF NOT EXISTS system_reports (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id        VARCHAR(191) NOT NULL DEFAULT 'default',
                submission_date  DATETIME DEFAULT CURRENT_TIMESTAMP,
                system_id        INTEGER NOT NULL,
                system_name      TEXT    NOT NULL,
                submitter_name   TEXT,
                report_data      TEXT    NOT NULL,
                FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
            )"
        ))
        .execute(pool).await?;

        for idx in &[
            "CREATE INDEX IF NOT EXISTS idx_next_run ON policy_schedules (enabled, next_run)",
            "CREATE INDEX IF NOT EXISTS idx_results_tenant_test ON results (tenant_id, test_id)",
            "CREATE INDEX IF NOT EXISTS idx_test_conditions_tenant_test ON test_conditions (tenant_id, test_id)",
            "CREATE INDEX IF NOT EXISTS idx_systems_tenant_status ON systems (tenant_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_systems_tenant_score ON systems (tenant_id, compliance_score)",
            "CREATE INDEX IF NOT EXISTS idx_sig_tenant_group ON systems_in_groups (tenant_id, group_id)",
            "CREATE INDEX IF NOT EXISTS idx_sip_tenant_group ON systems_in_policy (tenant_id, group_id)",
            "CREATE INDEX IF NOT EXISTS idx_tip_tenant_test ON tests_in_policy (tenant_id, test_id)",
            "CREATE INDEX IF NOT EXISTS idx_compliance_history_tenant_date ON compliance_history (tenant_id, check_date)",
            "CREATE INDEX IF NOT EXISTS idx_notify_tenant_owner ON notify (tenant_id, owner_id)",
            "CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant_active ON tenant_keys (tenant_id, is_active)",
            "CREATE INDEX IF NOT EXISTS idx_reports_tenant_date ON reports (tenant_id, submission_date)",
            "CREATE INDEX IF NOT EXISTS idx_system_reports_tenant_date ON system_reports (tenant_id, submission_date)",
        ] {
            sqlx::query(idx).execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 7")
            .execute(pool).await?;
        info!("Schema migration v6 → v7 complete.");
    }

    // v7 → v8: seed SMTP settings for all existing tenants
    if version < 8 {
        info!("Running schema migration v7 → v8 (SMTP settings)...");

        for sql in &[
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_host', '', 'SMTP relay hostname' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_port', '587', 'SMTP relay port' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_username', '', 'SMTP relay username' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_password', '', 'SMTP relay password' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_from', '', 'From address for outgoing emails' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'smtp_tls', 'starttls', 'TLS mode: starttls, tls, or none' FROM tenants t",
            "INSERT OR IGNORE INTO settings (tenant_id, skey, value, description)
             SELECT t.id, 'app_url', '', 'Public URL of this installation (used in email links)' FROM tenants t",
        ] {
            sqlx::query(&db_compat::adapt_sql(sql)).execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 8")
            .execute(pool).await?;
        info!("Schema migration v7 → v8 complete.");
    }

    // v8 → v9: bootstrap admin role protection trigger (SQLite only)
    if version < 9 {
        info!("Running schema migration v8 → v9 (protect bootstrap admin role)...");

        if let Some(trigger_sql) = db_compat::admin_role_trigger_sql() {
            sqlx::query(trigger_sql).execute(pool).await?;
        }

        sqlx::query("UPDATE schema_info SET version = 9")
            .execute(pool).await?;
        info!("Schema migration v8 → v9 complete.");
    }

    // v9 → v10: backfill columns and tables that belong in the base schema but
    // were missing from initialize_database on installs stamped at v9.
    //   • users.email_verified  — added for SaaS registration/login
    //   • tenants.status        — added for EE/SaaS tenant management
    //   • tenants.plan          — added for EE/SaaS plan enforcement
    //   • email_verifications   — SaaS registration tokens
    //   • password_resets       — SaaS password reset tokens
    //   • plan_limits           — SaaS per-plan resource caps
    if version < 10 {
        info!("Running schema migration v9 → v10 (unified base schema backfill)...");

        if !db_compat::column_exists(pool, "users", "email_verified").await {
            let _ = sqlx::query(
                "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1"
            ).execute(pool).await;
        }

        if !db_compat::column_exists(pool, "tenants", "status").await {
            let _ = sqlx::query(
                "ALTER TABLE tenants ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
            ).execute(pool).await;
        }

        if !db_compat::column_exists(pool, "tenants", "plan").await {
            let _ = sqlx::query(
                "ALTER TABLE tenants ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'"
            ).execute(pool).await;
        }

        sqlx::query(&db_compat::adapt_sql(
            "CREATE TABLE IF NOT EXISTS email_verifications (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                tenant_id  VARCHAR(191) NOT NULL,
                token      VARCHAR(191) NOT NULL UNIQUE,
                expires_at TEXT    NOT NULL,
                created_at TEXT    NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )"
        )).execute(pool).await?;

        sqlx::query(&db_compat::adapt_sql(
            "CREATE TABLE IF NOT EXISTS password_resets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                token      VARCHAR(191) NOT NULL UNIQUE,
                expires_at TEXT    NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0,
                created_at TEXT    NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )"
        )).execute(pool).await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS plan_limits (
                plan      VARCHAR(191) NOT NULL,
                resource  VARCHAR(191) NOT NULL,
                max_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (plan, resource)
            )"
        ).execute(pool).await?;

        sqlx::query("UPDATE schema_info SET version = 10")
            .execute(pool).await?;
        info!("Schema migration v9 → v10 complete.");
    }

    // v10 → v11: rename MySQL/MariaDB reserved-word columns.
    //   test_conditions.type      → ctype      (TYPE is reserved in some MariaDB versions)
    //   test_conditions.condition → comparison  (CONDITION is reserved in MySQL/MariaDB)
    //   notify.type               → ntype
    //   notify.timestamp          → nts         (TIMESTAMP is a MySQL/MariaDB type keyword)
    // MySQL installs never had these old column names (the schema creation failed before
    // this fix), so on MySQL the column_exists checks return false and nothing is renamed.
    if version < 11 {
        info!("Running schema migration v10 → v11 (rename reserved-word columns)...");

        // RENAME COLUMN is supported on SQLite ≥ 3.25 and PostgreSQL ≥ 9.
        // On MySQL we skip — the tables were never created with the old names.
        match crate::get_db_backend() {
            crate::DbBackend::Sqlite | crate::DbBackend::Postgres => {
                if db_compat::column_exists(pool, "test_conditions", "type").await {
                    let _ = sqlx::query(
                        "ALTER TABLE test_conditions RENAME COLUMN \"type\" TO ctype",
                    ).execute(pool).await;
                }
                if db_compat::column_exists(pool, "test_conditions", "condition").await {
                    let _ = sqlx::query(
                        "ALTER TABLE test_conditions RENAME COLUMN \"condition\" TO comparison",
                    ).execute(pool).await;
                }
                if db_compat::column_exists(pool, "notify", "type").await {
                    let _ = sqlx::query(
                        "ALTER TABLE notify RENAME COLUMN \"type\" TO ntype",
                    ).execute(pool).await;
                }
                if db_compat::column_exists(pool, "notify", "timestamp").await {
                    let _ = sqlx::query(
                        "ALTER TABLE notify RENAME COLUMN \"timestamp\" TO nts",
                    ).execute(pool).await;
                }
            }
            crate::DbBackend::Mysql => {
                // Tables were never created with the old names on MySQL — nothing to do.
            }
        }

        sqlx::query("UPDATE schema_info SET version = 11")
            .execute(pool).await?;
        info!("Schema migration v10 → v11 complete.");
    }

    Ok(())
}
