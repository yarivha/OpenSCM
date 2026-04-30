// src/schema.rs
use sqlx::SqlitePool;
use sqlx::Row;
use tracing::info;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine as _};

/// Initialize the database schema
pub async fn initialize_database(pool: &SqlitePool) -> Result<(), sqlx::Error> {

    info!("Init Database......");


    // schema_info
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_info (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Seed schema version for fresh installs — skips all migrations
    sqlx::query("INSERT OR IGNORE INTO schema_info (id, version) VALUES (1, 5)")
        .execute(pool)
        .await?;


    //  Tenants Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY, 
            name TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(pool)
    .await?;

    // 2. FIX: The Tenant Keys Table (Created as a separate table)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS settings (
            tenant_id TEXT NOT NULL DEFAULT 'default',
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            PRIMARY KEY (tenant_id, key),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;


    // Create notify table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notify (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            type TEXT,
            timestamp TEXT,
            owner_id INTEGER,
            message TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    // Create users table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            username TEXT NOT NULL ,
            password TEXT NOT NULL,
            name TEXT,
            email TEXT,
            role TEXT,
            UNIQUE(username, tenant_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    
    // Create systems table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            name TEXT,
            ver TEXT,
            key TEXT,
            ip TEXT,
            os TEXT,
            arch TEXT,
            status TEXT,
            groups TEXT,
            auth_public_key TEXT,
            auth_signature TEXT,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            compliance_score REAL DEFAULT -1.0,
            tests_passed INTEGER DEFAULT 0,
            tests_failed INTEGER DEFAULT 0,
            total_tests INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
   

    // Create system_groups table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            name TEXT NOT NULL,
            description TEXT,
            UNIQUE(name, tenant_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    
    // Create systems_in_groups table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems_in_groups (
            tenant_id TEXT NOT NULL DEFAULT 'default',
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

    // Create tests table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
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
    )
    .execute(pool)
    .await?;
    
    
     // Create conditions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS test_conditions (
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
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;


    // Create policies table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS policies (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           tenant_id TEXT NOT NULL DEFAULT 'default',
           name TEXT NOT NULL,
           description TEXT,
           version TEXT,
           compliance_score REAL DEFAULT -1.0,
           systems_passed INTEGER DEFAULT 0,
           systems_failed INTEGER DEFAULT 0,
           FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;



     // Create policy schedules table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS policy_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            policy_id INTEGER NOT NULL,
            schedule_type TEXT NOT NULL DEFAULT 'scan',
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
    )
    .execute(pool)
    .await?;

    
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_next_run ON policy_schedules (enabled, next_run)",
    )
    .execute(pool)
    .await?;


    // Create tests_in_policy table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tests_in_policy (
            tenant_id TEXT NOT NULL DEFAULT 'default',
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


    // Create systems_in_policy table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems_in_policy (
            tenant_id TEXT NOT NULL DEFAULT 'default',
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


    // Create commands table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS commands (
            tenant_id TEXT NOT NULL DEFAULT 'default',
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


    // Create results table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS results (
            tenant_id TEXT NOT NULL DEFAULT 'default',
            system_id INTEGER,
            test_id INTEGER,
            result TEXT,
            last_updated TEXT,
            PRIMARY KEY (tenant_id,system_id, test_id),
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
            FOREIGN KEY (system_id) REFERENCES systems(id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE
        )",
   )
   .execute(pool)
   .await?;


    // Create reports table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            submission_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            policy_name TEXT NOT NULL,
            policy_version TEXT,
            policy_description TEXT,
            submitter_name TEXT,
            tests_metadata TEXT NOT NULL, 
            report_results TEXT NOT NULL,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;



    // Create compliance history table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS compliance_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            check_date DATE DEFAULT CURRENT_TIMESTAMP,
            systems_score REAL DEFAULT 0.0,
            policies_score REAL DEFAULT 0.0,
            total_systems INTEGER,
            failed_systems INTEGER,
            total_policies INTEGER,
            failed_policies INTEGER,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;



    // Create elements table
    sqlx::query(   
        "CREATE TABLE IF NOT EXISTS elements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
       )",
    )
    .execute(pool)
    .await?;


    // Create selements table
    sqlx::query(   
        "CREATE TABLE IF NOT EXISTS selements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
       )",
    )
    .execute(pool)
    .await?;

    
     // Create conditions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conditions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
       )",
    )
    .execute(pool)
    .await?;



// --------------------------------------
//  Insert default settings 
// --------------------------------------


    // Insert the default CE tenant
    sqlx::query("INSERT OR IGNORE INTO tenants (id, name) VALUES ('default', 'Default Tenant')")
        .execute(pool)
        .await?;

    // NOTE: the admin user is NOT seeded here.
    // It is created by the /install handler with the password chosen by the
    // administrator. This ensures no default credentials ever exist on disk.
   

    // Inset Default Settings

    sqlx::query(
        "INSERT OR IGNORE INTO settings (tenant_id, key, value, description) VALUES
        ('default', 'offline_threshold', '3600', 'Seconds without activity before system is marked offline'),
        ('default', 'compliance_sat', '80', 'Minimum compliance percentage for SAT status'),
        ('default', 'compliance_marginal', '60', 'Minimum compliance percentage for MARGINAL status')"
        )
        .execute(pool)
        .await?;



    // --------------------
    // Elements
    // --------------------
    let elements = vec![
        ("AGENT"),("OS"),("HOSTNAME"),("IP"),("DOMAIN"),("ARCHITECTURE"),("USER"),("GROUP"),("FILE"),
        ("DIRECTORY"),("PROCESS"),("PACKAGE"),("REGISTRY"),("PORT"),("CMD"),
    ];

    for name in elements {
        sqlx::query(
            "INSERT OR IGNORE INTO elements (name) VALUES (?)"
        )
        .bind(name)
        .execute(pool)
        .await?;
    }

   
    // --------------------
    // Selements
    // --------------------
    let selements = vec![
        ("EXISTS"), ("NOT EXISTS"),("CONTENT"),("VERSION"),("PERMISSION"),("OWNER"),("GROUP"),("SHA1"),("SHA2"),("OUTPUT"),
    ];

    for name in selements {
        sqlx::query(
            "INSERT OR IGNORE INTO selements (name) VALUES (?)"
        )
        .bind(name)
        .execute(pool)
        .await?;
    }

    
    // --------------------
    // Conditions
    // --------------------
    let conditions = vec![
        ("CONTAINS"),("NOT CONTAINS"),("EQUALS"),("NOT EQUALS"),("MORE THAN"),("LESS THAN"),("REGEX")
    ];

    for name in conditions {
        sqlx::query(
            "INSERT OR IGNORE INTO conditions (name) VALUES (?)"
        )
        .bind(name)
        .execute(pool)
        .await?;
    }



    // Create key pair is does not exits 
    let existing_key = sqlx::query("SELECT id FROM tenant_keys WHERE tenant_id = 'default' LIMIT 1")
        .fetch_optional(pool)
        .await?;

    if existing_key.is_none() {
        info!("Generating new Ed25519 pair for default tenant...");
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let public_base64 = general_purpose::STANDARD.encode(verifying_key.as_bytes());
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


    Ok(())
} 


// DB Migration 
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Create schema_info if it doesn't exist
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_info (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Seed with 0 if empty
    sqlx::query("INSERT OR IGNORE INTO schema_info (id, version) VALUES (1, 0)")
        .execute(pool)
        .await?;

    let version: i64 = sqlx::query_scalar("SELECT version FROM schema_info")
        .fetch_one(pool)
        .await?;

    info!("Current schema version: {}", version);

    // v0 → v1: bump only, base schema already applied by schema.rs
    if version < 1 {
        sqlx::query("UPDATE schema_info SET version = 1")
            .execute(pool)
            .await?;
        info!("Schema version set to 1.");
    }

    // v1 → v2 (0.1.5 → 0.1.6)
    if version < 2 {
        info!("Running schema migration v1 → v2...");

        // Ignore error if column already exists (new install)
        let _ = sqlx::query("ALTER TABLE tests ADD COLUMN app_filter TEXT DEFAULT 'all'")
            .execute(pool)
            .await;

        sqlx::query("UPDATE schema_info SET version = 2")
            .execute(pool)
            .await?;

        info!("Schema migration v1 → v2 complete.");
    }

    // v2 → v3
    if version < 3 {
        info!("Running schema migration v2 → v3...");

        let mut migration_tx = pool.begin().await?;

        // Clean up any leftover from previous failed attempt
        sqlx::query("DROP TABLE IF EXISTS policy_schedules_old")
            .execute(&mut *migration_tx).await?;

        sqlx::query("ALTER TABLE policy_schedules RENAME TO policy_schedules_old")
            .execute(&mut *migration_tx).await?;

        sqlx::query(r#"CREATE TABLE policy_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            policy_id INTEGER NOT NULL,
            schedule_type TEXT NOT NULL DEFAULT 'scan',
            enabled BOOLEAN NOT NULL DEFAULT 1,
            frequency TEXT NOT NULL,
            cron_expression TEXT,
            next_run DATETIME NOT NULL,
            last_run DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(policy_id, schedule_type),
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
        )"#)
        .execute(&mut *migration_tx).await?;

        sqlx::query(
            "INSERT INTO policy_schedules (id, tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run, last_run, created_at)
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

        // Check whether flat columns exist (absent on fresh installs)
        let has_flat_columns: bool = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pragma_table_info('tests') WHERE name = 'element_1'"
        )
        .fetch_one(&mut *migration_tx)
        .await
        .unwrap_or(0) > 0;

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
                let test_id: i64 = row.get("id");
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
                        "INSERT INTO test_conditions (tenant_id, test_id, type, element, input, selement, condition, sinput)
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

            // Drop the 25 flat columns using ALTER TABLE DROP COLUMN (SQLite 3.35+).
            // Each statement is a literal string — no string interpolation — to
            // avoid any future regression where a column name could become
            // user-controlled.
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
                // Column may already be absent if a previous partial migration
                // dropped some columns before crashing — ignore that error and
                // continue so the migration is re-entrant.
                let _ = sqlx::query(sql).execute(&mut *migration_tx).await;
            }
        }

        sqlx::query("UPDATE schema_info SET version = 4")
            .execute(&mut *migration_tx).await?;

        migration_tx.commit().await?;

        info!("Schema migration v3 → v4 complete.");
    }

    // =========================================================
    // Migration v4 → v5
    // Fix compliance_score DEFAULT: was 0.0, should be -1.0.
    // Systems/tests/policies that were inserted before any scan
    // ran got DEFAULT 0.0 and appeared in the "Top Failed" table
    // as 0% compliant even though they had never been scanned.
    // We correct any existing rows where score = 0.0 but there
    // are no associated results (i.e. genuinely unscanned).
    // =========================================================
    if version < 5 {
        info!("Running schema migration v4 → v5 (fix unscanned compliance_score 0.0 → -1.0)...");

        let mut migration_tx = pool.begin().await?;

        // Systems with score 0.0 and no results at all
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
        .execute(&mut *migration_tx)
        .await?;

        // Tests with score 0.0 and no associated results
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
        .execute(&mut *migration_tx)
        .await?;

        // Policies with score 0.0 and no associated results
        sqlx::query(
            "UPDATE policies SET compliance_score = -1.0
             WHERE compliance_score = 0.0
               AND systems_passed = 0
               AND systems_failed = 0
               AND NOT EXISTS (
                   SELECT 1 FROM results r
                   JOIN tests_in_policy tip ON tip.test_id = r.test_id
                     AND tip.tenant_id = r.tenant_id
                   WHERE tip.policy_id = policies.id
                     AND r.tenant_id   = policies.tenant_id
               )"
        )
        .execute(&mut *migration_tx)
        .await?;

        sqlx::query("UPDATE schema_info SET version = 5")
            .execute(&mut *migration_tx)
            .await?;

        migration_tx.commit().await?;

        info!("Schema migration v4 → v5 complete.");
    }

    Ok(())
}
