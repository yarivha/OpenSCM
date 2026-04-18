// src/schema.rs
use sqlx::SqlitePool;
use bcrypt::{hash, DEFAULT_COST};
use tracing::{info, error};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine as _};

/// Initialize the database schema
pub async fn initialize_database(pool: &SqlitePool) -> Result<(), sqlx::Error> {

    info!("Init Database......");


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
            compliance_score REAL DEFAULT 0.0,
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
            filter TEXT,
            element_1 TEXT,
            input_1 TEXT,
            selement_1 TEXT,
            condition_1 TEXT,
            sinput_1 TEXT,
            element_2 TEXT,
            input_2 TEXT,
            selement_2 TEXT,
            condition_2 TEXT,
            sinput_2 TEXT,
            element_3 TEXT,
            input_3 TEXT,
            selement_3 TEXT,
            condition_3 TEXT,
            sinput_3 TEXT,
            element_4 TEXT,
            input_4 TEXT,
            selement_4 TEXT,
            condition_4 TEXT,
            sinput_4 TEXT,
            element_5 TEXT,
            input_5 TEXT,
            selement_5 TEXT,
            condition_5 TEXT,
            sinput_5 TEXT,
            compliance_score REAL DEFAULT 0.0,
            systems_passed INTEGER DEFAULT 0,
            systems_failed INTEGER DEFAULT 0,
            FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
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
           compliance_score REAL DEFAULT 0.0,
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
        policy_id INTEGER NOT NULL UNIQUE, -- This UNIQUE keyword is the fix
        enabled BOOLEAN NOT NULL DEFAULT 1,
        frequency TEXT NOT NULL,
        cron_expression TEXT,
        next_run DATETIME NOT NULL,
        last_run DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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



    // Insert the default CE tenant
    sqlx::query("INSERT OR IGNORE INTO tenants (id, name) VALUES ('default', 'Default Tenant')")
        .execute(pool)
        .await?;

    // Insert default admin user if it doesn't exist
    let hashed_password = hash("admin", DEFAULT_COST)
    .map_err(|e| {
        error!("Failed to hash default admin password: {}", e);
        sqlx::Error::Protocol(e.to_string())
    })?;


    sqlx::query(
    "INSERT OR IGNORE INTO users (id, tenant_id, username, password, name, email, role)
     VALUES (1, 'default', 'admin', ?, 'Admin User', 'admin@example.com', 'admin')",
    )
    .bind(hashed_password)
    .execute(pool)
    .await?;
   

    // --------------------
    // Elements
    // --------------------
    let elements = vec![
        ("AGENT"),("OS"),("HOSTNAME"),("IP"),("DOMAIN"),("ARCHITECTURE"),("USER"),("GROUP"),("FILE"),
        ("DIRECTORY"),("PROCESS"),("PACKAGE"),("REGISTRY"),("PORT"),
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
        ("EXISTS"), ("NOT EXISTS"),("CONTENT"),("VERSION"),("PERMISSION"),("OWNER"),("SHA1"),("SHA2"),
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



