// src/schema.rs
use sqlx::SqlitePool;
use bcrypt::{hash, DEFAULT_COST};


/// Initialize the database schema
pub async fn initialize_database(pool: &SqlitePool) -> Result<(), sqlx::Error> {


    // Create notify table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notify (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            timestamp TEXT,
            message TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Create users table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            name TEXT,
            email TEXT,
            role TEXT
        )",
    )
    .execute(pool)
    .await?;
    
    // Create systems table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            trust_challenge TEXT,
            trust_proof TEXT,
            created_date TEXT,
            last_seen TEXT
        )",
    )
    .execute(pool)
    .await?;
    
    // Create system_groups table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
        )",
    )
    .execute(pool)
    .await?;
    
    // Create systems_in_groups table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems_in_groups (
            system_id INTEGER,
            group_id INTEGER,
            PRIMARY KEY (system_id, group_id),
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
            sinput_5 TEXT
        )",
    )
    .execute(pool)
    .await?;
    
    

    // Create policies table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS policies (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           name TEXT NOT NULL,
           description TEXT,
           version TEXT
        )",
    )
    .execute(pool)
    .await?;

    // Create tests_in_policy table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tests_in_policy (
            policy_id INTEGER,
            test_id INTEGER,
            PRIMARY KEY (policy_id, test_id),
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;


    // Create systems_in_policy table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS systems_in_policy (
            policy_id INTEGER,
            group_id INTEGER,
            PRIMARY KEY (policy_id, group_id),
            FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES system_groups (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;


    // Create commands table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS commands (
            system_id INTEGER,
	    test_id INTEGER,
            PRIMARY KEY (system_id, test_id),
            FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )", 
    )
    .execute(pool)
    .await?;


    // Create results table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS results (
            system_id INTEGER,
            test_id INTEGER,
            result TEXT,
            last_updated TEXT,
            PRIMARY KEY (system_id, test_id),
            FOREIGN KEY (system_id) REFERENCES systems(id) ON DELETE CASCADE,
            FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE
        )",
   )
   .execute(pool)
   .await?;



    // Create severity table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS severity (
            id INTEGER PRIMARY KEY,
            level TEXT NOT NULL UNIQUE
        )",
    )
    .execute(pool)
    .await?;



    // Insert severity levels if they don't exist
//    let severity_levels = ["Critical", "High", "Medium", "Low", "Informational"];
//    for (i, level) in severity_levels.iter().enumerate() {
//        let level_str = level.to_string();
//        sqlx::query(
//            "INSERT OR IGNORE INTO severity (id, level) VALUES (?, ?)",
//            params![i as i32 + 1, level_str],
//        )
//        .execute(pool)
//        .await?;
//    }
    
    // Create frameworks table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS frameworks (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT,
            description TEXT,
            UNIQUE(name, version)
        )",
    )
    .execute(pool)
    .await?;

    
    // Create controls table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS controls (
            id INTEGER PRIMARY KEY,
            framework_id INTEGER,
            control_id TEXT NOT NULL,
            title TEXT,
            description TEXT,
            FOREIGN KEY (framework_id) REFERENCES frameworks (id) ON DELETE CASCADE,
            UNIQUE(framework_id, control_id)
        )",
    )
    .execute(pool)
    .await?;

    // Create test_framework_mappings table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS test_framework_mappings (
            test_id INTEGER,
            control_id INTEGER,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE,
            FOREIGN KEY (control_id) REFERENCES controls (id) ON DELETE CASCADE,
            PRIMARY KEY (test_id, control_id)
        )",
    )
    .execute(pool)
    .await?;
    
    // Create test_results table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY,
            test_id INTEGER,
            system_id TEXT,
            status TEXT,
            score INTEGER,
            details TEXT,
            timestamp TEXT,
            execution_time INTEGER,
            FOREIGN KEY (test_id) REFERENCES tests (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    
    // Create system_compliance_history table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_compliance_history (
            id INTEGER PRIMARY KEY,
            system_id TEXT,
            timestamp TEXT,
            compliance_score REAL,
            passed INTEGER,
            failed INTEGER,
            warnings INTEGER,
            errors INTEGER
        )",
    )
    .execute(pool)
    .await?;
    
    // Create report_templates table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS report_templates (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            template_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_system_template INTEGER DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;
    
    // Create scheduled_reports table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS scheduled_reports (
            id INTEGER PRIMARY KEY,
            template_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            schedule TEXT NOT NULL,
            recipients TEXT,
            last_run TEXT,
            next_run TEXT,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (template_id) REFERENCES report_templates (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    
    // Create report_exports table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS report_exports (
            id INTEGER PRIMARY KEY,
            template_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            format TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            FOREIGN KEY (template_id) REFERENCES report_templates (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;

    
    // Create system_public_keys table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_public_keys (
            system_id INTEGER PRIMARY KEY,
            public_key TEXT NOT NULL,
            FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE
        )",
    )
    .execute(pool)
    .await?;
    
    // Create agent_keys table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agent_keys (
            id INTEGER PRIMARY KEY,
            public_key TEXT NOT NULL UNIQUE,
            agent_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT
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



    // Insert default admin user if it doesn't exist
    let hashed_password = hash("admin", DEFAULT_COST).unwrap();

    sqlx::query(
    "INSERT OR IGNORE INTO users (id, username, password, name, email, role)
     VALUES (1, 'admin', ?, 'Admin User', 'admin@example.com', 'admin')",
    )
    .bind(hashed_password)
    .execute(pool)
    .await?;
   

    // --------------------
    // Elements
    // --------------------
    let elements = vec![
        ("Agent"),("OS"),("Hostname"),("IP"),("Architecture"),("File"),("Directory"),("Process"),("Package"),("Registry"),("Port"),
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
        ("Exists"), ("Not Exists"),("Open"),("Close"),("Content"),("Version"),("Permission"),("Owner"),("SHA1"),("SHA256"),
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
        ("Contains"),("Not Contains"),("Equals"),("Not Equals"),("More Than"),("Less Than")
    ];

    for name in conditions {
        sqlx::query(
            "INSERT OR IGNORE INTO conditions (name) VALUES (?)"
        )
        .bind(name)
        .execute(pool)
        .await?;
    }



    Ok(())
} 
