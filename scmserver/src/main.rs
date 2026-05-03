use std::{sync::{Arc, atomic::{AtomicBool}}, str::FromStr, net::SocketAddr, fs, error::Error};
use tracing::{info, error, debug};
use tracing_subscriber::{fmt, EnvFilter, registry, layer::SubscriberExt, util::SubscriberInitExt, reload};
use base64::{Engine as _, engine::general_purpose};
use hkdf::Hkdf;
use sha2::Sha256;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::sync::mpsc;

// Importing the public items from our own library (scmserver)
use scmserver::{
    AppState, 
    create_core_router, 
    init_tera, 
    check_required_directories,
    config::{Config, private_key_path, db_path},
    schema::run_migrations,
    scheduler::{start_background_scheduler, recalculate_current_compliance},
};

fn print_usage() {
println!(r#"
OpenSCM Server - Security Compliance Manager 

USAGE:
scmserver [OPTIONS]

OPTIONS:
-h, --help          Print this help message
-ver, --version     Print version information

"#);
}



#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    scmserver::set_app_version(env!("CARGO_PKG_VERSION"));

// 0. Usage
    let version = env!("CARGO_PKG_VERSION");
    let args: Vec<String> = std::env::args().collect();

    for arg in &args {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "-ver" | "--version" => {
                println!("OpenSCM Server version: {}", version);
                return Ok(());
            }
            _ => {}
        }
    }

    // 1. Initial Infrastructure setup
    check_required_directories()?;

    // 2. Logging & Tracing setup
    let env_filter = EnvFilter::new("info");
    let (reload_layer, reload_handle) = reload::Layer::new(env_filter);
    registry()
        .with(reload_layer)
        .with(fmt::layer())
        .init();

    info!("Starting OpenSCM Community Edition...");

    // 3. Load Configuration
    let config = Config::load().map_err(|e| {
        error!("Failed to load configuration: {}", e);
        e
    })?;

    // Apply log level from config dynamically
    let loglevel = config.server.loglevel.as_deref().unwrap_or("info");
    let _ = reload_handle.reload(EnvFilter::new(loglevel));
    debug!("Log level set to '{}'", loglevel);

    // 4. Cryptography: Load key and derive Cookie Key
    let priv_base64 = fs::read_to_string(private_key_path())?;
    let priv_bytes = general_purpose::STANDARD.decode(priv_base64.trim())?;

    if priv_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".into());
    }

    let hk = Hkdf::<Sha256>::new(None, &priv_bytes);
    let mut cookie_key_bytes = [0u8; 64];
    hk.expand(b"oscm-cookie-signing-v1", &mut cookie_key_bytes)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    let cookie_key = axum_extra::extract::cookie::Key::from(&cookie_key_bytes);

    // 5. Database
    // Connect (creates an empty file if none exists).
    // Whether the DB is truly initialised is determined by the presence of the
    // schema_info table — NOT by the file's existence.  This avoids the trap
    // where the SQLite file is created on first connect but the schema hasn't
    // been set up yet, which would cause initialize_database to be skipped on
    // the next restart and leave the DB in an inconsistent state.
    //
    // Rule: initialize_database() is ONLY ever called from the /install handler
    // (triggered by the admin clicking "Complete Setup").  On subsequent starts
    // run_migrations() is sufficient.
    let database_url = format!("sqlite://{}", db_path());
    let options = SqliteConnectOptions::from_str(&database_url)?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    // Detect real initialisation: schema_info table exists and has a row.
    let db_initialized: bool = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_info'"
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(0) > 0;

    if db_initialized {
        sqlx::query("PRAGMA foreign_keys = ON").execute(&pool).await?;
        run_migrations(&pool).await?;
    } else {
        info!("Fresh install detected — waiting for setup via /install");
    }

    // 6. Background Workers
    // The compliance-sync worker is always started; it only runs queries when
    // triggered via sync_tx (from authenticated routes), so it stays idle until
    // after the install is complete.
    let (sync_tx, mut sync_rx) = mpsc::channel::<()>(100);
    let worker_pool = pool.clone();

    tokio::spawn(async move {
        while let Some(_) = sync_rx.recv().await {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            while sync_rx.try_recv().is_ok() {}
            if let Err(e) = recalculate_current_compliance(&worker_pool).await {
                error!("Compliance Sync Worker error: {}", e);
            }
        }
    });

    // Background scheduler only starts when the DB is already initialised; the
    // /install handler starts it after a fresh setup.
    if db_initialized {
        start_background_scheduler(pool.clone()).await;
    }

    // 7. Assemble Application State
    // We wrap things in Arc here to share them between the Core and potential SaaS wrappers
    let state = AppState {
        pool,
        tera: Arc::new(init_tera()?),
        config: Arc::new(config),
        sync_tx,
        is_initialized: Arc::new(AtomicBool::new(db_initialized)),
    };

    let port: u16 = state.config.server.port.as_deref()
        .unwrap_or("8000")
        .parse()
        .unwrap_or(8000);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    // ----------------------------------------------------

    // 8. Build the Router (This consumes/moves 'state')
    let app = create_core_router(state, cookie_key);

    // 9. Start the Server
    info!("OpenSCM Community Server listening on http://{}", addr);
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
