use std::{sync::Arc, str::FromStr, net::SocketAddr, fs, error::Error, path::PathBuf};
use tracing::{info, error, debug, warn};
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
    schema::{initialize_database, run_migrations},
    scheduler::{start_background_scheduler, recalculate_current_compliance},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

    // 5. Database Initialization
    let database_url = format!("sqlite://{}", db_path());
    let options = SqliteConnectOptions::from_str(&database_url)?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    sqlx::query("PRAGMA foreign_keys = ON").execute(&pool).await?;
    initialize_database(&pool).await?;
    run_migrations(&pool).await?;

    // 6. Background Workers
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

    start_background_scheduler(pool.clone()).await;

    // 7. Assemble Application State
    // We wrap things in Arc here to share them between the Core and potential SaaS wrappers
    let state = AppState {
        pool,
        tera: Arc::new(init_tera()?),
        config: Arc::new(config),
        sync_tx,
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
