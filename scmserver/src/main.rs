mod models;
mod handlers;
mod config;
mod schema;
mod auth;
mod client;
mod dashboard;
mod systems;
mod tests;
mod policies;
mod reports;
mod users;
mod settings;
mod scheduler;

use tera::Tera;
use axum::{Extension, Router, response::{Response, IntoResponse}, routing::{get, post}, http::{header, StatusCode}, body::{Bytes, Body}};
use tokio::sync::mpsc;
use std::time::Duration;
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt, reload};
use tracing::{info, debug, warn, error};
use std::{sync::Arc, str::FromStr, net::SocketAddr, path::PathBuf, error::Error};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use include_dir::{include_dir, Dir};

use crate::handlers::*;
use crate::schema::*;
use crate::auth::*;
use crate::client::*;
use crate::dashboard::*;
use crate::systems::*;
use crate::tests::*;
use crate::policies::*;
use crate::reports::*;
use crate::users::*;
use crate::settings::*;
use crate::scheduler::*;


// Embedded templates/static files
static TEMPLATES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");
static STATIC_FILES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/static");

// Initialize Tera from embedded templates
pub fn init_tera() -> Result<Tera, tera::Error> {
    let mut tera = Tera::default();
    for file in TEMPLATES_DIR.files() {
        let path = file.path().to_str().unwrap();
        let content = String::from_utf8_lossy(file.contents()).into_owned();
        tera.add_raw_template(path, &content)?;
    }
    tera.build_inheritance_chains()?;
    tera.check_macro_files()?;
    Ok(tera)
}

// Serve embedded static files
async fn serve_embedded_static_file(path: PathBuf) -> impl IntoResponse {
    let path_str = path.to_str().unwrap_or("");
    match STATIC_FILES_DIR.get_file(path_str) {
        Some(file) => {
            let mime_type = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime_type.to_string())
                .body(Body::from(Bytes::from(file.contents())))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Static file not found"))
            .unwrap(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Logging setup
    let env_filter = EnvFilter::new("info");
    let (reload_layer, reload_handle) = reload::Layer::new(env_filter);
    tracing_subscriber::registry()
        .with(reload_layer)
        .with(fmt::layer())
        .init();

    info!("Starting OpenSCM Server...");

    // Load Config
    let config = config::Config::load().map_err(|e| {
        error!("Failed to load configuration: {}", e);
        e
    })?;

    // Apply log level from config
    let loglevel = config.server.loglevel.as_deref().unwrap_or("info");
    let _ = reload_handle.reload(EnvFilter::new(loglevel));
    debug!("Log level set to '{}'", loglevel);

    // 3. Database Initialization
    info!("Connecting database at '{}'...", config.database.path);
    let db_path = PathBuf::from(&config.database.path);
    
    // Ensure the directory for the DB exists
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let database_url = format!("sqlite://{}", config.database.path);
    let options = SqliteConnectOptions::from_str(&database_url)?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    // Enable foreign keys and init schema
    sqlx::query("PRAGMA foreign_keys = ON").execute(&pool).await?;
    initialize_database(&pool).await?;

    // ---------------------------------------------------------
    // 4. Batch Compliance Worker (The Debouncer)
    // ---------------------------------------------------------
    // This channel allows handlers to "ping" the worker to recalculate
    let (sync_tx, mut sync_rx) = mpsc::channel::<()>(100);
    let worker_pool = pool.clone();

    tokio::spawn(async move {
        info!("Compliance Sync Worker: Online and listening.");
        
        while let Some(_) = sync_rx.recv().await {
            // DEBOUNCE: Wait 10 seconds after the first signal arrives
            // This captures the other 99 systems if they report at once
            tokio::time::sleep(Duration::from_secs(10)).await;

            // DRAIN: Clear out all other pings that happened during the wait
            while sync_rx.try_recv().is_ok() {}

            info!("Compliance Sync Worker: Starting batch recalculation...");
            // Replace 'reports' with the actual module where your function lives
            if let Err(e) = crate::scheduler::recalculate_current_compliance(&worker_pool).await {
                error!("Compliance Sync Worker: Batch recalculation failed: {}", e);
            } else {
                info!("Compliance Sync Worker: Batch recalculation successful.");
            }
        }
    });


    // 5. Background Scheduler (Keep existing)
    crate::scheduler::start_background_scheduler(pool.clone()).await;

    // 6. Template Engine
    info!("Loading Server Templates");
    let tera = Arc::new(init_tera()?);
    let config = Arc::new(config);

    // 7. Routes
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login).post(login_submit))
        .route("/logout", get(logout))
        .route("/users", get(users))
        .route("/users/add", get(users_add).post(users_add_save))
        .route("/users/delete/{id}", get(users_delete))
        .route("/users/edit/{id}", get(users_edit).post(users_edit_save))
        .route("/users/changepassword/{id}", post(change_password))
        .route("/systems", get(systems))
        .route("/systems/delete/{id}", get(systems_delete))
        .route("/systems/edit/{id}", get(systems_edit).post(systems_edit_save))
        .route("/systems/pending", get(systems_pending))
        .route("/systems/approve/{id}", get(systems_approve))
        .route("/system_groups", get(system_groups))
        .route("/system_groups/add", get(system_groups_add).post(system_groups_add_save))
        .route("/system_groups/delete/{id}", get(system_groups_delete))
        .route("/system_groups/edit/{id}", get(system_groups_edit).post(system_groups_edit_save))
        .route("/tests", get(tests))
        .route("/tests/add", get(tests_add).post(tests_add_save))
        .route("/tests/delete/{id}", get(tests_delete))
        .route("/tests/edit/{id}", get(tests_edit).post(tests_edit_save))
        .route("/policies", get(policies))
        .route("/policies/add", get(policies_add).post(policies_add_save))
        .route("/policies/edit/{id}", get(policies_edit).post(policies_edit_save))
        .route("/policies/delete/{id}", get(policies_delete))
        .route("/policies/run/{id}", get(policies_run))
        .route("/policies/report/{id}",get(policies_report))
        .route("/policies/download/{id}",get(policies_report_download))
        .route("/reports", get(reports))
        .route("/reports/save/{id}",get(reports_save))
        .route("/reports/view/{id}",get(reports_view))
        .route("/reports/delete/{id}",get(reports_delete))
        .route("/reports/download/{id}",get(reports_download))
        .route("/send", post(send))
        .route("/result", post(receive_result))
        .route("/{*path}", get(|axum::extract::Path(path): axum::extract::Path<String>| async move {
            serve_embedded_static_file(PathBuf::from(path)).await
        }))
        .fallback(not_found)
        .layer(Extension(pool))
        .layer(Extension(tera))
        .layer(Extension(config.clone()));

    // Pull port from config (default 8000)
    let port: u16 = config.server.port.as_deref()
    .unwrap_or("8000")
    .parse()
    .unwrap_or(8000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    info!("OpenSCM Server listening on http://{}", addr);
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
