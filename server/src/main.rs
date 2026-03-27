// main.rs

mod models;
mod handlers;
mod config;
mod schema;
mod auth;
mod client;

use tera::Tera;
use axum::Extension;
use axum::response::{Response, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use axum::http::{header, StatusCode};
use axum::body::{Bytes, Body};
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt, reload};
use tracing::{debug, info, warn};
use std::sync::Arc;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::error::Error;
use include_dir::{include_dir, Dir};

use crate::handlers::*;
use crate::schema::*;
use crate::auth::*;
use crate::client::*;

// Config file name
static CONFIG_FILE: &str = "scmserver.config";

// Embedded templates
static TEMPLATES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");
// Embedded static files
static STATIC_FILES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/static");

// Initialize Tera from embedded templates
pub fn init_tera() -> Result<Tera, tera::Error> {
    let mut tera = Tera::default();
    // use the static directory directly
    let templates = &TEMPLATES_DIR;

    for file in templates.files() {
        let path = file.path().to_str().unwrap();
        let content = String::from_utf8_lossy(file.contents()).into_owned();
        tera.add_raw_template(path, &content)?;
    }

    // build inheritance and macro graph so {% extends %} works
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
    // Initialize tracing subscriber
    let env_filter = EnvFilter::new("info");
    let (reload_layer, reload_handle) = reload::Layer::new(env_filter);
    tracing_subscriber::registry()
        .with(reload_layer)
        .with(fmt::layer())
        .init();

    info!("Starting SCM Server...");

    // Ensure config file exists
    let config_path = Path::new(CONFIG_FILE);
    if !config_path.exists() {
        warn!("Config '{}' not found. Creating default.", CONFIG_FILE);
        config::Config::default().save_to(CONFIG_FILE)
            .map_err(|e| Box::<dyn Error>::from(e))?;
    }

    // Load config
    let config = config::load_and_validate_config(CONFIG_FILE)
        .map_err(|e| Box::<dyn Error>::from(e))?;
    info!("Config '{}' loaded successfully", CONFIG_FILE);

    // Apply log level from config
    let level = config.server.loglevel.as_deref().unwrap_or("info");
    reload_handle.reload(EnvFilter::new(level))
        .map_err(|e| Box::<dyn Error>::from(e))?;
    debug!("Log level updated to '{}'", level);

    // Initialize Tera
    info!("Loading Templates");
    let tera = init_tera().map_err(|e| Box::<dyn Error>::from(e))?;
    let tera = Arc::new(tera);

    // Ensure DB directory exists
    info!("Initializing database...");
    let db_path = &config.database.path;
    if let Some(parent) = Path::new(db_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Box::<dyn Error>::from(e))?;
    }

    let database_url = format!("sqlite://{}", db_path);
    let options = SqliteConnectOptions::from_str(&database_url)?
        .create_if_missing(true);

    // Create connection pool
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .map_err(|e| Box::<dyn Error>::from(e))?;

    // Enable foreign keys
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await
        .map_err(|e| Box::<dyn Error>::from(e))?;

    // Initialize database schema
    initialize_database(&pool)
        .await
        .map_err(|e| Box::<dyn Error>::from(e))?;

    info!("Database ready at '{}'", db_path);

    // Wrap config in Arc so it can be cloned into extensions
    let config = Arc::new(config);

    // Build routes
    info!("Loading Routes");
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login))
        .route("/login", post(login_submit))
        .route("/logout", get(logout))
        .route("/users", get(users))
        .route("/users/add", get(users_add))
        .route("/users/add", post(users_add_save))
        .route("/users/delete/{id}", get(users_delete))
        .route("/systems", get(systems))
        .route("/systems/delete/{id}", get(systems_delete))
        .route("/systems/edit/{id}", get(systems_edit))
        .route("/systems/edit/{id}", post(systems_edit_save))
        .route("/systems/pending", get(systems_pending))
        .route("/systems/approve/{id}", get(systems_approve))
        .route("/system_groups", get(system_groups))
        .route("/system_groups/add", get(system_groups_add))
        .route("/system_groups/add", post(system_groups_add_save))
        .route("/system_groups/delete/{id}", get(system_groups_delete))
        .route("/system_groups/edit/{id}", get(system_groups_edit))
        .route("/system_groups/edit/{id}", post(system_groups_edit_save))
        .route("/tests", get(tests))
        .route("/tests/add", get(tests_add))
        .route("/tests/add", post(tests_add_save))
        .route("/tests/delete/{id}", get(tests_delete))
        .route("/tests/edit/{id}", get(tests_edit))
        .route("/tests/edit/{id}", post(tests_edit_save))
        .route("/policies", get(policies))
        .route("/policies/add", get(policies_add))
        .route("/policies/add", post(policies_add_save))
        .route("/policies/edit/{id}", get(policies_edit))
        .route("/policies/edit/{id}", post(policies_edit_save))
        .route("/policies/delete/{id}", get(policies_delete))
        .route("/policies/run/{id}", get(policies_run))
        .route("/send", post(send))
        .route("/result", post(receive_result))
        .route("/{*path}", get(|path: axum::extract::Path<String>| async move {
            serve_embedded_static_file(PathBuf::from(path.0)).await
        }))
        .fallback(not_found)
        .layer(Extension(pool.clone()))
        .layer(Extension(tera.clone()))
        .layer(Extension(config.clone()));

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("Listening on http://{}", addr);
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
