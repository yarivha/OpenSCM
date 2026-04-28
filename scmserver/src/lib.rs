// 1. Module Declarations (Now public so the SaaS repo can access them)
pub mod models;
pub mod handlers;
pub mod config;
pub mod schema;
pub mod auth;
pub mod client;
pub mod dashboard;
pub mod systems;
pub mod tests;
pub mod policies;
pub mod reports;
pub mod users;
pub mod settings;
pub mod scheduler;

// 2. Imports needed for the public API
use std::{sync::Arc, path::PathBuf, error::Error};
use axum::{Router, Extension, response::IntoResponse, routing::{get, post}, http::{header, StatusCode}, body::{Bytes, Body}};
use tera::Tera;
use include_dir::{include_dir, Dir};
use tracing::info;

// 3. Re-exporting static assets so the SaaS version can find them
pub static TEMPLATES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");
pub static STATIC_FILES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/static");

// 4. The Shared Application State
// This struct is the "glue" between your Core logic and the Enterprise wrapper.
#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub tera: Arc<Tera>,
    pub config: Arc<config::Config>,
    pub sync_tx: tokio::sync::mpsc::Sender<()>,
}

// 5. Utility functions moved from main.rs
pub fn init_tera() -> Result<Tera, Box<dyn Error>> {
    let mut tera = Tera::default();
    for file in TEMPLATES_DIR.files() {
        let path = file.path().to_str()
            .ok_or_else(|| format!("Template path is not valid UTF-8: {:?}", file.path()))?;
        
        let content = std::str::from_utf8(file.contents())
            .map_err(|e| format!("Template '{}' contains invalid UTF-8: {}", path, e))?
            .to_owned();

        tera.add_raw_template(path, &content)?;
    }
    tera.build_inheritance_chains()?;
    tera.check_macro_files()?;
    Ok(tera)
}

pub fn check_required_directories() -> Result<(), Box<dyn Error>> {
    use crate::config::{config_path, private_key_path, db_path};
    let targets = [config_path(), db_path(), private_key_path()];

    for target in targets {
        if let Some(parent) = std::path::Path::new(&target).parent() {
            if !parent.exists() {
                info!("Required directory {:?} is missing. Attempting to create...", parent);
                std::fs::create_dir_all(parent)?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if target == private_key_path() { 0o700 } else { 0o755 };
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

pub async fn serve_embedded_static_file(path: PathBuf) -> impl IntoResponse {
    let path_str = path.to_str().unwrap_or("");
    match STATIC_FILES_DIR.get_file(path_str) {
        Some(file) => {
            let mime_type = mime_guess::from_path(path).first_or_octet_stream();
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, mime_type.to_string())
                .body(Body::from(Bytes::from(file.contents())))
                .unwrap()
        }
        None => axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Static file not found"))
            .unwrap(),
    }
}

// 6. The pluggable Core Router
// The SaaS version will call this to get all standard OpenSCM functionality.
pub fn create_core_router(state: AppState, cookie_key: axum_extra::extract::cookie::Key) -> Router {
    Router::new()
        .route("/", get(dashboard::dashboard))
        .route("/login", get(auth::login).post(auth::login_submit))
        .route("/logout", get(auth::logout))
        .route("/notifications/clear", get(handlers::clear_notifications))
        .route("/users", get(users::users))
        .route("/users/add", get(users::users_add).post(users::users_add_save))
        .route("/users/delete/{id}", get(users::users_delete))
        .route("/users/edit/{id}", get(users::users_edit).post(users::users_edit_save))
        .route("/users/changepassword/{id}", post(users::change_password))
        .route("/systems", get(systems::systems))
        .route("/systems/delete/{id}", get(systems::systems_delete))
        .route("/systems/edit/{id}", get(systems::systems_edit).post(systems::systems_edit_save))
        .route("/systems/pending", get(systems::systems_pending))
        .route("/systems/approve/{id}", get(systems::systems_approve))
        .route("/systems/bulk/approve", post(systems::systems_bulk_approve))
        .route("/systems/bulk/delete", post(systems::systems_bulk_delete))
        .route("/systems/bulk/add_group", post(systems::systems_bulk_add_group))
        .route("/system_groups", get(systems::system_groups))
        .route("/system_groups/add", get(systems::system_groups_add).post(systems::system_groups_add_save))
        .route("/system_groups/delete/{id}", get(systems::system_groups_delete))
        .route("/system_groups/edit/{id}", get(systems::system_groups_edit).post(systems::system_groups_edit_save))
        .route("/tests", get(tests::tests))
        .route("/tests/add", get(tests::tests_add).post(tests::tests_add_save))
        .route("/tests/delete/{id}", get(tests::tests_delete))
        .route("/tests/bulk/delete", post(tests::tests_bulk_delete))
        .route("/tests/bulk/add_policy", post(tests::tests_bulk_add_policy))
        .route("/tests/edit/{id}", get(tests::tests_edit).post(tests::tests_edit_save))
        .route("/policies", get(policies::policies))
        .route("/policies/add", get(policies::policies_add).post(policies::policies_add_save))
        .route("/policies/edit/{id}", get(policies::policies_edit).post(policies::policies_edit_save))
        .route("/policies/delete/{id}", get(policies::policies_delete))
        .route("/policies/run/{id}", get(policies::policies_run))
        .route("/policies/report/{id}", get(policies::policies_report))
        .route("/policies/download/{id}", get(policies::policies_report_download))
        .route("/reports", get(reports::reports))
        .route("/reports/save/{id}", get(reports::reports_save))
        .route("/reports/view/{id}", get(reports::reports_view))
        .route("/reports/delete/{id}", get(reports::reports_delete))
        .route("/reports/bulk/delete", post(reports::reports_bulk_delete))
        .route("/reports/download/{id}", get(reports::reports_download))
        .route("/settings", get(settings::settings))
        .route("/settings/save", post(settings::settings_save))
        .route("/send", post(client::send))
        .route("/result", post(client::receive_result))
        .route("/{*path}", get(|axum::extract::Path(path): axum::extract::Path<String>| async move {
            serve_embedded_static_file(PathBuf::from(path)).await
        }))
        .fallback(handlers::not_found)
        // Apply Shared Layers
        .layer(Extension(state.pool))
        .layer(Extension(state.tera))
        .layer(Extension(state.config))
        .layer(Extension(state.sync_tx))
        .with_state(cookie_key)
}
