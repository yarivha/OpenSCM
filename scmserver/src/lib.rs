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
pub mod install;

// 2. Imports needed for the public API
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}, OnceLock}, path::PathBuf, error::Error};

// Version registry — set once at binary startup so EE/SaaS show their own version.
static APP_VERSION: OnceLock<String> = OnceLock::new();

/// Call this from each binary's main() before starting the server.
/// Uses the calling crate's CARGO_PKG_VERSION.
pub fn set_app_version(version: &str) {
    let _ = APP_VERSION.set(version.to_string());
}

/// Returns the version set by set_app_version(), or CE's version as fallback.
pub fn app_version() -> &'static str {
    APP_VERSION.get().map(|s| s.as_str()).unwrap_or(env!("CARGO_PKG_VERSION"))
}
use axum::{Router, Extension, response::IntoResponse, routing::{get, post}, http::{header, StatusCode}, body::{Bytes, Body}};
use axum::middleware;
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
    /// False on a brand-new install until /install setup completes.
    pub is_initialized: Arc<AtomicBool>,
}

// 5. Utility functions moved from main.rs
pub fn init_tera() -> Result<Tera, Box<dyn Error>> {
    init_tera_with_overrides(&[])
}

/// Like `init_tera`, but lets callers replace specific CE templates by name.
/// Pass `&[("login.html", "<html>...")]` to substitute individual templates.
pub fn init_tera_with_overrides(overrides: &[(&str, &str)]) -> Result<Tera, Box<dyn Error>> {
    let mut tera = Tera::default();
    for file in TEMPLATES_DIR.files() {
        let path = file.path().to_str()
            .ok_or_else(|| format!("Template path is not valid UTF-8: {:?}", file.path()))?;

        // Skip CE template if the caller supplies an override for this name
        if overrides.iter().any(|(name, _)| *name == path) {
            continue;
        }

        let content = std::str::from_utf8(file.contents())
            .map_err(|e| format!("Template '{}' contains invalid UTF-8: {}", path, e))?
            .to_owned();

        tera.add_raw_template(path, &content)?;
    }
    for (name, content) in overrides {
        tera.add_raw_template(name, content)?;
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

// 6. Initialisation guard middleware
// Redirects every request to /install when the DB has not been set up yet,
// and redirects /install to /login once setup is complete.
// NOTE: called via closure in create_core_router so the Arc is captured
// directly rather than extracted from an Extension (which would not be
// available at the outermost middleware layer).
async fn init_guard(
    is_initialized: Arc<AtomicBool>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path().to_owned();
    let initialized = is_initialized.load(Ordering::SeqCst);

    // Let static assets through unconditionally (needed for the install page CSS/JS)
    let is_asset = path.starts_with("/static/") || {
        let p = path.as_str();
        p.ends_with(".css") || p.ends_with(".js") || p.ends_with(".png")
            || p.ends_with(".ico") || p.ends_with(".svg") || p.ends_with(".woff2")
    };

    if is_asset {
        return next.run(request).await;
    }

    if !initialized && path != "/install" {
        return axum::response::Redirect::to("/install").into_response();
    }
    if initialized && path == "/install" {
        return axum::response::Redirect::to("/login").into_response();
    }

    next.run(request).await
}

// 7. The pluggable Core Router
pub fn create_core_router(state: AppState, cookie_key: axum_extra::extract::cookie::Key) -> Router {
    Router::new()
        .route("/install", get(install::install_get).post(install::install_post))
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
        .route("/systems/report/{id}", get(systems::system_report))
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
        .layer(Extension(state.pool))
        .layer(Extension(state.tera))
        .layer(Extension(state.config))
        .layer(Extension(state.sync_tx))
        .layer(Extension(state.is_initialized.clone()))   // available to handlers
        .layer({                                           // middleware uses closure, not Extension
            let flag = state.is_initialized.clone();
            middleware::from_fn(move |req, next| {
                let flag = flag.clone();
                async move { init_guard(flag, req, next).await }
            })
        })
        .with_state(cookie_key)
}
