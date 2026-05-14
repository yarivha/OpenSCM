// =============================================================================
// install.rs — first-run setup wizard
//
// Reachable only when is_initialized = false (enforced by init_guard middleware).
// GET shows the setup form; POST validates the admin password, initialises the
// database, creates the admin user, and marks the installation as complete.
//
// MySQL flow: a new AnyPool is created for the target URL, the schema is
// initialised on it, the config file is updated with db_type/mysql_url, and a
// "restart required" page is shown.  The server must be restarted so the main
// pool switches to MySQL.
// =============================================================================
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;
use axum::{Extension, response::{IntoResponse, Html, Redirect}};
use bcrypt::{hash, DEFAULT_COST};
use tera::{Tera, Context};
use tracing::error;

use crate::config::Config;
use crate::schema::{initialize_database, run_migrations};
use crate::scheduler::start_background_scheduler;
use crate::db_compat;
use crate::PostInstallFn;

// ─────────────────────────────────────────────────────────────────────────────
// GET /install
// Show the first-run setup form (only reachable before initialisation).
// Role: Public
// ─────────────────────────────────────────────────────────────────────────────
pub async fn install_get(
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    let ctx = Context::new();
    match tera.render("install.html", &ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("install template error: {}", e);
            Html("<h1>Template error</h1>".to_string()).into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /install
// Validate the chosen admin password, initialise the DB schema, create the
// admin user, run migrations, and flip is_initialized to true.
//
// MySQL path: create a temporary pool for the target URL, initialise schema
// there, write db_type + mysql_url into the config file, and render the
// "restart required" page.  The existing server pool stays on SQLite until the
// process is restarted.
//
// SQLite path: operate on the existing pool, start the scheduler, and redirect
// to /login as before.
// Role: Public
// ─────────────────────────────────────────────────────────────────────────────
pub async fn install_post(
    Extension(pool): Extension<sqlx::AnyPool>,
    Extension(tera): Extension<Arc<Tera>>,
    Extension(config): Extension<Arc<Config>>,
    Extension(is_initialized): Extension<Arc<AtomicBool>>,
    post_install: Option<Extension<PostInstallFn>>,
    axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>,
) -> impl IntoResponse {
    // Helper: render install.html with an error message.
    let render_error = |tera: &Tera, msg: &str| -> axum::response::Response {
        let mut ctx = Context::new();
        ctx.insert("error_message", msg);
        match tera.render("install.html", &ctx) {
            Ok(html) => Html(html).into_response(),
            Err(_)   => Html("<h1>Template error</h1>".to_string()).into_response(),
        }
    };

    let password = form.get("password").map(|s| s.trim()).unwrap_or("");
    let confirm  = form.get("confirm_password").map(|s| s.trim()).unwrap_or("");
    let db_type  = form.get("db_type").map(|s| s.trim()).unwrap_or("sqlite");
    let mysql_url_raw = form.get("mysql_url").map(|s| s.trim()).unwrap_or("");

    // --- Password validation ---
    if password.is_empty() {
        return render_error(&tera, "Admin password is required.");
    }
    if password.len() < 8 {
        return render_error(&tera, "Password must be at least 8 characters.");
    }
    if password != confirm {
        return render_error(&tera, "Passwords do not match.");
    }

    // --- MySQL URL validation (only when MySQL is selected) ---
    if db_type == "mysql" {
        if mysql_url_raw.is_empty() {
            return render_error(&tera, "MySQL URL is required when MySQL backend is selected.");
        }
        if !mysql_url_raw.starts_with("mysql://") {
            return render_error(&tera, "MySQL URL must start with mysql://");
        }
    }

    // --- Select the target pool ---
    // For MySQL we create a fresh pool pointed at the user-supplied URL so that
    // schema initialisation runs against the right database.  For SQLite we
    // reuse the pool that was already opened at startup.
    let (target_pool, is_mysql) = if db_type == "mysql" {
        match sqlx::AnyPool::connect(mysql_url_raw).await {
            Ok(p) => (p, true),
            Err(e) => {
                error!("install: failed to connect to MySQL: {}", e);
                return render_error(&tera, &format!("Could not connect to MySQL: {}", e));
            }
        }
    } else {
        // SQLite — enable FK enforcement before initialisation.
        if let Err(e) = sqlx::query("PRAGMA foreign_keys = ON").execute(&pool).await {
            error!("install: PRAGMA error: {}", e);
        }
        (pool.clone(), false)
    };

    // For the MySQL path we must update the global db_compat backend so that
    // adapt_sql() / last_insert_id_sql() etc. emit MySQL-compatible SQL during
    // initialisation.  The process is in pre-init state so no concurrent
    // authenticated requests are running.
    if is_mysql {
        crate::set_db_backend(crate::DbBackend::Mysql);
    }

    // --- Initialise schema ---
    if let Err(e) = initialize_database(&target_pool).await {
        error!("install: initialize_database failed: {}", e);
        return render_error(&tera, "Database initialisation failed. Check server logs.");
    }

    // --- Hash admin password ---
    let hashed = match hash(password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("install: bcrypt error: {}", e);
            return render_error(&tera, "Failed to hash password. Check server logs.");
        }
    };

    // --- Create the admin user ---
    if let Err(e) = sqlx::query(
        &db_compat::adapt_sql("INSERT OR IGNORE INTO users (id, tenant_id, username, password, name, email, role)
         VALUES (1, 'default', 'admin', ?, 'Admin User', 'admin@example.com', 'superuser')")
    )
    .bind(hashed)
    .execute(&target_pool)
    .await
    {
        error!("install: failed to create admin user: {}", e);
        return render_error(&tera, "Failed to create admin user. Check server logs.");
    }

    // --- Run migrations (fresh DB starts at current version, so this is a no-op) ---
    if let Err(e) = run_migrations(&target_pool).await {
        error!("install: run_migrations failed: {}", e);
    }

    // --- Run EE/SaaS post-install hook if registered ---
    if let Some(Extension(hook)) = post_install {
        hook(target_pool.clone()).await;
    }

    // --- MySQL path: write config and show restart page ---
    if is_mysql {
        let mut new_cfg = (*config).clone();
        new_cfg.database.db_type  = Some("mysql".to_string());
        new_cfg.database.mysql_url = Some(mysql_url_raw.to_string());
        if let Err(e) = new_cfg.save() {
            error!("install: failed to save config: {}", e);
            return render_error(&tera, "Failed to write configuration file. Check server logs.");
        }

        let mut ctx = Context::new();
        ctx.insert("restart_required", &true);
        return match tera.render("install.html", &ctx) {
            Ok(html) => Html(html).into_response(),
            Err(_)   => Html("<h1>Template error</h1>".to_string()).into_response(),
        };
    }

    // --- SQLite path: start scheduler and mark initialised ---
    start_background_scheduler(target_pool).await;
    is_initialized.store(true, Ordering::SeqCst);

    Redirect::to("/login").into_response()
}
