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

use axum::extract::Form as AxumForm;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::ConnectOptions as _;
use sqlx::mysql::MySqlConnectOptions;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::timeout;

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

    // --- MySQL path: write config then re-exec the process ---
    // We write the MySQL URL to the config file and immediately schedule a
    // process restart so the server re-opens its pool against MySQL.  The
    // spawned task waits long enough for the HTTP response to be flushed, then:
    //   • Unix   — exec() replaces the process image (zero-downtime swap)
    //   • Windows — spawns a replacement process then calls exit(0)
    // The browser page shown polls /login every second; once the restarted
    // process is up (typically < 2 s) it redirects automatically.
    if is_mysql {
        let mut new_cfg = (*config).clone();
        new_cfg.database.db_type  = Some("mysql".to_string());
        new_cfg.database.mysql_url = Some(mysql_url_raw.to_string());
        if let Err(e) = new_cfg.save() {
            error!("install: failed to save config: {}", e);
            return render_error(&tera, "Failed to write configuration file. Check server logs.");
        }

        tokio::spawn(async move {
            // Give the HTTP layer time to flush the response before we exit.
            tokio::time::sleep(Duration::from_millis(800)).await;

            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => {
                    error!("install: could not find current_exe for restart: {}", e);
                    std::process::exit(0);
                }
            };
            let args: Vec<String> = std::env::args().skip(1).collect();

            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(&exe).args(&args).exec();
                // exec() only returns if it fails.
                error!("install: exec() failed: {}", err);
            }
            #[cfg(not(unix))]
            {
                if let Err(e) = std::process::Command::new(&exe).args(&args).spawn() {
                    error!("install: failed to spawn replacement process: {}", e);
                }
            }
            std::process::exit(0);
        });

        let mut ctx = Context::new();
        ctx.insert("restarting", &true);
        return match tera.render("install.html", &ctx) {
            Ok(html) => Html(html).into_response(),
            Err(_)   => Html("<h1>Starting…</h1>").into_response(),
        };
    }

    // --- SQLite path: start scheduler and mark initialised ---
    start_background_scheduler(target_pool).await;
    is_initialized.store(true, Ordering::SeqCst);

    Redirect::to("/login").into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /install/test-db
// Attempts to connect to the supplied MySQL URL and returns a JSON result.
// Uses a single direct connection (no pool) with a 5-second timeout so the
// user gets fast, clear feedback even when the server is unreachable.
// Only reachable before initialisation (enforced by init_guard).
// Role: Public (install wizard)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TestDbForm {
    pub mysql_url: String,
}

#[derive(Serialize)]
struct TestDbResponse {
    success: bool,
    message: String,
}

pub async fn test_db_post(
    AxumForm(form): AxumForm<TestDbForm>,
) -> impl IntoResponse {
    use sqlx::Connection as _;

    let url = form.mysql_url.trim();

    if url.is_empty() {
        return (StatusCode::BAD_REQUEST, axum::Json(TestDbResponse {
            success: false,
            message: "MySQL URL is required.".into(),
        }));
    }

    if !url.starts_with("mysql://") {
        return (StatusCode::BAD_REQUEST, axum::Json(TestDbResponse {
            success: false,
            message: "URL must start with mysql://".into(),
        }));
    }

    let opts = match MySqlConnectOptions::from_str(url) {
        Ok(o) => o,
        Err(e) => return (StatusCode::OK, axum::Json(TestDbResponse {
            success: false,
            message: format!("Invalid MySQL URL: {}", e),
        })),
    };

    let connect_result = timeout(Duration::from_secs(5), opts.connect()).await;

    match connect_result {
        Err(_) => (StatusCode::OK, axum::Json(TestDbResponse {
            success: false,
            message: "Connection timed out after 5 seconds. Check host, port, and firewall.".into(),
        })),
        Ok(Err(e)) => (StatusCode::OK, axum::Json(TestDbResponse {
            success: false,
            message: format!("Connection failed: {}", e),
        })),
        Ok(Ok(mut conn)) => {
            let ping = sqlx::query("SELECT 1").execute(&mut conn).await;
            conn.close().await.ok();
            match ping {
                Ok(_) => (StatusCode::OK, axum::Json(TestDbResponse {
                    success: true,
                    message: "Connection successful.".into(),
                })),
                Err(e) => (StatusCode::OK, axum::Json(TestDbResponse {
                    success: false,
                    message: format!("Connected but ping failed: {}", e),
                })),
            }
        }
    }
}
