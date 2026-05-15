// =============================================================================
// install.rs — first-run setup wizard
//
// Reachable only when is_initialized = false (enforced by init_guard middleware).
// GET shows the setup form; POST validates the admin password, initialises the
// database, creates the admin user, and marks the installation as complete.
// =============================================================================
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;
use axum::{Extension, response::{IntoResponse, Html, Redirect}};
use bcrypt::{hash, DEFAULT_COST};
use tera::{Tera, Context};
use tracing::error;

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
    let mut ctx = Context::new();
    ctx.insert("edition", crate::app_edition());
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
// Role: Public
// ─────────────────────────────────────────────────────────────────────────────
pub async fn install_post(
    Extension(pool): Extension<sqlx::SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
    Extension(is_initialized): Extension<Arc<AtomicBool>>,
    post_install: Option<Extension<PostInstallFn>>,
    axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>,
) -> impl IntoResponse {
    // Helper: render install.html with an error message.
    let render_error = |tera: &Tera, msg: &str| -> axum::response::Response {
        let mut ctx = Context::new();
        ctx.insert("edition", crate::app_edition());
        ctx.insert("error_message", msg);
        match tera.render("install.html", &ctx) {
            Ok(html) => Html(html).into_response(),
            Err(_)   => Html("<h1>Template error</h1>".to_string()).into_response(),
        }
    };

    let password = form.get("password").map(|s| s.trim()).unwrap_or("");
    let confirm  = form.get("confirm_password").map(|s| s.trim()).unwrap_or("");

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

    // Enable FK enforcement before initialisation.
    if let Err(e) = sqlx::query("PRAGMA foreign_keys = ON").execute(&pool).await {
        error!("install: PRAGMA error: {}", e);
    }

    // --- Initialise schema ---
    if let Err(e) = initialize_database(&pool).await {
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
    .execute(&pool)
    .await
    {
        error!("install: failed to create admin user: {}", e);
        return render_error(&tera, "Failed to create admin user. Check server logs.");
    }

    // --- Run migrations (fresh DB starts at current version, so this is a no-op) ---
    if let Err(e) = run_migrations(&pool).await {
        error!("install: run_migrations failed: {}", e);
    }

    // --- Run SaaS post-install hook if registered ---
    if let Some(Extension(hook)) = post_install {
        hook(pool.clone()).await;
    }

    // --- Start scheduler and mark initialised ---
    start_background_scheduler(pool).await;
    is_initialized.store(true, Ordering::SeqCst);

    Redirect::to("/login").into_response()
}
