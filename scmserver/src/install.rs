// src/install.rs — First-run setup screen
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;
use axum::{Extension, response::{IntoResponse, Html, Redirect}};
use bcrypt::{hash, DEFAULT_COST};
use tera::{Tera, Context};
use tracing::error;

use crate::schema::{initialize_database, run_migrations};
use crate::scheduler::start_background_scheduler;

/// GET /install — show the setup form (only reachable when not yet initialised)
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

/// POST /install — initialise the database and set the admin password
pub async fn install_post(
    Extension(pool): Extension<sqlx::SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
    Extension(is_initialized): Extension<Arc<AtomicBool>>,
    axum::extract::Form(form): axum::extract::Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let password     = form.get("password").map(|s| s.trim()).unwrap_or("");
    let confirm      = form.get("confirm_password").map(|s| s.trim()).unwrap_or("");

    // --- Validation ---
    let mut error: Option<&str> = None;
    if password.is_empty() {
        error = Some("Admin password is required.");
    } else if password.len() < 8 {
        error = Some("Password must be at least 8 characters.");
    } else if password != confirm {
        error = Some("Passwords do not match.");
    }

    if let Some(msg) = error {
        let mut ctx = Context::new();
        ctx.insert("error_message", msg);
        return match tera.render("install.html", &ctx) {
            Ok(html) => Html(html).into_response(),
            Err(_)   => Html("<h1>Template error</h1>".to_string()).into_response(),
        };
    }

    // --- Initialise DB (creates all tables, seeds default admin with "admin" password) ---
    if let Err(e) = sqlx::query("PRAGMA foreign_keys = ON").execute(&pool).await {
        error!("install: PRAGMA error: {}", e);
    }

    if let Err(e) = initialize_database(&pool).await {
        error!("install: initialize_database failed: {}", e);
        let mut ctx = Context::new();
        ctx.insert("error_message", "Database initialisation failed. Check server logs.");
        return match tera.render("install.html", &ctx) {
            Ok(html) => Html(html).into_response(),
            Err(_)   => Html("<h1>Template error</h1>".to_string()).into_response(),
        };
    }

    // --- Create the admin user with the chosen password ---
    // Both bcrypt failure and INSERT failure are fatal: if the admin user cannot
    // be created the installation is incomplete.  Render the error page rather
    // than proceeding to set is_initialized = true with no usable admin account.
    let hashed = match hash(password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("install: bcrypt error: {}", e);
            let mut ctx = Context::new();
            ctx.insert("error_message", "Failed to hash password. Check server logs.");
            return match tera.render("install.html", &ctx) {
                Ok(html) => Html(html).into_response(),
                Err(_)   => Html("<h1>Template error</h1>".to_string()).into_response(),
            };
        }
    };

    if let Err(e) = sqlx::query(
        "INSERT OR IGNORE INTO users (id, tenant_id, username, password, name, email, role)
         VALUES (1, 'default', 'admin', ?, 'Admin User', 'admin@example.com', 'admin')"
    )
    .bind(hashed)
    .execute(&pool)
    .await
    {
        error!("install: failed to create admin user: {}", e);
        let mut ctx = Context::new();
        ctx.insert("error_message", "Failed to create admin user. Check server logs.");
        return match tera.render("install.html", &ctx) {
            Ok(html) => Html(html).into_response(),
            Err(_)   => Html("<h1>Template error</h1>".to_string()).into_response(),
        };
    }

    // --- Run migrations (fresh DB starts at v4, so this is effectively a no-op) ---
    if let Err(e) = run_migrations(&pool).await {
        error!("install: run_migrations failed: {}", e);
    }

    // --- Start background scheduler ---
    start_background_scheduler(pool).await;

    // --- Mark as initialised — only reached if admin user was created successfully ---
    is_initialized.store(true, Ordering::SeqCst);

    Redirect::to("/login").into_response()
}
