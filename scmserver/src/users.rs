use axum::response::{IntoResponse, Redirect};
use axum::extract::{RawForm, Extension, Query, Path, Form};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use tracing::{info, error};
use bytes::Bytes;
use bcrypt::{hash, DEFAULT_COST};
use serde::Deserialize;

use crate::models::{ErrorQuery, User, UserRole, AuthSession};
use crate::auth::{self};
use crate::handlers::{render_template, parse_form_data};


// ============================================================
// USERS
// ============================================================

pub async fn users(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let rows_result = sqlx::query(
        "SELECT id, username, role, name, email FROM users WHERE tenant_id = ? ORDER BY username",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let users: Vec<User> = match rows_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| User {
                id: row.get("id"),
                username: row.get("username"),
                role: row.get("role"),
                name: row.get("name"),
                email: row.get("email"),
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch users: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load users.");
            context.insert("users", &Vec::<User>::new());
            return render_template(&tera, Some(&pool), "users.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    context.insert("users", &users);
    render_template(&tera, Some(&pool), "users.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn users_add(
    Query(query): Query<ErrorQuery>,
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }

    render_template(&tera, Some(&pool), "users_add.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn users_add_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    let raw_string = match String::from_utf8(raw_form.0.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    // Validate required fields BEFORE opening a transaction
    let username = match form_data.get("username").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/users/add?error_message=Username+is+required").into_response(),
    };

    let password = match form_data.get("password").and_then(|v| v.first()).filter(|s| s.len() >= 8) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/users/add?error_message=Password+must+be+at+least+8+characters").into_response(),
    };

    let role_raw = match form_data.get("role").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
        Some(v) => v.to_string(),
        None => return Redirect::to("/users/add?error_message=Role+is+required").into_response(),
    };
    // Validate against known roles to prevent arbitrary strings being stored
    let role = match role_raw.to_lowercase().as_str() {
        "admin" | "editor" | "runner" | "viewer" => role_raw,
        _ => return Redirect::to("/users/add?error_message=Invalid+role+selected").into_response(),
    };

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    let name = form_data
        .get("name")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let email = form_data
        .get("email")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Check if username already exists within this tenant
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = ? AND tenant_id = ?)",
    )
    .bind(&username)
    .bind(&auth.tenant_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(false);

    if exists {
        tx.rollback().await.ok();
        let encoded = urlencoding::encode(&format!("User '{}' already exists", username)).to_string();
        return Redirect::to(&format!("/users/add?error_message={}", encoded)).into_response();
    }

    // Hash password
    let password_hash = match hash(&password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Failed to hash password: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    // Insert with tenant_id
    if let Err(e) = sqlx::query(
        "INSERT INTO users (tenant_id, name, email, username, password, role) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&email)
    .bind(&username)
    .bind(&password_hash)
    .bind(&role)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Failed to create user: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    info!("User '{}' created by '{}' (Tenant: {}).", username, auth.username, auth.tenant_id);
    Redirect::to("/users").into_response()
}


pub async fn users_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

    // Prevent self-deletion
    if auth.userid == id {
        return Redirect::to("/users?error_message=You+cannot+delete+your+own+account").into_response();
    }

    // Single row delete — no transaction needed
    if let Err(e) = sqlx::query("DELETE FROM users WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&*pool)
        .await
    {
        error!("Failed to delete user {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting user: {}", e)).to_string();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    info!("User ID {} deleted by '{}' (Tenant: {}).", id, auth.username, auth.tenant_id);
    Redirect::to("/users").into_response()
}


#[derive(serde::Deserialize)]
pub struct UserEditParams {
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}


pub async fn users_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(params): Query<UserEditParams>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    let current_role = UserRole::from(auth.role.as_str());
    let is_admin = current_role >= UserRole::Admin;
    let is_owner = auth.userid == id;

    if !is_admin && !is_owner {
        error!(
            attempted_by = %auth.username,
            user_id = %auth.userid,
            "Unauthorized user edit attempt"
        );
        return Redirect::to("/users?error_message=Unauthorized+edit+attempt").into_response();
    }

    let row_result = sqlx::query(
        "SELECT id, username, name, email, role FROM users WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/users?error_message=User+not+found").into_response(),
        Err(e) => {
            error!("Database error fetching user {}: {}", id, e);
            return Redirect::to("/users?error_message=Database+error").into_response();
        }
    };

    let user = User {
        id: row.try_get("id").unwrap_or(0),
        username: row.try_get("username").unwrap_or_default(),
        role: row.try_get("role").unwrap_or_default(),
        name: row.try_get("name").unwrap_or(None),
        email: row.try_get("email").unwrap_or(None),
    };

    let mut context = Context::new();
    if let Some(msg) = &params.error_message {
        context.insert("error_message", msg);
    }
    if let Some(msg) = &params.success_message {
        context.insert("success_message", msg);
    }
    context.insert("user", &user);
    render_template(&tera, Some(&pool), "users_edit.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn users_edit_save(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    let current_role = UserRole::from(auth.role.as_str());
    let is_admin = current_role >= UserRole::Admin;
    let is_owner = auth.userid == id;

    if !is_admin && !is_owner {
        error!(
            attempted_by = %auth.username,
            user_id = %auth.userid,
            "Unauthorized user edit attempt"
        );
        return Redirect::to("/users?error_message=Unauthorized+edit+attempt").into_response();
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded =
                urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    let name = form_data
        .get("name")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let email = form_data
        .get("email")
        .and_then(|v| v.first())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Only admins can change roles
    let role = if is_admin {
        match form_data.get("role").and_then(|v| v.first()).filter(|s| !s.trim().is_empty()) {
            Some(r) => r.to_string(),
            None => {
                tx.rollback().await.ok();
                return Redirect::to("/users?error_message=Role+is+required").into_response();
            }
        }
    } else {
        // Non-admins cannot change their own role — fetch current role from DB
        match sqlx::query_scalar::<_, String>(
            "SELECT role FROM users WHERE id = ? AND tenant_id = ?",
        )
        .bind(id)
        .bind(&auth.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(Some(r)) => r,
            _ => {
                tx.rollback().await.ok();
                return Redirect::to("/users?error_message=User+not+found").into_response();
            }
        }
    };

    if let Err(e) = sqlx::query(
        "UPDATE users SET name = ?, email = ?, role = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&name)
    .bind(&email)
    .bind(&role)
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error updating user: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/users?error_message={}", encoded)).into_response();
    }

    info!("User ID {} updated by '{}' (Tenant: {}).", id, auth.username, auth.tenant_id);

    let target = if is_admin { "/users" } else { "/" };
    Redirect::to(&format!("{}?success_message=Settings+saved+successfully", target)).into_response()
}


#[derive(Deserialize)]
pub struct ChangePasswordForm {
    pub password1: String,
    pub password2: String,
}


pub async fn change_password(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    Path(user_id): Path<i64>,
    Form(payload): Form<ChangePasswordForm>,
) -> impl IntoResponse {

    let current_role = UserRole::from(auth.role.as_str());
    let is_admin = current_role >= UserRole::Admin;
    let is_owner = auth.userid as i64 == user_id;

    if !is_admin && !is_owner {
        return Redirect::to("/users?error_message=Access+Denied").into_response();
    }

    // Validate passwords match
    if payload.password1 != payload.password2 {
        let encoded = urlencoding::encode("Passwords do not match").to_string();
        return Redirect::to(&format!(
            "/users/edit/{}?error_message={}",
            user_id, encoded
        ))
        .into_response();
    }

    // Validate password length
    if payload.password1.len() < 8 {
        let encoded = urlencoding::encode("Password must be at least 8 characters").to_string();
        return Redirect::to(&format!(
            "/users/edit/{}?error_message={}",
            user_id, encoded
        ))
        .into_response();
    }

    let hashed_password = match hash(&payload.password1, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password for user {}: {}", user_id, e);
            let encoded = urlencoding::encode("Encryption error").to_string();
            return Redirect::to(&format!(
                "/users/edit/{}?error_message={}",
                user_id, encoded
            ))
            .into_response();
        }
    };

    // Update with tenant filter
    match sqlx::query(
        "UPDATE users SET password = ? WHERE id = ? AND tenant_id = ?",
    )
    .bind(&hashed_password)
    .bind(user_id)
    .bind(&auth.tenant_id)
    .execute(&*pool)
    .await
    {
        Ok(_) => {
            info!(
                "Password changed for user ID {} by '{}' (Tenant: {}).",
                user_id, auth.username, auth.tenant_id
            );
            let encoded = urlencoding::encode("Password updated successfully").to_string();
            Redirect::to(&format!(
                "/users/edit/{}?success_message={}",
                user_id, encoded
            ))
            .into_response()
        }
        Err(e) => {
            error!("Failed to update password for user {}: {}", user_id, e);
            let encoded = urlencoding::encode("Database failure").to_string();
            Redirect::to(&format!(
                "/users/edit/{}?error_message={}",
                user_id, encoded
            ))
            .into_response()
        }
    }
}
