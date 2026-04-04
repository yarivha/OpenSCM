use axum::response::{Html, Response, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{RawForm, Extension, Query, Path};
use http_body_util::Full;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use std::collections::{HashMap, BTreeMap};
use urlencoding::decode;
use tracing::error;
use bytes::Bytes;
use bcrypt::{hash, DEFAULT_COST};
use chrono::Local;

use crate::models::ErrorQuery;
use crate::models::Notification;
use crate::models::User;
use crate::models::System;
use crate::models::SystemGroup;
use crate::models::SystemInsideGroup;
use crate::models::Test;
use crate::models::Policy;
use crate::models::SystemInsidePolicy;
use crate::models::TestInsidePolicy;
use crate::models::SystemCompliance;
use crate::models::PolicyCompliance;
use crate::models::Element;
use crate::models::SElement;
use crate::models::Condition;
use crate::models::ReportData;
use crate::models::TestMeta;
use crate::models::SystemReport;
use crate::models::IndividualResult;
use crate::auth::AuthSession;
use crate::handlers::render_template;
use crate::handlers::parse_form_data;
use crate::handlers::not_found;



//////////////////// Settings /////////////////////////
 

// users
pub async fn users(auth: AuthSession, Query(query): Query<ErrorQuery>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
 -> Result<Html<String>, StatusCode> {
    // Fetch users from the database
    let rows = sqlx::query("SELECT id, username, role, name, email FROM users")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let users: Vec<User> = rows.into_iter().map(|row| {
        User {
            id: row.get("id"),
            username: row.get("username"),
            role: row.get("role"),
            name: row.get("name"),
            email: row.get("email"),
        }
    }).collect();

    // Prepare handler-specific context
    let mut context = Context::new();
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }

    context.insert("users", &users);

    // Use the generic render function to render the template with global data
    render_template(&tera,Some(&pool), "users.html", context, Some(auth)).await
}



// users_add
pub async fn users_add(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>)
    -> Result<Html<String>, StatusCode> {
    let context = Context::new();
    render_template(&tera,Some(&pool), "users_add.html", context, Some(auth)).await
}



// users_add_save
pub async fn users_add_save(auth: AuthSession, pool: Extension<SqlitePool>, raw_form: RawForm) -> Redirect {
    // Start transaction
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message));
        }
    };


    // Convert bytes to string
    let raw_string = match String::from_utf8(raw_form.0.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message));
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // Extract name and description (with error handling)
    let name = form_data.get("name").and_then(|v| v.first()).map(|s| s.to_string());
    let email = form_data.get("email").and_then(|v| v.first()).map(|s| s.to_string());
    let username = form_data.get("username").and_then(|v| v.first()).map(|s| s.to_string());
    let password = form_data.get("password").and_then(|v| v.first()).map(|s| s.to_string());
    let role = form_data.get("role").and_then(|v| v.first()).map(|s| s.to_string());



    // Hash password
    let password_hash = match hash(&password.clone().unwrap(), DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            let error_message = format!("Failed to hash password: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message));
        }
    };


    // Insert into DB using transaction
    let result = sqlx::query(
        "INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(name.as_ref().unwrap(), ) // Unwrap after checking for None
    .bind(email.as_ref().unwrap(), ) // Unwrap after checking for None
    .bind(username.as_ref().unwrap(), ) // Unwrap after checking for None
    .bind(password_hash)  
    .bind(role.as_ref().unwrap()) // Unwrap after checking for None
    .execute(&mut *tx)
    .await;

    // Check for insert error
    if let Err(e) = result {
        let error_message = format!("Database insert error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/users?error_message={}", encoded_message));
    }

    // Commit transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Database error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/users?error_message={}", encoded_message));
    }

    Redirect::to("/users")
}



// users_delete
pub async fn users_delete(auth: AuthSession, Path(id): Path<i32>, pool: Extension<SqlitePool>) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message));
        }
    };

    // delete the user
    let delete_user_result = sqlx::query(
        "DELETE FROM users WHERE id=?"
    )
    .bind(&id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = delete_user_result {
        let error_message = format!("Error deleting user: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); // Ensure the transaction is rolled back
        return Redirect::to(&format!("/users?error_message={}", encoded_message));
    }

    // Commit the transaction if all queries were successful
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error committing transaction: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/users?error_message={}", encoded_message));
    }
    
    Redirect::to("/users") 
}   


////////////////////////////////////////////////////////////////////





