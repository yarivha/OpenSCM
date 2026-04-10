use axum::response::{Html, IntoResponse, Redirect};
use axum::http::StatusCode;
use axum::extract::{RawForm, Extension, Query, Path};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use std::str::FromStr;
use urlencoding;
use tracing::error;
use bytes::Bytes;
use bcrypt::{hash, DEFAULT_COST};

use crate::models::ErrorQuery;
use crate::models::User;
use crate::auth::{self, UserRole, AuthSession};
use crate::handlers::render_template;
use crate::handlers::parse_form_data;



// users
pub async fn users(auth: AuthSession, Query(query): Query<ErrorQuery>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
 ->  impl IntoResponse {
    
     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }

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
    render_template(&tera,Some(&pool), "users.html", context, Some(auth)).await.into_response()
}



// users_add
pub async fn users_add(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>)
    -> impl IntoResponse { 
    
    // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }


    let context = Context::new();
    render_template(&tera,Some(&pool), "users_add.html", context, Some(auth)).await.into_response()
}



// users_add_save
pub async fn users_add_save(auth: AuthSession, pool: Extension<SqlitePool>, raw_form: RawForm) 
    -> impl IntoResponse {
    
    // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }


    // Start transaction
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
        }
    };


    // Convert bytes to string
    let raw_string = match String::from_utf8(raw_form.0.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
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
            return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
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
        return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
    }

    // Commit transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Database error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
    }

    Redirect::to("/users").into_response()
}



// users_delete
pub async fn users_delete(auth: AuthSession, Path(id): Path<i32>, pool: Extension<SqlitePool>) 
    -> impl IntoResponse {
        
    // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Admin) {
        return redir;
    }


    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
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
        return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
    }

    // Commit the transaction if all queries were successful
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error committing transaction: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
    }
    
    Redirect::to("/users").into_response() 
}   



pub async fn users_edit(auth: AuthSession, Path(id): Path<i32>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>)
    -> impl IntoResponse {

    let current_role = UserRole::from(auth.role.as_str());

    let is_admin = current_role >= UserRole::Admin;
    let is_owner = auth.userid == id;

    if !is_admin && !is_owner {
        error!(
            attempted_by = %auth.username, 
            user_id = %auth.userid, 
            "Unauthorized edit attempt"
        );
        // Redirect them away or return a 403 Forbidden
        return Redirect::to("/users?error_message=Unauthorized+edit+attempt").into_response();
    }


    let row_result = sqlx::query("
        SELECT id, username, name, email, role 
        FROM users 
        WHERE id = ? 
    ")
    .bind(id)
    .fetch_optional(&*pool)
    .await;

    // Handle potential Database Errors AND missing rows
    let row = match row_result {
        Ok(Some(r)) => r, // We found the user
        Ok(None) => {     // The query worked, but no user found
            return Redirect::to("/users?error_message=User+not+found").into_response();
        }
        Err(e) => {      // Database error (connection lost, etc.)
            error!("Database error: {}", e);
            return Redirect::to("/users?error_message=Database+error").into_response();
        }
    };


    let user = User {
            id: row.try_get("id").unwrap(),
            username: row.try_get("username").unwrap(),
            role: row.try_get("role").unwrap(),
            name: row.try_get("name").unwrap(),
            email: row.try_get("email").unwrap(),
        };



    let mut context = Context::new();
    context.insert("user", &user);
    render_template(&tera,Some(&pool), "users_edit.html", context, Some(auth)).await.into_response()
}




// system_edit_save
pub async fn users_edit_save(auth: AuthSession, Path(id): Path<i32>,pool: Extension<SqlitePool>, raw_form: RawForm) -> impl IntoResponse {
    
     let current_role = UserRole::from(auth.role.as_str());
            
    let is_admin = current_role >= UserRole::Admin;
    let is_owner = auth.userid == id;
        
    if !is_admin && !is_owner {
        error!(
            attempted_by = %auth.username,
            user_id = %auth.userid, 
            "Unauthorized edit attempt"
        );
        // Redirect them away or return a 403 Forbidden
        return Redirect::to("/users?error_message=Unauthorized+edit+attempt").into_response();
    }



     let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // Extract name and description (with error handling)
    let name = form_data.get("name").and_then(|v| v.first()).map(|s| s.to_string());
    let email = form_data.get("email").and_then(|v| v.first()).map(|s| s.to_string());
    let role = form_data.get("role").and_then(|v| v.first()).map(|s| s.to_string());

    // Update system
    let update_system_result = sqlx::query(
        "UPDATE users SET name=?, email=?, role=?  WHERE id=?"
    )
    .bind(name.as_ref().unwrap()) // Unwrap after checking for None
    .bind(email.as_ref().unwrap()) // Unwrap after checking for None
    .bind(role.as_ref().unwrap())
    .bind(id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = update_system_result {
        let error_message = format!("Error updating user: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok();
        return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
    }


    // Commit the transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/users?error_message={}", encoded_message)).into_response();
    }


    let target_url = if current_role >= UserRole::Admin {
        "/users"
    } else {
        "/"
    };

    let redirect_path = format!("{}?success_message=Settings+saved+successfully", target_url);
    Redirect::to(&redirect_path).into_response()
}



