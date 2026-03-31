use axum::response::{Html, Redirect};
use axum::extract::{FromRequestParts, Query, Extension, Form};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use axum::http::request::Parts;
use axum::http::StatusCode;
use std::sync::Arc;
use std::future::Future;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use bcrypt::verify;
use serde::Deserialize;
use serde_json::{json, Value};
use tera::{Tera, Context};
use tracing::{info, warn, error};

use crate::models::ErrorQuery;
use crate::handlers::render_template;


// AuthSession
pub struct AuthSession {
    pub username: String,
    pub role: String,
}

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync + 'static,
{
    type Rejection = Redirect;

    fn from_request_parts<'a, 'b>(
        parts: &'a mut Parts,
        _state: &'b S,
    ) -> impl Future<Output = Result<Self, <Self as FromRequestParts<S>>::Rejection>> + Send {
        async move {
            let jar = CookieJar::from_headers(&parts.headers);

            if let Some(cookie) = jar.get("session") {
                info!("AuthSession: found session cookie: {}", cookie.value());

                if let Ok(session_json) = serde_json::from_str::<Value>(cookie.value()) {
                    if let (Some(username), Some(role)) = (
                        session_json.get("username").and_then(|v| v.as_str()),
                        session_json.get("role").and_then(|v| v.as_str()),
                    ) {
                        return Ok(AuthSession {
                            username: username.to_string(),
                            role: role.to_string(),
                        });
                    }
                }

                warn!("AuthSession: malformed session data");
            } else {
                warn!("AuthSession: no session cookie found, redirecting to login.");
            }

            Err(Redirect::to("/login"))
        }
    }
}


#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

// login
pub async fn login(Query(query): Query<ErrorQuery>, tera: Extension<Arc<Tera>>) 
                                 -> Result<Html<String>, StatusCode> {
    let mut context = Context::new();
    let auth = AuthSession {
            username: "".to_string(),
            role: "".to_string(),
        };
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
        warn!("Login page rendered with error: {}", error_message);
    } else {
        info!("Login page rendered.");
    }
    render_template(&tera, None, "login.html",context, None).await
}

// login_submit
pub async fn login_submit(
    jar: CookieJar,
    Extension(pool): Extension<SqlitePool>,
    Form(form): Form<LoginForm>,
) -> (CookieJar, Redirect) {
    info!("Login attempt: {}", form.username);

    let row = sqlx::query("SELECT id, username, password, role FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(&pool)
        .await;

    let row = match row {
        Ok(row) => row,
        Err(e) => {
            error!("Database query failed: {}", e);
            return (jar, Redirect::to("/login?error_message=Internal%20Server%20Error"));
        }
    };

    if let Some(row) = row {
        let password_hash: String = row.get("password");
        let username: String = row.get("username");
        let role: String = row.get("role");

        info!("User '{}' found in DB, verifying password...", username);

        if verify(&form.password, &password_hash).unwrap_or(false) {
            info!("Password verified for user '{}'", username);

            let session_data = json!({
                "username": username,
                "role": role,
            })
            .to_string();

            let mut cookie = Cookie::new("session", session_data);
            cookie.set_path("/");
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Lax);

            let updated_jar = jar.add(cookie);
            return (updated_jar, Redirect::to("/"));
        } else {
            warn!("Invalid password for user '{}'", username);
        }
    } else {
        warn!("Login failed: no such user '{}'", form.username);
    }
   
    // add notification 
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let message = format!("user {} failed authentication", form.username);

    if let Err(e) = sqlx::query("INSERT INTO notify (type, timestamp, message) VALUES (?, ?, ?)")
                    .bind("auth") // notification type
                    .bind(now)    // timestamp
                    .bind(message) // message
                    .execute(&pool)
                    .await
                    {
                        error!("Failed to insert notification: {}", e);
                    }

    (jar, Redirect::to("/login?error_message=Invalid%20Credentials"))
}

// logout
pub async fn logout(jar: CookieJar) -> (CookieJar, Redirect) {
    if let Some(cookie) = jar.get("session") {
        let session_id = cookie.value().to_string();
        info!("Logging out session: {}", session_id);
    } else {
        warn!("Logout: no session cookie found");
    }

    let updated_jar = jar.remove(Cookie::from("session"));
    (updated_jar, Redirect::to("/login"))
}
