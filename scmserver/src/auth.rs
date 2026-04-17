use axum::response::{Html, Redirect, IntoResponse, Response};
use axum::extract::{FromRef, FromRequestParts, Query, Extension, Form};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar, Key};
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

use crate::handlers::{render_template, add_notification};
use crate::models::{UserRole, ErrorQuery, AuthSession};


/// Checks if the current role meets the required level.
/// Returns None if authorized, or a Redirect if unauthorized.
pub fn authorize(current_role: &str, required: UserRole) -> Option<Response> {
    let user_level = UserRole::from(current_role);
    
    if user_level >= required {
        None
    } else {
        warn!("Unauthorized access attempt: Required {:?}, User has {}", required, current_role);
        let msg = format!("Unauthorized+access.+{:?}+role+required.", required);
        Some(Redirect::to(&format!("/?error_message={}", msg)).into_response())
    }
}



impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync + 'static,
    Key: FromRef<S>, 
{
    type Rejection = Redirect;

    fn from_request_parts<'a, 'b>(
        parts: &'a mut Parts,
        state: &'b S, 
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let key = Key::from_ref(state);

        async move {
            let jar = SignedCookieJar::from_headers(&parts.headers, key);

            if let Some(cookie) = jar.get("session") {
                if let Ok(session_json) = serde_json::from_str::<Value>(cookie.value()) {
                    if let (Some(username), Some(userid_str), Some(tenant_id), Some(role)) = (
                        session_json.get("username").and_then(|v| v.as_str()),
                        session_json.get("userid").and_then(|v| v.as_str()),
                        session_json.get("tenant_id").and_then(|v| v.as_str()),
                        session_json.get("role").and_then(|v| v.as_str()),
                    ) {
                        let userid = match userid_str.parse::<i32>() {
                             Ok(id) => id,
                            Err(_) => return Err(Redirect::to("/login")),
                        };
                       

                        return Ok(AuthSession {
                            username: username.to_string(),
                            userid, 
                            tenant_id: tenant_id.to_string(),
                            role: role.to_string(),
                        });
                    }
                }
            }

            // If anything fails (no cookie, bad signature, missing fields), redirect to login
            Err(Redirect::to("/login"))
        }
    }
}


// --- 4. HANDLERS ---

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

// login
pub async fn login(Query(query): Query<ErrorQuery>, tera: Extension<Arc<Tera>>) -> Result<Html<String>, StatusCode> {
    let mut context = Context::new();
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    render_template(&tera, None, "login.html", context, None).await
}



// login_submit
pub async fn login_submit(
    jar: SignedCookieJar,           
    Extension(pool): Extension<SqlitePool>,
    Form(form): Form<LoginForm>,
) -> (SignedCookieJar, Redirect) {

    // Guard against empty credentials
    if form.username.is_empty() || form.password.is_empty() {
        return (jar, Redirect::to("/login?error_message=Invalid%20Credentials"));
    }

    let row = sqlx::query("SELECT password, username, id, tenant_id, role FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(&pool)
        .await;

    // Timing attack protection — always run bcrypt regardless of whether user exists
    const DUMMY_HASH: &str = "$2b$12$invalidhashfortimingprotectionXXXXXXXXXXXXXXXXXXXXXX";

    let (hash_to_check, maybe_row) = match row {
        Ok(Some(row)) => {
            let hash: String = row.get("password");
            (hash, Some(row))
        },
        Ok(None) => {
            warn!("Login attempt for non-existent user: '{}'", form.username);
            (DUMMY_HASH.to_string(), None)
        },
        Err(e) => {
            error!("Database error during login: {}", e);
            (DUMMY_HASH.to_string(), None)
        },
    };

    let password_valid = verify(&form.password, &hash_to_check).unwrap_or(false);

    if password_valid {
        if let Some(row) = maybe_row {
            let username: String = row.get("username");
            let userid_raw: i32 = row.get("id");
            let role: String = row.get("role");

            let tenant_id: String = row.try_get::<String, _>("tenant_id")
                .unwrap_or_else(|_| "default".to_string());

            // Treat invalid userid as auth failure instead of defaulting to 0
            let userid = match userid_raw.to_string().parse::<i32>() {
                Ok(id) => id,
                Err(_) => {
                    error!("Invalid userid in database for user: '{}'", username);
                    return (jar, Redirect::to("/login?error_message=Invalid%20Credentials"));
                }
            };

            let session_data = json!({
                "username": username,
                "userid": userid.to_string(),
                "tenant_id": tenant_id,
                "role": role
            }).to_string();

            let mut cookie = Cookie::new("session", session_data);
            cookie.set_path("/");
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Lax);
            cookie.set_max_age(time::Duration::hours(8));

            info!("User '{}' logged in successfully for tenant '{}'", username, tenant_id);
            return (jar.add(cookie), Redirect::to("/"));
        }
    } else {
        warn!("Failed login attempt for user: '{}'", form.username);

        // If user exists but password was wrong, notify them
        if let Some(row) = maybe_row {
            let userid_raw: i32 = row.get("id");
            let tenant_id: String = row.try_get::<String, _>("tenant_id")
                .unwrap_or_else(|_| "default".to_string());

            add_notification(
                &pool,
                &tenant_id,
                "warning",
                userid_raw,
                &format!("Failed login attempt for user '{}'", form.username),
            ).await;
        }


    }

    (jar, Redirect::to("/login?error_message=Invalid%20Credentials"))
}




// logout
pub async fn logout(jar: SignedCookieJar) -> (SignedCookieJar, Redirect) {
    (jar.remove(Cookie::from("session")), Redirect::to("/login"))
}

