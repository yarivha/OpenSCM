use axum::response::{Html, Redirect, IntoResponse, Response};
use axum::extract::{FromRef, FromRequestParts, Query, Extension, Form};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite, SignedCookieJar, Key};
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
use tracing::{debug, info, warn, error};

use crate::models::ErrorQuery;
use crate::handlers::render_template;
use crate::models::UserRole;


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

// --- 3. SESSION HANDLING ---

pub struct AuthSession {
    pub username: String,
    pub userid: i32,
    pub tenant_id: String,
    pub role: String,
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
                    // --- THE FIX: We match 4 items on the left to match the 4 on the right ---
                    if let (Some(username), Some(userid), Some(tenant_id), Some(role)) = (
                        session_json.get("username").and_then(|v| v.as_str()),
                        session_json.get("userid").and_then(|v| v.as_str()),
                        session_json.get("tenant_id").and_then(|v| v.as_str()),
                        session_json.get("role").and_then(|v| v.as_str()),
                    ) {
                        return Ok(AuthSession {
                            username: username.to_string(),
                            // Parsing to i32 since that's what your struct now expects
                            userid: userid.parse::<i32>().unwrap_or(0),
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

pub async fn login(Query(query): Query<ErrorQuery>, tera: Extension<Arc<Tera>>) -> Result<Html<String>, StatusCode> {
    let mut context = Context::new();
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    render_template(&tera, None, "login.html", context, None).await
}




pub async fn login_submit(
    jar: SignedCookieJar,           
    Extension(pool): Extension<SqlitePool>,
    Form(form): Form<LoginForm>,
) -> (SignedCookieJar, Redirect) {

    let row = sqlx::query("SELECT password, username, id, tenant_id, role FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(&pool)
        .await;

    // 1. Check if the database query succeeded AND found a user
    if let Ok(Some(row)) = row {
        let password_hash: String = row.get("password");
        
        // 2. Verify the password first
        if verify(&form.password, &password_hash).unwrap_or(false) {
            let username: String = row.get("username");
            let userid_raw: i32 = row.get("id");
            let role: String = row.get("role");

            // 3. SAFE TENANT RETRIEVAL
            // If the DB column is NULL, we map it to "default" to stay 
            // consistent with our binary signature logic.
            let tenant_id: String = row.try_get::<String, _>("tenant_id")
                .unwrap_or_else(|_| "default".to_string());

            let userid = userid_raw.to_string();
            
            // 4. Create the session payload
            let session_data = json!({ 
                "username": username, 
                "userid": userid,  
                "tenant_id": tenant_id,
                "role": role 
            }).to_string();

            let mut cookie = Cookie::new("session", session_data);
            cookie.set_path("/");
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Lax);

            info!("User {} logged in successfully for tenant {}", username, tenant_id);
            return (jar.add(cookie), Redirect::to("/"));
        }
    } 
    
    (jar, Redirect::to("/login?error_message=Invalid%20Credentials"))
}



// logout
pub async fn logout(jar: CookieJar) -> (CookieJar, Redirect) {
    (jar.remove(Cookie::from("session")), Redirect::to("/login"))
}
