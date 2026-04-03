use axum::response::{Html, Response, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{RawForm, Extension, Query, Path};
use http_body_util::Full;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use std::collections::HashMap;
use urlencoding::decode;
use tracing::error;
use bytes::Bytes;
use bcrypt::{hash, DEFAULT_COST};

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
use crate::auth::AuthSession;



//////////////////////////////// Helper Functions ///////////////////////////////////
pub async fn render_template(
    tera: &Tera,
    pool: Option<&SqlitePool>,
    template_name: &str,
    mut context: Context,
    auth: Option<AuthSession>,
) -> Result<Html<String>, StatusCode> {
    // Add common context values
    context.insert("version", env!("CARGO_PKG_VERSION"));
    if let Some(auth) = auth {
        context.insert("username", &auth.username);
        context.insert("role", &auth.role);
    }

    if let Some(pool) = pool {
        
        // Add notify count
        let notify_row = sqlx::query("SELECT COUNT(*) as count FROM notify")
                  .fetch_one(pool)
                  .await
                  .map_err(|e| {
                    error!("DB error getting notify count: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                  })?;

        let notify_count: i64 = notify_row.get("count");
        context.insert("notify_count", &notify_count);

        // Add notify list
        let notifications = sqlx::query("SELECT id, type, timestamp, message FROM notify ORDER BY timestamp DESC LIMIT 10")
            .map(|row: sqlx::sqlite::SqliteRow| Notification {
                id: row.get("id"),
                r#type: row.get("type"),
                timestamp: row.get("timestamp"),
                message: row.get("message"),
            })
            .fetch_all(pool)
            .await
            .map_err(|e| {
                error!("Failed to fetch notifications: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        context.insert("notifications", &notifications);

        // Add pending registrations count 
        let pending_row = sqlx::query("SELECT COUNT(*) as count FROM systems WHERE status = 'pending'")
                  .fetch_one(pool)
                  .await
                  .map_err(|e| {
                    error!("DB error getting pending count: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                  })?;

        let pending_count: i64 = pending_row.get("count");
        context.insert("pending_count", &pending_count);
    }
    // Render template
    let rendered = tera.render(template_name, &context).map_err(|e| {
        error!("Template render error ({}): {}", template_name, e);
        StatusCode::INTERNAL_SERVER_ERROR

    })?;

    Ok(Html(rendered))
}


// Helper function to parse URL-encoded form data
fn parse_form_data(raw_string: &str) -> HashMap<String, Vec<String>> {
    let mut form_data: HashMap<String, Vec<String>> = HashMap::new();
    
    for pair in raw_string.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            // Replace '+' with spaces before decoding
            let key = key.replace('+', " ");
            let value = value.replace('+', " ");

            // Decode percent-encoded values safely
            let key_decoded = decode(&key)
                .unwrap_or_else(|_| key.clone().into())
                .to_string();
            let value_decoded = decode(&value)
                .unwrap_or_else(|_| value.clone().into())
                .to_string();

            form_data
                .entry(key_decoded)
                .or_insert_with(Vec::new)
                .push(value_decoded);
        }
    }

    form_data
}



pub async fn not_found() -> impl IntoResponse {
    // Body content
    let body = "404 - Not Found";

    // Build the response
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Full::from(body))  // Use Full or Boxed body type
        .unwrap()
}


/////////////////////////////////// Handlers Functions /////////////////////////////////

// dashboard
pub async fn dashboard(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
    -> Result<Html<String>, StatusCode> {

    let mut context = Context::new();
    
    // Get systems count
    let systems_count_row = sqlx::query("SELECT COUNT(*) as count FROM systems WHERE status= 'active'")
        .fetch_one(&*pool)
        .await
        .unwrap();
    
    let systems_count: i64 = systems_count_row.get("count");
    

    // Get policies count
    let policies_count_row = sqlx::query("SELECT COUNT(*) as count FROM policies")
        .fetch_one(&*pool)
        .await
        .unwrap();

    let policies_count: i64 = policies_count_row.get("count");

    // Get Top failed systems
    let rows = sqlx::query(r#"
        SELECT
            s.name AS system_name,
            s.os,

            CASE 
                WHEN COUNT(r.test_id) = 0 THEN 0.0 -- Using 0.0 to keep sqlx happy (f64)
                ELSE ROUND(
                    (SUM(CASE WHEN r.result = 'true' THEN 1 ELSE 0 END) * 100.0) 
                    / COUNT(r.test_id),
                    2)
            END AS compliance,

            COALESCE(SUM(CASE WHEN r.result = 'true' THEN 1 ELSE 0 END), 0) AS passed_tests,
            COALESCE(SUM(CASE WHEN r.result = 'false' THEN 1 ELSE 0 END), 0) AS failed_tests

        FROM systems s
        JOIN results r ON s.id = r.system_id

        GROUP BY s.id, s.name, s.os

        ORDER BY compliance ASC
        LIMIT 5
    "#)
    .fetch_all(&*pool)
    .await
    .map_err(|e| {
        error!("Systems stats DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let top_failed_systems: Vec<SystemCompliance> = rows.into_iter().map(|row| {
        SystemCompliance {
            system_name: row.get::<String, _>("system_name"),
            os: row.get::<String, _>("os"),
            compliance: row.get::<f64, _>("compliance"),
            passed_tests: row.get::<i64, _>("passed_tests"),
            failed_tests: row.get::<i64, _>("failed_tests"),
        }
    }).collect();


  

    // Get Top failed policies
    let rows = sqlx::query(r#"
        SELECT
            p.id AS policy_id,
            p.name AS policy_name,
            p.version AS policy_version,
            ROUND(
                SUM(CASE WHEN system_status = 'passed' THEN 1 ELSE 0 END) * 100.0
                / COUNT(*),
                2
            ) AS compliance,
            SUM(CASE WHEN system_status = 'passed' THEN 1 ELSE 0 END) AS passed_systems,
            SUM(CASE WHEN system_status = 'failed' THEN 1 ELSE 0 END) AS failed_systems
        FROM (
            SELECT
                tip.policy_id,
                r.system_id,
                CASE
                    WHEN SUM(CASE WHEN r.result = 'false' THEN 1 ELSE 0 END) > 0
                        THEN 'failed'
                    ELSE 'passed'
                END AS system_status
            FROM tests_in_policy tip
            JOIN results r ON r.test_id = tip.test_id
            GROUP BY tip.policy_id, r.system_id
        ) AS system_results
        JOIN policies p ON p.id = system_results.policy_id
        GROUP BY p.id, p.name, p.version
        ORDER BY compliance ASC
        LIMIT 5
    "#)
    .fetch_all(&*pool)
    .await
    .map_err(|e| {
        error!("Dashboard stats DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    
    let top_failed_policies: Vec<PolicyCompliance> = rows.into_iter().map(|row| {
        PolicyCompliance {
            policy_id: row.get::<i64, _>("policy_id"),
            policy_name: row.get::<String, _>("policy_name"),
            policy_version: row.get::<String, _>("policy_version"),
            policy_description: None,
            compliance: row.get::<f64, _>("compliance"),
            passed_systems: Some(row.get::<i64, _>("passed_systems")),
            failed_systems: Some(row.get::<i64, _>("failed_systems")),
        }
    }).collect();



    context.insert("systems_count", &systems_count.to_string());
    context.insert("policies_count", &policies_count.to_string());
    context.insert("top_failed_systems", &top_failed_systems); 
    context.insert("top_failed_policies", &top_failed_policies);
    render_template(&tera,Some(&pool), "dashboard.html", context, Some(auth)).await
}



////////////////////////// Inventory //////////////////////////////


// systems
pub async fn systems(
    auth: AuthSession,
    Query(params): Query<HashMap<String, String>>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {
    let filter = params.get("filter").map(|s| s.to_lowercase());

    let rows = match filter.as_deref() {
        Some("active") | Some("pending") => {
            sqlx::query(
                r#"
                SELECT
                    s.id AS system_id,
                    COALESCE(s.name, 'NA') AS system_name,
                    COALESCE(s.ver, 'NA') AS system_ver,
                    COALESCE(s.ip, 'NA') AS system_ip,
                    COALESCE(s.os, 'NA') AS system_os,
                    COALESCE(s.arch, 'NA') AS system_arch,
                    COALESCE(s.status, 'NA') AS system_status,
                    COALESCE(GROUP_CONCAT(sg.name), 'none') AS group_names,
                    COALESCE(s.created_date, '') AS created_date,
                    COALESCE(s.last_seen, '') AS last_seen
                FROM
                    systems AS s
                LEFT JOIN
                    systems_in_groups AS sig ON s.id = sig.system_id
                LEFT JOIN
                    system_groups AS sg ON sig.group_id = sg.id
                WHERE
                    s.status = ?
                GROUP BY
                    s.id
                ORDER BY
                    CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END,
                    s.id ASC
                "#
            )
            .bind(filter.unwrap())
            .fetch_all(&pool)
            .await
            .unwrap()
        }
        _ => {
            sqlx::query(
                r#"
                SELECT
                    s.id AS system_id,
                    COALESCE(s.name, 'NA') AS system_name,
                    COALESCE(s.ver, 'NA') AS system_ver,
                    COALESCE(s.ip, 'NA') AS system_ip,
                    COALESCE(s.os, 'NA') AS system_os,
                    COALESCE(s.arch, 'NA') AS system_arch,
                    COALESCE(s.status, 'NA') AS system_status,
                    COALESCE(GROUP_CONCAT(sg.name), 'none') AS group_names,
                    COALESCE(s.created_date, '') AS created_date,
                    COALESCE(s.last_seen, '') AS last_seen
                FROM
                    systems AS s
                LEFT JOIN
                    systems_in_groups AS sig ON s.id = sig.system_id
                LEFT JOIN
                    system_groups AS sg ON sig.group_id = sg.id
                GROUP BY
                    s.id
                ORDER BY
                    CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END,
                    s.id ASC
                "#
            )
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };

    let systems: Vec<System> = rows
        .into_iter()
        .map(|row| System {
            id: row.try_get("system_id").unwrap(),
            name: row.try_get("system_name").unwrap(),
            ver: row.try_get("system_ver").unwrap(),
            ip: row.try_get("system_ip").unwrap(),
            os: row.try_get("system_os").unwrap(),
            arch: row.try_get("system_arch").unwrap(),
            status: row.try_get("system_status").unwrap(),
            groups: row.try_get("group_names").unwrap(),
            auth_signature: None,
            auth_public_key: None,
            trust_challenge: None,
            trust_proof: None,
            created_date: row.try_get("created_date").unwrap(),
            last_seen: row.try_get("last_seen").unwrap(),
        })
        .collect();

    let mut context = Context::new();
    if let Some(error_message) = params.get("error_message") {
        context.insert("error_message", error_message);
    }
    context.insert("systems", &systems);
    render_template(&tera, Some(&pool), "systems.html", context, Some(auth)).await
}

// systems_approve
pub async fn systems_approve(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> Redirect {
    // Attempt to update the system status
    if let Err(e) = sqlx::query("UPDATE systems SET status = 'active' WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
    {
        let error_message = format!("Error approving system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/systems?error_message={}", encoded_message));
    }

    // Success: redirect back to systems page
    Redirect::to("/systems")
}



// systems_delete
pub async fn systems_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> Redirect {
    // Attempt to delete the system
    if let Err(e) = sqlx::query("DELETE FROM systems WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
    {
        let error_message = format!("Error deleting system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/systems?error_message={}", encoded_message));
    }

    // Success: redirect back to systems page
    Redirect::to("/systems")
}


// systems_edit
pub async fn systems_edit(auth: AuthSession, Path(id): Path<i32>,pool: Extension<SqlitePool>,tera: Extension<Arc<Tera>>) -> impl IntoResponse  {

    // capture system
    let row = sqlx::query("
                SELECT id,name,ver,ip,os,arch,status from systems where id=?")
    .bind(id)
    .fetch_one(&*pool)
    .await
    .unwrap();

    let system = System {
            id: row.try_get("id").unwrap(),
            name: row.try_get("name").unwrap(),
            ver: row.try_get("ver").unwrap(),
            ip: row.try_get("ip").unwrap(),
            os: row.try_get("os").unwrap(),
            arch: row.try_get("arch").unwrap(),
            status: row.try_get("status").unwrap(),
            groups: None,
            auth_signature: None,
            auth_public_key: None,
            trust_challenge: None,
            trust_proof: None,
            created_date: None,
            last_seen: None
        };
    
    // capture groups list
    let rows = sqlx::query("
         SELECT
                sg.id AS group_id,
                sg.name AS group_name,
                sg.description AS group_description
            FROM
                system_groups AS sg
        ")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let groups: Vec<SystemGroup> = rows.into_iter().map(|row| {
        SystemGroup {
            id: row.get("group_id"),
            name: row.get("group_name"),
            description: row.get("group_description"),
            systems: None,
        }
    }).collect();
    

    // capture groups that has the system 
    let rows = sqlx::query("
         SELECT system_id,group_id from systems_in_groups where system_id=?")
        .bind(id)
        .fetch_all(&*pool)
        .await
        .unwrap();

    let systems_in_groups: Vec<SystemInsideGroup> = rows.into_iter().map(|row| {
        SystemInsideGroup {
            system_id: row.get("system_id"),
            group_id: row.get("group_id"),
        }
    }).collect();

    let mut context = Context::new();
    context.insert("system", &system);
    context.insert("groups", &groups);
    context.insert("systems_in_groups", &systems_in_groups);
    render_template(&tera, Some(&pool), "systems_edit.html",context, Some(auth)).await
}

// system_edit_save
pub async fn systems_edit_save(auth: AuthSession, Path(id): Path<i32>,pool: Extension<SqlitePool>, raw_form: RawForm) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/systems?error_message={}", encoded_message));
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/systems?error_message={}", encoded_message));
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // Extract name and description (with error handling)
    let name = form_data.get("name").and_then(|v| v.first()).map(|s| s.to_string());
    let ip = form_data.get("ip").and_then(|v| v.first()).map(|s| s.to_string());
    let os = form_data.get("os").and_then(|v| v.first()).map(|s| s.to_string());
    let arch = form_data.get("arch").and_then(|v| v.first()).map(|s| s.to_string());
    let groups: Option<Vec<String>> = form_data.get("groups").cloned();

    // Update system
    let update_system_result = sqlx::query(
        "UPDATE systems SET name=?, ip=?, os=?, arch=?  WHERE id=?"
    )
    .bind(name.as_ref().unwrap()) // Unwrap after checking for None
    .bind(ip.as_ref().unwrap()) // Unwrap after checking for None
    .bind(os.as_ref().unwrap())
    .bind(arch.as_ref().unwrap())
    .bind(id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = update_system_result { 
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); 
        return Redirect::to(&format!("/systems?error_message={}", encoded_message));
    }

    // Remove all related groups
    let remove_related_groups = sqlx::query(
        "DELETE FROM systems_in_groups WHERE system_id=?"
    )
    .bind(id) 
    .execute(&mut *tx)
    .await;

    if let Err(e) = remove_related_groups
    {
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok();
        return Redirect::to(&format!("/systems?error_message={}", encoded_message));
    }


    // Assign selected group
    if let Some(groups) = groups {
        for group_id_str in groups {
            if let Ok(group_id) = group_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT INTO systems_in_groups (system_id, group_id) VALUES (?, ?)"
                )
                .bind(id)
                .bind(group_id)
                .execute(&mut *tx)
                .await
                {
                    let error_message = format!("Error updating system: {}", e);
                    let encoded_message = urlencoding::encode(&error_message);
                    return Redirect::to(&format!("/systems?error_message={}", encoded_message));
                }
            }   
        }
    }

    // Commit the transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/systems?error_message={}", encoded_message));
    }

    Redirect::to("/systems")
}


// systems_pending
pub async fn systems_pending(auth: AuthSession, Query(query): Query<ErrorQuery>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) -> impl IntoResponse {
    let rows = sqlx::query("
        SELECT
            s.id AS system_id,
            COALESCE(s.name, 'NA') AS system_name,
            COALESCE(s.ver, 'NA') AS system_ver,
            COALESCE(s.ip, 'NA') AS system_ip,
            COALESCE(s.os, 'NA') AS system_os,
            COALESCE(s.arch, 'NA') AS system_arch,
            COALESCE(s.status, 'NA') AS system_status,
            COALESCE(GROUP_CONCAT(sg.name), 'none') AS group_names,
            COALESCE(s.created_date, '') AS created_date,
            COALESCE(s.last_seen, '') AS last_seen
        FROM
            systems AS s
        LEFT JOIN
            systems_in_groups AS sig ON s.id = sig.system_id
        LEFT JOIN
            system_groups AS sg ON sig.group_id = sg.id
        WHERE
            s.status = 'pending'
        GROUP BY
            s.id")        
        .fetch_all(&*pool)
        .await
        .unwrap();

    let systems: Vec<System> = rows.into_iter().map(|row| {
        System {
            id: row.try_get("system_id").unwrap(),
            name: row.try_get("system_name").unwrap(),
            ver: row.try_get("system_ver").unwrap(),
            ip: row.try_get("system_ip").unwrap(),
            os: row.try_get("system_os").unwrap(),
            arch: row.try_get("system_arch").unwrap(),
            status: row.try_get("system_status").unwrap(),
            groups: row.try_get("group_names").unwrap(),
            auth_signature: None,
            auth_public_key: None,
            trust_challenge: None,
            trust_proof: None,
            created_date: row.try_get("created_date").unwrap(),
            last_seen: row.try_get("last_seen").unwrap(),
        }
    }).collect();

    // Prepare handler-specific context
    let mut context = Context::new();
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    context.insert("systems", &systems);
    render_template(&tera,Some(&pool), "systems.html", context, Some(auth)).await
}






// system_groups
pub async fn system_groups(auth: AuthSession, Query(query): Query<ErrorQuery>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) -> impl IntoResponse {
    let rows = sqlx::query("
         SELECT
                sg.id AS group_id,
                sg.name AS group_name,
                sg.description AS group_description,
                COALESCE(GROUP_CONCAT(s.name), 'none') AS system_names
            FROM
                system_groups AS sg
            LEFT JOIN
                systems_in_groups AS sig ON sg.id = sig.group_id
            LEFT JOIN
                systems AS s ON sig.system_id = s.id
            GROUP BY
                sg.id, sg.name, sg.description")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let system_groups: Vec<SystemGroup> = rows.into_iter().map(|row| {
        SystemGroup {
            id: row.get("group_id"),
            name: row.get("group_name"),
            description: row.get("group_description"),
            systems: row.get("system_names"),
        }
    }).collect();

    // Prepare handler-specific context
    let mut context = Context::new();
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    context.insert("system_groups", &system_groups);
    render_template(&tera,Some(&pool), "system_groups.html", context, Some(auth)).await
}


// system_groups_add
pub async fn system_groups_add(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
    -> Result<Html<String>, StatusCode> {
    let rows = sqlx::query("
        SELECT id,name,status from systems")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let systems: Vec<System> = rows.into_iter().map(|row| {
        System {
            id: row.get("id"), // Use try_get for Option and handle potential errors
            name: row.get("name"),
            ver: None,
            ip: None,
            os: None, 
            arch: None,
            status: row.get("status"),
            groups: None,
            auth_signature: None,
            auth_public_key: None,
            trust_challenge: None,
            trust_proof: None,
            created_date: None,
            last_seen: None,
    }
    }).collect();

    let mut context = Context::new();
    context.insert("systems", &systems);
    render_template(&tera,Some(&pool), "system_groups_add.html", context, Some(auth)).await
}

//system_groups_add_save
pub async fn system_groups_add_save(auth : AuthSession, pool: Extension<SqlitePool>, raw_form: RawForm) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // Extract name and description (with error handling)
    let name = form_data.get("name").and_then(|v| v.first()).map(|s| s.to_string());
    let description = form_data.get("description").and_then(|v| v.first()).map(|s| s.to_string());
    let systems: Option<Vec<String>> = form_data.get("systems").cloned();

    // if name is empty
    if name.is_none() || description.is_none() {
        let error_message = "Missing 'name' or 'description' in form data.";
        let encoded_message = urlencoding::encode(error_message);
        return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
    }

    let result = sqlx::query(
        "INSERT INTO system_groups (name, description) VALUES (?, ?)"
    )
    .bind(name.as_ref().unwrap(), ) // Unwrap after checking for None
    .bind(description.as_ref().unwrap()) // Unwrap after checking for None
    .execute(&mut *tx)
    .await;

    let group_id = match result {
        Ok(res) => res.last_insert_rowid(),
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
        }
    };

    if let Some(systems) = systems {
        for system_id_str in systems {
            if let Ok(system_id) = system_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT INTO systems_in_groups (system_id, group_id) VALUES (?, ?)"
                )
                .bind(system_id)
                .bind(group_id)
                .execute(&mut *tx)
                .await
                {
                    let error_message = format!("Database error: {}", e);
                    let encoded_message = urlencoding::encode(&error_message);
                    return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
                }
            } else {
                let error_message = format!("Invalid system ID: {}", system_id_str);
                let encoded_message = urlencoding::encode(&error_message);
                return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
            }
        }
    }

    // Commit the transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Database error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
    }

    Redirect::to("/system_groups")
}


// system_groups_delete
pub async fn system_groups_delete(auth: AuthSession, Path(id): Path<i32>, pool: Extension<SqlitePool>) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
        }
    };

    // Delete records from the relationship table first
    let delete_relationship_result = sqlx::query(
        "DELETE FROM systems_in_groups WHERE group_id=?"
    )
    .bind(&id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = delete_relationship_result {
        let error_message = format!("Error deleting relationship: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); // Ensure the transaction is rolled back
        return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
    }

    // Now delete the system_group
    let delete_group_result = sqlx::query(
        "DELETE FROM system_groups WHERE id=?"
    )
    .bind(&id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = delete_group_result {
        let error_message = format!("Error deleting system group: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); // Ensure the transaction is rolled back
        return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
    }

    // Commit the transaction if all queries were successful
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error committing transaction: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
    }

    Redirect::to("/system_groups")
}


// system_group_edit
pub async fn system_groups_edit(auth: AuthSession, Path(id): Path<i32>,pool: Extension<SqlitePool>,tera: Extension<Arc<Tera>>) -> impl IntoResponse  {

    // capture system
    let row = sqlx::query("
                SELECT id,name,description from system_groups where id=?")
    .bind(id)
    .fetch_one(&*pool)
    .await
    .unwrap();

    let group = SystemGroup {
            id: row.try_get("id").unwrap(),
            name: row.try_get("name").unwrap(),
            description: row.try_get("description").unwrap(),
            systems: None,
    };
    
    // capture system list
    let rows = sqlx::query("
         SELECT id, name, status from systems ")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let systems: Vec<System> = rows.into_iter().map(|row| {
        System {
            id: row.get("id"), // Use try_get for Option and handle potential errors
            name: row.get("name"),
            ver: None,
            ip: None,
            os: None, 
            arch: None,
            status: row.get("status"),
            groups: None,
            auth_signature: None,
            auth_public_key: None,
            trust_challenge: None,
            trust_proof: None,
            created_date: None,
            last_seen: None,
        }
        }).collect();
    

    // capture groups that has the system 
    let rows = sqlx::query("
         SELECT system_id,group_id from systems_in_groups where group_id=?")
        .bind(id)
        .fetch_all(&*pool)
        .await
        .unwrap();

    let systems_in_groups: Vec<SystemInsideGroup> = rows.into_iter().map(|row| {
        SystemInsideGroup {
            system_id: row.get("system_id"),
            group_id: row.get("group_id"),
        }
    }).collect();

    let mut context = Context::new();
    context.insert("group", &group);
    context.insert("systems", &systems);
    context.insert("systems_in_groups", &systems_in_groups);
    render_template(&tera, Some(&pool), "system_groups_edit.html", context, Some(auth)).await
}


// system_groups_edit_save
pub async fn system_groups_edit_save(auth: AuthSession, Path(id): Path<i32>,pool: Extension<SqlitePool>, raw_form: RawForm) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // Extract name and description (with error handling)
    let name = form_data.get("name").and_then(|v| v.first()).map(|s| s.to_string());
    let description = form_data.get("description").and_then(|v| v.first()).map(|s| s.to_string());
    let systems: Option<Vec<String>> = form_data.get("systems").cloned(); 

    // Update system
    let update_group_result = sqlx::query(
        "UPDATE system_groups SET name=?, description=? WHERE id=?"
    )
    .bind(name.as_ref().unwrap()) // Unwrap after checking for None
    .bind(description.as_ref().unwrap()) // Unwrap after checking for None
    .bind(id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = update_group_result { 
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); 
        return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
    }

    // Remove all related groups
    let remove_related_systems = sqlx::query(
        "DELETE FROM systems_in_groups WHERE group_id=?"
    )
    .bind(id) 
    .execute(&mut *tx)
    .await;

    if let Err(e) = remove_related_systems
    {
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok();
        return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
    }


    // Assign selected systems
    if let Some(systems) = systems {
        for system_id_str in systems {
            if let Ok(system_id) = system_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT INTO systems_in_groups (system_id, group_id) VALUES (?, ?)"
                )
                .bind(system_id)
                .bind(id)
                .execute(&mut *tx)
                .await
                {
                    let error_message = format!("Error updating system: {}", e);
                    let encoded_message = urlencoding::encode(&error_message);
                    return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
                }
            }
        }
    }


    // Commit the transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/system_groups?error_message={}", encoded_message));
    }

    Redirect::to("/system_groups")
}


///////////////////// Compliance ////////////////////////


// tests
pub async fn tests(auth: AuthSession, Query(query): Query<ErrorQuery>,pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
            -> Result<Html<String>, StatusCode> {
    let rows = sqlx::query("
        SELECT
                t.id,
                t.name,
                t.description,
                t.severity
            FROM
                tests t
            ORDER BY
                t.name")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let tests: Vec<Test> = rows.into_iter().map(|row| {
        Test {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            rational: None,
            remediation: None,
            severity: row.get("severity"),    
            filter: None,
            element_1: None,
            input_1: None,
            selement_1: None,
            condition_1: None,
            sinput_1: None,
            element_2: None,
            input_2: None,
            selement_2: None,
            condition_2: None,
            sinput_2: None,
            element_3: None,
            input_3: None,
            selement_3: None,
            condition_3: None,
            sinput_3: None,
            element_4: None,
            input_4: None,
            selement_4: None,
            condition_4: None,
            sinput_4: None,
            element_5: None,
            input_5: None,
            selement_5: None,
            condition_5: None,
            sinput_5: None,
        }
    }).collect();

    // Prepare handler-specific context
    let mut context = Context::new();
    
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    context.insert("tests", &tests);

    // Use the generic render function to render the template with global data
    render_template(&tera, Some(&pool), "tests.html", context, Some(auth)).await
}


// tests_add
pub async fn tests_add(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
    -> Result<Html<String>, StatusCode> {
   

     
    let rows = sqlx::query("
        SELECT id,name from elements")
        .fetch_all(&*pool)
        .await
        .unwrap();


    let elements : Vec<Element> = rows.into_iter().map(|row| {
        Element {
            id: row.get("id"), 
            name: row.get("name"),
            description: None,
    }
    }).collect();

    let rows = sqlx::query("
        SELECT id,name from selements")
        .fetch_all(&*pool)
        .await
        .unwrap();


    let selements : Vec<SElement> = rows.into_iter().map(|row| {
        SElement {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
    }
    }).collect();

    let rows = sqlx::query("
        SELECT id,name from conditions")
        .fetch_all(&*pool)
        .await
        .unwrap();


    let conditions : Vec<Condition> = rows.into_iter().map(|row| {
        Condition {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
    }
    }).collect();

    // Prepare context for template
    let mut context = Context::new();
    context.insert("elements", &elements);
    context.insert("selements", &selements);
    context.insert("conditions", &conditions);
    render_template(&tera,Some(&pool), "tests_add.html", context, Some(auth)).await
}


// tests_add_save
pub async fn tests_add_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    raw_form: RawForm,
) -> Redirect {
    // Start transaction
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/tests?error_message={}", encoded_message));
        }
    };

    // Parse raw form
    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/tests?error_message={}", encoded_message));
        }
    };

    let form_data = parse_form_data(&raw_string);

    // -----------------------
    // Extract fields
    // -----------------------
    let name        = form_data.get("name").and_then(|v| v.first()).map(|s| s.to_string());
    if name.is_none() {
        let encoded_message = urlencoding::encode("Missing 'name' in form data.");
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }

    // For optional fields, default to empty string if not provided
    let description = form_data.get("description").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let severity    = form_data.get("severity").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let rational    = form_data.get("rational").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let remediation = form_data.get("remediation").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let filter      = form_data.get("filter").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();

   
    // element_* → "None" if empty
    let element_1   = form_data.get("element_1").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let element_2   = form_data.get("element_2").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let element_3   = form_data.get("element_3").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let element_4   = form_data.get("element_4").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let element_5   = form_data.get("element_5").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();

    // input_* → "" if empty
    let input_1     = form_data.get("input_1").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let input_2     = form_data.get("input_2").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let input_3     = form_data.get("input_3").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let input_4     = form_data.get("input_4").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let input_5     = form_data.get("input_5").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();

    // selement_* → "None" if empty
    let selement_1  = form_data.get("selement_1").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let selement_2  = form_data.get("selement_2").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let selement_3  = form_data.get("selement_3").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let selement_4  = form_data.get("selement_4").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let selement_5  = form_data.get("selement_5").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();

    // condition_* → "None" if empty
    let condition_1 = form_data.get("condition_1").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let condition_2 = form_data.get("condition_2").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let condition_3 = form_data.get("condition_3").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let condition_4 = form_data.get("condition_4").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let condition_5 = form_data.get("condition_5").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();

    // sinput_* → "" if empty
    let sinput_1    = form_data.get("sinput_1").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let sinput_2    = form_data.get("sinput_2").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let sinput_3    = form_data.get("sinput_3").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let sinput_4    = form_data.get("sinput_4").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let sinput_5    = form_data.get("sinput_5").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();



    // -----------------------
    // Mandatory field check
    // -----------------------
    if name.is_none() {
        let error_message = "Missing 'name' in form data.";
        let encoded_message = urlencoding::encode(error_message);
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }

    // -----------------------
    // Insert into database
    // -----------------------
    let result = sqlx::query(
        "INSERT INTO tests (name, description, severity, rational, remediation, filter,
                            element_1, input_1, selement_1, condition_1, sinput_1,
                            element_2, input_2, selement_2, condition_2, sinput_2,
                            element_3, input_3, selement_3, condition_3, sinput_3,
                            element_4, input_4, selement_4, condition_4, sinput_4, 
                            element_5, input_5, selement_5, condition_5, sinput_5)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(name.as_ref().unwrap())
    .bind(&description)
    .bind(&severity)
    .bind(&rational)
    .bind(&remediation)
    .bind(&filter)
    .bind(&element_1)
    .bind(&input_1)
    .bind(&selement_1)
    .bind(&condition_1)
    .bind(&sinput_1)
    .bind(&element_2)
    .bind(&input_2)
    .bind(&selement_2)
    .bind(&condition_2)
    .bind(&sinput_2)
    .bind(&element_3)
    .bind(&input_3)
    .bind(&selement_3)
    .bind(&condition_3)
    .bind(&sinput_3)
    .bind(&element_4)
    .bind(&input_4)
    .bind(&selement_4)
    .bind(&condition_4)
    .bind(&sinput_4)
    .bind(&element_5)
    .bind(&input_5)
    .bind(&selement_5)
    .bind(&condition_5)
    .bind(&sinput_5)
    .execute(&mut *tx)
    .await;

    if let Err(e) = result {
        let error_message = format!("Database insert error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }

    if let Err(e) = tx.commit().await {
        let error_message = format!("Database commit error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }

    Redirect::to("/tests")
}



// tests_delete
pub async fn tests_delete(auth: AuthSession, Path(id): Path<i32>, pool: Extension<SqlitePool>) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/tests?error_message={}", encoded_message));
        }
    };


    let delete_test_result = sqlx::query(
        "DELETE FROM tests WHERE id=?"
    )
    .bind(&id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = delete_test_result {
        let error_message = format!("Error deleting test: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); // Ensure the transaction is rolled back
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }        

    // Commit the transaction if all queries were successful
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error committing transaction: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }

    Redirect::to("/tests")
}

// tests_edit
pub async fn tests_edit(auth: AuthSession, Path(id): Path<i32>,pool: Extension<SqlitePool>,tera: Extension<Arc<Tera>>) -> impl IntoResponse  {

    // capture system
    let row = sqlx::query("
                SELECT id,name,description,severity,rational,remediation,filter,
                element_1,input_1,selement_1,condition_1,sinput_1,
                element_2,input_2,selement_2,condition_2,sinput_2,
                element_3,input_3,selement_3,condition_3,sinput_3,
                element_4,input_4,selement_4,condition_4,sinput_4,
                element_5,input_5,selement_5,condition_5,sinput_5
                from tests where id=?")
    .bind(id)
    .fetch_one(&*pool)
    .await
    .unwrap();

    let test = Test {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            severity: row.get("severity"),
            rational: row.get("rational"),
            remediation: row.get("remediation"),
            filter: row.get("filter"),
            element_1: row.get("element_1"),
            input_1: row.get("input_1"),
            selement_1: row.get("selement_1"),
            condition_1: row.get("condition_1"),
            sinput_1: row.get("sinput_1"),
            element_2: row.get("element_2"),
            input_2: row.get("input_2"),
            selement_2: row.get("selement_2"),
            condition_2: row.get("condition_2"),
            sinput_2: row.get("sinput_2"),
            element_3: row.get("element_3"),
            input_3: row.get("input_3"),
            selement_3: row.get("selement_3"),
            condition_3: row.get("condition_3"),
            sinput_3: row.get("sinput_3"),
            element_4: row.get("element_4"),
            input_4: row.get("input_4"),
            selement_4: row.get("selement_4"),
            condition_4: row.get("condition_4"),
            sinput_4: row.get("sinput_4"),
            element_5: row.get("element_5"),
            input_5: row.get("input_5"),
            selement_5: row.get("selement_5"),
            condition_5: row.get("condition_5"),
            sinput_5: row.get("sinput_5"),
        };

    let rows = sqlx::query("
        SELECT id,name from elements")
        .fetch_all(&*pool)
        .await
        .unwrap();


    let elements : Vec<Element> = rows.into_iter().map(|row| {
        Element {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
    }
    }).collect();


    let rows = sqlx::query("
        SELECT id,name from selements")
        .fetch_all(&*pool)
        .await
        .unwrap();


    let selements : Vec<SElement> = rows.into_iter().map(|row| {
        SElement {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
    }
    }).collect();


    
    let rows = sqlx::query("
        SELECT id,name from conditions")
        .fetch_all(&*pool)
        .await
        .unwrap();
        
            
    let conditions : Vec<Condition> = rows.into_iter().map(|row| {
        Condition {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
    }
    }).collect();


    
    let mut context = Context::new();
    context.insert("test", &test);
    context.insert("elements", &elements);
    context.insert("selements", &selements);
    context.insert("conditions", &conditions);
    render_template(&tera, Some(&pool), "tests_edit.html", context, Some(auth)).await
}


// tests_edit_save
pub async fn tests_edit_save(auth: AuthSession, Path(id): Path<i32>,pool: Extension<SqlitePool>, raw_form: RawForm) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/tests?error_message={}", encoded_message));
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/tests?error_message={}", encoded_message));
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // -----------------------
    // Extract fields 
    // -----------------------
    let name        = form_data.get("name").and_then(|v| v.first()).map(|s| s.to_string());
    if name.is_none() {
        let encoded_message = urlencoding::encode("Missing 'name' in form data.");
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }
    
    // For optional fields, default to empty string if not provided
    let description = form_data.get("description").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let severity    = form_data.get("severity").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let rational    = form_data.get("rational").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let remediation = form_data.get("remediation").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let filter      = form_data.get("filter").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    
    
    // element_* → "None" if empty
    let element_1   = form_data.get("element_1").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let element_2   = form_data.get("element_2").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let element_3   = form_data.get("element_3").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let element_4   = form_data.get("element_4").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let element_5   = form_data.get("element_5").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();

    // input_* → "" if empty
    let input_1     = form_data.get("input_1").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let input_2     = form_data.get("input_2").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let input_3     = form_data.get("input_3").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let input_4     = form_data.get("input_4").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let input_5     = form_data.get("input_5").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();

    // selement_* → "None" if empty
    let selement_1  = form_data.get("selement_1").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let selement_2  = form_data.get("selement_2").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let selement_3  = form_data.get("selement_3").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let selement_4  = form_data.get("selement_4").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let selement_5  = form_data.get("selement_5").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();

    // condition_* → "None" if empty
    let condition_1 = form_data.get("condition_1").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let condition_2 = form_data.get("condition_2").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let condition_3 = form_data.get("condition_3").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let condition_4 = form_data.get("condition_4").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();
    let condition_5 = form_data.get("condition_5").and_then(|v| v.first()).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("None").to_string();

    // sinput_* → "" if empty
    let sinput_1    = form_data.get("sinput_1").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let sinput_2    = form_data.get("sinput_2").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let sinput_3    = form_data.get("sinput_3").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let sinput_4    = form_data.get("sinput_4").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();
    let sinput_5    = form_data.get("sinput_5").and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default();



    // -----------------------
    // Mandatory field check
    // -----------------------
    if name.is_none() {
        let error_message = "Missing 'name' in form data.";
        let encoded_message = urlencoding::encode(error_message);
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }



    // Update system
    let update_group_result = sqlx::query(
        "UPDATE tests SET name=?, description=?, severity=?, rational=?, remediation=?, filter=?,
                          element_1=?, input_1=?, selement_1=?, condition_1=?, sinput_1=?,
                          element_2=?, input_2=?, selement_2=?, condition_2=?, sinput_2=?,
                          element_3=?, input_3=?, selement_3=?, condition_3=?, sinput_3=?,
                          element_4=?, input_4=?, selement_4=?, condition_4=?, sinput_4=?,
                          element_5=?, input_5=?, selement_5=?, condition_5=?, sinput_5=?
        WHERE id=?"
    )
    .bind(name.as_ref().unwrap())
    .bind(&description)
    .bind(&severity)
    .bind(&rational)
    .bind(&remediation)
    .bind(&filter)
    .bind(&element_1)
    .bind(&input_1)
    .bind(&selement_1)
    .bind(&condition_1)
    .bind(&sinput_1)
    .bind(&element_2)
    .bind(&input_2)
    .bind(&selement_2)
    .bind(&condition_2)
    .bind(&sinput_2)
    .bind(&element_3)
    .bind(&input_3)
    .bind(&selement_3)
    .bind(&condition_3)
    .bind(&sinput_3)
    .bind(&element_4)
    .bind(&input_4)
    .bind(&selement_4)
    .bind(&condition_4)
    .bind(&sinput_4)
    .bind(&element_5)
    .bind(&input_5)
    .bind(&selement_5)
    .bind(&condition_5)
    .bind(&sinput_5)
    .bind(id)
    .execute(&mut *tx)
    .await;


    if let Err(e) = update_group_result {
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok();
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }

    // Commit the transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error updating system: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/tests?error_message={}", encoded_message));
    }

    Redirect::to("/tests")
}



// policies
pub async fn policies(auth: AuthSession, Query(query): Query<ErrorQuery>, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
-> Result<Html<String>, StatusCode> {

    let rows = sqlx::query(r#"
        SELECT 
            p.id AS policy_id,
            p.name AS policy_name,
            p.version AS policy_version,
            p.description AS policy_description,
            -- If there are no systems, ROUND returns NULL; COALESCE turns that NULL into -1
            CAST(
                COALESCE(
                    ROUND(
                        SUM(CASE WHEN system_status = 'passed' THEN 1 ELSE 0 END) * 100.0 
                        / NULLIF(COUNT(system_results.system_id), 0), 
                        2
                    ), 
                    -1.0
                ) AS REAL
            ) AS compliance
        FROM policies p
        LEFT JOIN (
            -- Subquery: Determines status for systems that actually HAVE results
            SELECT 
                tip.policy_id, 
                r.system_id,
                CASE 
                    WHEN SUM(CASE WHEN r.result = 'false' THEN 1 ELSE 0 END) > 0 
                        THEN 'failed' 
                    ELSE 'passed' 
                END AS system_status
            FROM tests_in_policy tip
            JOIN results r ON r.test_id = tip.test_id
            GROUP BY tip.policy_id, r.system_id
        ) AS system_results ON p.id = system_results.policy_id
        GROUP BY p.id, p.name, p.version, p.description
        ORDER BY p.id ASC

    "#)
    .fetch_all(&*pool)
    .await
    .map_err(|e| {
        error!("Database query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let policies: Vec<PolicyCompliance> = rows.into_iter().map(|row| {
        PolicyCompliance {
            // The Turbofish (::<Type, _>) fixes the E0282 error
            policy_id: row.get::<i64, _>("policy_id"),
            policy_name: row.get::<String, _>("policy_name"),
            policy_version: row.get::<String, _>("policy_version"),

            policy_description: Some(row.get::<Option<String>, _>("policy_description")
            .unwrap_or_default()),

            compliance: row.get::<f64, _>("compliance"),
            passed_systems: None,
            failed_systems: None,
        }
    }).collect();



    // Prepare handler-specific context
    let mut context = Context::new();
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    if let Some(success_message) = query.success_message {
        context.insert("success_message", &success_message);
    }
    context.insert("policies", &policies);
    render_template(&tera, Some(&pool), "policies.html", context, Some(auth)).await
}




// policies_add
pub async fn policies_add(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
    -> Result<Html<String>, StatusCode> {
    let rows = sqlx::query("
        SELECT id,name from tests")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let tests: Vec<Test> = rows.into_iter().map(|row| {
        Test {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
            rational: None,
            remediation: None,
            severity: None,
            filter: None,
            element_1: None,
            input_1: None,
            selement_1: None,
            condition_1: None,
            sinput_1: None,
            element_2: None,
            input_2: None,
            selement_2: None,
            condition_2: None,
            sinput_2: None,
            element_3: None,
            input_3: None,
            selement_3: None,
            condition_3: None,
            sinput_3: None,
            element_4: None,
            input_4: None,
            selement_4: None,
            condition_4: None,
            sinput_4: None,
            element_5: None,
            input_5: None,
            selement_5: None,
            condition_5: None,
            sinput_5: None,
        }
    }).collect();

    let rows = sqlx::query("
        SELECT id,name from system_groups")
        .fetch_all(&*pool)
        .await
        .unwrap();
    let system_groups: Vec<SystemGroup> = rows.into_iter().map(|row| {
        SystemGroup {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
            systems: None,
    }
    }).collect();

    let mut context = Context::new();
    context.insert("tests", &tests);
    context.insert("system_groups",&system_groups);
    render_template(&tera,Some(&pool), "policies_add.html", context, Some(auth)).await
}


//policies_add_save
pub async fn policies_add_save(auth: AuthSession, Extension(pool): Extension<SqlitePool>, RawForm(raw_form): RawForm) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message));
        }
    };

    let raw_string = match String::from_utf8(raw_form.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message));
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // Required fields
    let name = match form_data.get("name").and_then(|v| v.first()) {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => return Redirect::to("/policies?error_message=Name is required"),
    };

    let version = match form_data.get("version").and_then(|v| v.first()) {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => return Redirect::to("/policies?error_message=Version is required"),
    };

    let description: Option<String> = form_data
    .get("description")
    .and_then(|v| v.first())
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());


    // Multi-selects (must have at least one)
    let tests = form_data
        .get("tests")
        .cloned()
        .unwrap_or_default();

    let system_groups = form_data
        .get("system_groups")
        .cloned()
        .unwrap_or_default();


    // Insert into DB using transaction
    let result = sqlx::query(
        "INSERT INTO policies (name, version, description) VALUES (?, ?, ?)"
    )
    .bind(&name) 
    .bind(&version) 
    .bind(&description) 
    .execute(&mut *tx)
    .await;


    let policy_id = match result {
        Ok(res) => res.last_insert_rowid(),
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message));
        }
    };

    // Insert into DB tests
        for test_id_str in tests {
            if let Ok(test_id) = test_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT OR IGNORE INTO tests_in_policy (policy_id, test_id) VALUES (?, ?)"
                )
                .bind(policy_id)
                .bind(test_id)
                .execute(&mut *tx)
                .await
                {
                    let error_message = format!("Database error: {}", e);
                    let encoded_message = urlencoding::encode(&error_message);
                    return Redirect::to(&format!("/policies?error_message={}", encoded_message));
                }
            } else {
                let error_message = format!("Invalid test ID: {}", test_id_str);
                let encoded_message = urlencoding::encode(&error_message);
                return Redirect::to(&format!("/policies?error_message={}", encoded_message));
            }
        }

    // insert into DB system_groups
        for group_id_str in system_groups {
            if let Ok(group_id) = group_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT OR IGNORE INTO systems_in_policy (policy_id, group_id) VALUES (?, ?)"
                )
                .bind(policy_id)
                .bind(group_id)
                .execute(&mut *tx)
                .await
                {
                    let error_message = format!("Database error: {}", e);
                    let encoded_message = urlencoding::encode(&error_message);
                    return Redirect::to(&format!("/policies?error_message={}", encoded_message));
                }
            } else {
                let error_message = format!("Invalid group ID: {}", group_id_str);
                let encoded_message = urlencoding::encode(&error_message);
                return Redirect::to(&format!("/policies?error_message={}", encoded_message));
            }
        }

    // Commit the transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Database error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }

    Redirect::to("/policies")
}

//policies_edit
pub async fn policies_edit(auth: AuthSession, Path(id): Path<i32>,pool: Extension<SqlitePool>,tera: Extension<Arc<Tera>>) -> impl IntoResponse  {

let row = sqlx::query("
                SELECT id,name,version,description from policies where id=?")
    .bind(id)
    .fetch_one(&*pool)
    .await
    .unwrap();

    let policy = Policy {
            id: row.try_get("id").unwrap(),
            name: row.try_get("name").unwrap(),
            version: row.try_get("version").unwrap(),
            description: row.try_get("description").unwrap(),
    };

    // get tests
    let rows = sqlx::query("
        SELECT id,name from tests")
        .fetch_all(&*pool)
        .await
        .unwrap(); 
        
    let test_groups: Vec<Test> = rows.into_iter().map(|row| {
        Test { 
            id: row.get("id"),
            name: row.get("name"),
            description: None,
            rational: None,
            remediation: None,
            severity: None,
            filter: None,
            element_1: None,
            input_1: None,
            selement_1: None,
            condition_1: None,
            sinput_1: None,
            element_2: None,
            input_2: None,
            selement_2: None,
            condition_2: None,
            sinput_2: None,
            element_3: None,
            input_3: None,
            selement_3: None, 
            condition_3: None,
            sinput_3: None,
            element_4: None,
            input_4: None,
            selement_4: None,
            condition_4: None,
            sinput_4: None,
            element_5: None,
            input_5: None,
            selement_5: None,
            condition_5: None,
            sinput_5: None,
        }
    }).collect();

    // get system_groups
    let rows = sqlx::query("
        SELECT id,name from system_groups")
        .fetch_all(&*pool)
        .await
        .unwrap();
    let system_groups: Vec<SystemGroup> = rows.into_iter().map(|row| {
        SystemGroup {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
            systems: None,
    }
    }).collect();

    // get tests inside the policy
    let rows = sqlx::query("
         SELECT policy_id,test_id from tests_in_policy where policy_id=?")
        .bind(id)
        .fetch_all(&*pool)
        .await
        .unwrap();

    let tests_in_policy: Vec<TestInsidePolicy> = rows.into_iter().map(|row| {
        TestInsidePolicy {
            policy_id: row.get("policy_id"),
            test_id: row.get("test_id"),
        }
    }).collect();


   // get system_groups inside the policy
    let rows = sqlx::query("
         SELECT policy_id,group_id from systems_in_policy where policy_id=?")
        .bind(id)
        .fetch_all(&*pool)
        .await
        .unwrap();

    let systems_in_policy: Vec<SystemInsidePolicy> = rows.into_iter().map(|row| { 
        SystemInsidePolicy {
            policy_id: row.get("policy_id"),
            group_id: row.get("group_id"),
        }
    }).collect();



    let mut context = Context::new();
    context.insert("policy",&policy);
    context.insert("tests", &test_groups);
    context.insert("system_groups",&system_groups);
    context.insert("tests_in_policy", &tests_in_policy);
    context.insert("systems_in_policy", &systems_in_policy);
    render_template(&tera,Some(&pool), "policies_edit.html", context, Some(auth)).await

}


//policies_edit_save
pub async fn policies_edit_save(auth: AuthSession, Path(id): Path<i32>, Extension(pool): Extension<SqlitePool>, RawForm(raw_form): RawForm) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message));
        }
    };

    let raw_string = match String::from_utf8(raw_form.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let error_message = format!("Error converting bytes to string: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message));
        }
    };

    // Parse the URL-encoded string
    let form_data = parse_form_data(&raw_string);

    // Required fields
    let name = match form_data.get("name").and_then(|v| v.first()) {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => return Redirect::to("/policies?error_message=Name is required"),
    };

    let version = match form_data.get("version").and_then(|v| v.first()) {
        Some(v) if !v.trim().is_empty() => v.to_string(),
        _ => return Redirect::to("/policies?error_message=Version is required"),
    };

    let description: Option<String> = form_data
    .get("description")
    .and_then(|v| v.first())
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());

    // Multi-selects (must have at least one)
    let tests = form_data
        .get("tests")
        .cloned()
        .unwrap_or_default();

    let system_groups = form_data
        .get("system_groups")
        .cloned()
        .unwrap_or_default();


    // update policy table 
    let update_policy_result = sqlx::query(
        "UPDATE policies SET name=?, version=?, description=? WHERE id=?" 
    )
    .bind(&name) 
    .bind(&version) 
    .bind(&description) 
    .bind(id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = update_policy_result { 
        let error_message = format!("Error updating policy: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); 
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }

    // Remove all related groups
    let remove_related_groups = sqlx::query(
        "DELETE FROM tests_in_policy WHERE policy_id=?"
    )
    .bind(id) 
    .execute(&mut *tx)
    .await;

    if let Err(e) = remove_related_groups
    {
        let error_message = format!("Error updating policy: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }
    

    // Remove all related systems
    let remove_related_systems = sqlx::query(
        "DELETE FROM systems_in_policy WHERE policy_id=?"
    )
    .bind(id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = remove_related_systems
    {
        let error_message = format!("Error updating policy: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }


    // Insert into DB test_groups
        for test_id_str in tests {
            if let Ok(test_id) = test_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT OR IGNORE INTO tests_in_policy (policy_id, test_id) VALUES (?, ?)"
                )
                .bind(id)
                .bind(test_id)
                .execute(&mut *tx)
                .await
                {
                    let error_message = format!("Database error: {}", e);
                    let encoded_message = urlencoding::encode(&error_message);
                    return Redirect::to(&format!("/policies?error_message={}", encoded_message));
                }
            } else {
                let error_message = format!("Invalid test ID: {}", test_id_str);
                let encoded_message = urlencoding::encode(&error_message);
                return Redirect::to(&format!("/policies?error_message={}", encoded_message));
            }
        }

    // insert into DB system_groups
        for group_id_str in system_groups {
            if let Ok(group_id) = group_id_str.parse::<i32>() {
                if let Err(e) = sqlx::query(
                    "INSERT OR IGNORE INTO systems_in_policy (policy_id, group_id) VALUES (?, ?)"
                )
                .bind(id)
                .bind(group_id)
                .execute(&mut *tx)
                .await
                {
                    let error_message = format!("Database error: {}", e);
                    let encoded_message = urlencoding::encode(&error_message);
                    return Redirect::to(&format!("/policies?error_message={}", encoded_message));
                }
            } else {
                let error_message = format!("Invalid group ID: {}", group_id_str);
                let encoded_message = urlencoding::encode(&error_message);
                return Redirect::to(&format!("/policies?error_message={}", encoded_message));
            }
        }

    // Commit the transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Database error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }

    Redirect::to("/policies")
}



// policies_delete
pub async fn policies_delete(auth: AuthSession, Path(id): Path<i32>, pool: Extension<SqlitePool>) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message));
        }
    };

    
    let delete_policy_result = sqlx::query(
        "DELETE FROM policies WHERE id=?"
    )
    .bind(&id) 
    .execute(&mut *tx)
    .await; 
            
    if let Err(e) = delete_policy_result {
        let error_message = format!("Error deleting system group: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); // Ensure the transaction is rolled back
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }

    // Commit the transaction if all queries were successful
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error committing transaction: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }

    Redirect::to("/policies")
}

// policies_run
pub async fn policies_run(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>
) -> Redirect {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/policies?error_message={}", encoded_message));
        }
    };

    // Insert commands for all system × test combinations
    if let Err(e) = sqlx::query(
        r#"
        INSERT OR IGNORE INTO commands (system_id, test_id)
        SELECT sig.system_id, tip.test_id
        FROM systems_in_policy sip
        JOIN systems_in_groups sig ON sip.group_id = sig.group_id
        JOIN tests_in_policy tip ON sip.policy_id = tip.policy_id
        WHERE sip.policy_id = ?
        "#
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    {
        let error_message = format!("Error running policy: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok();
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }

    // Commit transaction
    if let Err(e) = tx.commit().await {
        let error_message = format!("Database commit error: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/policies?error_message={}", encoded_message));
    }

    Redirect::to("/policies?success_message=Policy run successfully")
}


//////////////////// Reports /////////////////////////
// reports
pub async fn reports(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>)
    -> Result<Html<String>, StatusCode> {
    let context = Context::new();
    render_template(&tera,Some(&pool), "reports.html", context, Some(auth)).await
}






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





