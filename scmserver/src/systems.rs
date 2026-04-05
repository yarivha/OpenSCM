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
use tracing::{warn, error};
use bytes::Bytes;

use crate::models::ErrorQuery;
use crate::models::Notification;
use crate::models::System;
use crate::models::SystemGroup;
use crate::models::SystemInsideGroup;
use crate::models::Test;
use crate::models::Element;
use crate::models::SElement;
use crate::models::Condition;
use crate::auth::AuthSession;
use crate::handlers::render_template;
use crate::handlers::parse_form_data;



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
    let row_result = sqlx::query("
        SELECT id, name, ver, ip, os, arch, status 
        FROM systems 
        WHERE id = ? AND status = 'active'
    ")
    .bind(id)
    .fetch_optional(&*pool)
    .await;

    // 2. Handle potential Database Errors AND missing rows
    let row = match row_result {
        Ok(Some(r)) => r,
        _ => {
            warn!("System ID {} not found or not active.", id);
            // We MUST call .into_response() here
            return Redirect::to("/systems").into_response(); 
        }
    };



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
    render_template(&tera, Some(&pool), "systems_edit.html",context, Some(auth)).await.into_response()
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
        SELECT id,name,status from systems where status='active'")
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
         SELECT id, name, status from systems where status='active' ")
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


