use axum::response::{IntoResponse, Redirect};
use axum::extract::{RawForm, Extension, Query, Path};
use tokio::sync::mpsc;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use tracing::{info, error};
use bytes::Bytes;

use crate::models::{ErrorQuery, Test, TestCondition, Element, SElement, Condition, UserRole, AuthSession};
use crate::auth::{self};
use crate::handlers::render_template;
use crate::handlers::parse_form_data;


// ============================================================
// HELPERS
// ============================================================

/// Fetch global elements, selements, and conditions lookup tables.
/// These are shared across all tenants.
async fn fetch_lookup_tables(
    pool: &SqlitePool,
) -> Result<(Vec<Element>, Vec<SElement>, Vec<Condition>), sqlx::Error> {
    let element_rows = sqlx::query("SELECT id, name FROM elements")
        .fetch_all(pool)
        .await?;

    let elements = element_rows
        .into_iter()
        .map(|row| Element {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
        })
        .collect();

    let selement_rows = sqlx::query("SELECT id, name FROM selements")
        .fetch_all(pool)
        .await?;

    let selements = selement_rows
        .into_iter()
        .map(|row| SElement {
            id: row.get("id"),
            name: row.get("name"),
            description: None,
        })
        .collect();

    let condition_rows = sqlx::query("SELECT id, name FROM conditions")
        .fetch_all(pool)
        .await?;

    let conditions = condition_rows
    .into_iter()
    .map(|row| Condition {
        id: row.get("id"),
        name: row.get("name"),
        description: None,
    })
    .collect();


    Ok((elements, selements, conditions))
}

/// Extract and map all test fields from a sqlx row.
fn map_test_row(row: &sqlx::sqlite::SqliteRow) -> Test {
    Test {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        severity: row.get("severity"),
        rational: row.get("rational"),
        remediation: row.get("remediation"),
        filter: row.get("filter"),
        app_filter: row.get("app_filter"),
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
    }
}

/// Extract all test fields from parsed form data.
fn extract_test_fields(
    form_data: &std::collections::HashMap<String, Vec<String>>,
) -> Result<(String, String, String, String, String, String, String,
             String, String, String, String, String,
             String, String, String, String, String,
             String, String, String, String, String,
             String, String, String, String, String,
             String, String, String, String, String), String> {

    let name = form_data
        .get("name")
        .and_then(|v| v.first())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| "Test name is required.".to_string())?;

    let get_opt = |key: &str| -> String {
        form_data.get(key).and_then(|v| v.first()).map(|s| s.to_string()).unwrap_or_default()
    };

    let get_or_none = |key: &str| -> String {
        form_data.get(key).and_then(|v| v.first())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "None".to_string())
    };

    Ok((
        name,
        get_opt("description"),
        get_opt("severity"),
        get_opt("rational"),
        get_opt("remediation"),
        get_opt("filter"),
        get_opt("app_filter"),
        get_or_none("element_1"),   get_opt("input_1"),   get_or_none("selement_1"),   get_or_none("condition_1"),   get_opt("sinput_1"),
        get_or_none("element_2"),   get_opt("input_2"),   get_or_none("selement_2"),   get_or_none("condition_2"),   get_opt("sinput_2"),
        get_or_none("element_3"),   get_opt("input_3"),   get_or_none("selement_3"),   get_or_none("condition_3"),   get_opt("sinput_3"),
        get_or_none("element_4"),   get_opt("input_4"),   get_or_none("selement_4"),   get_or_none("condition_4"),   get_opt("sinput_4"),
        get_or_none("element_5"),   get_opt("input_5"),   get_or_none("selement_5"),   get_or_none("condition_5"),   get_opt("sinput_5"),
    ))
}


// ============================================================
// HANDLERS
// ============================================================

pub async fn tests(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let rows_result = sqlx::query(
        "SELECT
            id, name, description, severity,
            rational, remediation, filter,app_filter,
            element_1, input_1, selement_1, condition_1, sinput_1,
            element_2, input_2, selement_2, condition_2, sinput_2,
            element_3, input_3, selement_3, condition_3, sinput_3,
            element_4, input_4, selement_4, condition_4, sinput_4,
            element_5, input_5, selement_5, condition_5, sinput_5
        FROM tests
        WHERE tenant_id = ?
        ORDER BY name",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let tests: Vec<Test> = match rows_result {
        Ok(rows) => rows.iter().map(map_test_row).collect(),
        Err(e) => {
            error!("Failed to fetch tests: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load tests.");
            context.insert("tests", &Vec::<Test>::new());
            return render_template(&tera, Some(&pool), "tests.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    context.insert("tests", &tests);
    render_template(&tera, Some(&pool), "tests.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn tests_add(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut context = Context::new();

    match fetch_lookup_tables(&*pool).await {
        Ok((elements, selements, conditions)) => {
            context.insert("elements", &elements);
            context.insert("selements", &selements);
            context.insert("conditions", &conditions);
        }
        Err(e) => {
            error!("Failed to fetch lookup tables: {}", e);
            context.insert("error_message", "Failed to load form data.");
        }
    }

    render_template(&tera, Some(&pool), "tests_add.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn tests_add_save(
    auth: AuthSession,
    pool: Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    let (
        name, description, severity, rational, remediation, filter, app_filter,
        element_1, input_1, selement_1, condition_1, sinput_1,
        element_2, input_2, selement_2, condition_2, sinput_2,
        element_3, input_3, selement_3, condition_3, sinput_3,
        element_4, input_4, selement_4, condition_4, sinput_4,
        element_5, input_5, selement_5, condition_5, sinput_5,
    ) = match extract_test_fields(&form_data) {
        Ok(fields) => fields,
        Err(msg) => {
            let encoded = urlencoding::encode(&msg).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    // Get applicability type and filter
    let app_type = form_data.get("app_type")
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("always");


    // Insert test
    let result = sqlx::query(
        "INSERT INTO tests (
            tenant_id, name, description, severity, rational, remediation, filter, app_filter,
            element_1, input_1, selement_1, condition_1, sinput_1,
            element_2, input_2, selement_2, condition_2, sinput_2,
            element_3, input_3, selement_3, condition_3, sinput_3,
            element_4, input_4, selement_4, condition_4, sinput_4,
            element_5, input_5, selement_5, condition_5, sinput_5
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?
        )",
    )
    .bind(&auth.tenant_id)
    .bind(&name)
    .bind(&description)
    .bind(&severity)
    .bind(&rational)
    .bind(&remediation)
    .bind(&filter)
    .bind(&app_filter)
    .bind(&element_1).bind(&input_1).bind(&selement_1).bind(&condition_1).bind(&sinput_1)
    .bind(&element_2).bind(&input_2).bind(&selement_2).bind(&condition_2).bind(&sinput_2)
    .bind(&element_3).bind(&input_3).bind(&selement_3).bind(&condition_3).bind(&sinput_3)
    .bind(&element_4).bind(&input_4).bind(&selement_4).bind(&condition_4).bind(&sinput_4)
    .bind(&element_5).bind(&input_5).bind(&selement_5).bind(&condition_5).bind(&sinput_5)
    .execute(&mut *tx)
    .await;

    let test_id = match result {
        Ok(r) => r.last_insert_rowid(),
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database insert error: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    // Save applicability conditions if conditional
    if app_type == "conditional" {
        for i in 1..=3 {
            let element = form_data.get(&format!("app_element_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            if element.is_empty() || element == "-- Select --" {
                continue;
            }

            let input = form_data.get(&format!("app_input_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let selement = form_data.get(&format!("app_selement_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let condition = form_data.get(&format!("app_condition_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let sinput = form_data.get(&format!("app_sinput_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            if let Err(e) = sqlx::query(
                "INSERT INTO test_conditions (tenant_id, test_id, type, element, input, selement, condition, sinput)
                 VALUES (?, ?, 'applicability', ?, ?, ?, ?, ?)",
            )
            .bind(&auth.tenant_id)
            .bind(test_id)
            .bind(&element)
            .bind(&input)
            .bind(&selement)
            .bind(&condition)
            .bind(&sinput)
            .execute(&mut *tx)
            .await
            {
                let encoded = urlencoding::encode(&format!("Error saving applicability condition: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
            }
        }
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    info!("Test '{}' created by '{}'.", name, auth.username);
    Redirect::to("/tests").into_response()
}




pub async fn tests_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    // ON DELETE CASCADE handles related records — no transaction needed
    if let Err(e) = sqlx::query("DELETE FROM tests WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
    {
        error!("Failed to delete test {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting test: {}", e)).to_string();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("Test ID {} deleted by '{}'.", id, auth.username);
    Redirect::to("/tests").into_response()
}



pub async fn tests_edit(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let row_result = sqlx::query(
        "SELECT
            id, name, description, severity, rational, remediation, filter, app_filter,
            element_1, input_1, selement_1, condition_1, sinput_1,
            element_2, input_2, selement_2, condition_2, sinput_2,
            element_3, input_3, selement_3, condition_3, sinput_3,
            element_4, input_4, selement_4, condition_4, sinput_4,
            element_5, input_5, selement_5, condition_5, sinput_5
        FROM tests
        WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await;

    let row = match row_result {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Redirect::to("/tests?error_message=Test+not+found").into_response();
        }
        Err(e) => {
            error!("Database error fetching test {}: {}", id, e);
            return Redirect::to("/tests?error_message=Database+error").into_response();
        }
    };

    let test = map_test_row(&row);

    // Fetch applicability conditions
    let app_conditions = match sqlx::query_as::<_, TestCondition>(
        "SELECT id, tenant_id, test_id, type, element, input, selement, condition, sinput
         FROM test_conditions
         WHERE test_id = ? AND tenant_id = ? AND type = 'applicability'
         ORDER BY id ASC
         LIMIT 3",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch applicability conditions for test {}: {}", id, e);
            vec![]
        }
    };

    let mut context = Context::new();

    match fetch_lookup_tables(&*pool).await {
        Ok((elements, selements, conditions)) => {
            context.insert("elements", &elements);
            context.insert("selements", &selements);
            context.insert("conditions", &conditions);
        }
        Err(e) => {
            error!("Failed to fetch lookup tables for test edit {}: {}", id, e);
            context.insert("error_message", "Failed to load form data.");
        }
    }

    context.insert("test", &test);
    context.insert("app_conditions", &app_conditions);
    render_template(&tera, Some(&pool), "tests_edit.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn tests_edit_save(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
    Extension(sync_tx): Extension<mpsc::Sender<()>>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Database error: {}", e)).to_string();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(e) => {
            let encoded = urlencoding::encode(&format!("Invalid form encoding: {}", e)).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    let form_data = parse_form_data(&raw_string);

    let (
        name, description, severity, rational, remediation, filter, app_filter,
        element_1, input_1, selement_1, condition_1, sinput_1,
        element_2, input_2, selement_2, condition_2, sinput_2,
        element_3, input_3, selement_3, condition_3, sinput_3,
        element_4, input_4, selement_4, condition_4, sinput_4,
        element_5, input_5, selement_5, condition_5, sinput_5,
    ) = match extract_test_fields(&form_data) {
        Ok(fields) => fields,
        Err(msg) => {
            let encoded = urlencoding::encode(&msg).to_string();
            tx.rollback().await.ok();
            return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
        }
    };

    // Get applicability type and filter
    let app_type = form_data.get("app_type")
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("always");


    // Update test
    let result = sqlx::query(
        "UPDATE tests SET
            name = ?, description = ?, severity = ?, rational = ?, remediation = ?, filter = ?, app_filter = ?,
            element_1 = ?, input_1 = ?, selement_1 = ?, condition_1 = ?, sinput_1 = ?,
            element_2 = ?, input_2 = ?, selement_2 = ?, condition_2 = ?, sinput_2 = ?,
            element_3 = ?, input_3 = ?, selement_3 = ?, condition_3 = ?, sinput_3 = ?,
            element_4 = ?, input_4 = ?, selement_4 = ?, condition_4 = ?, sinput_4 = ?,
            element_5 = ?, input_5 = ?, selement_5 = ?, condition_5 = ?, sinput_5 = ?
        WHERE id = ? AND tenant_id = ?",
    )
    .bind(&name)
    .bind(&description)
    .bind(&severity)
    .bind(&rational)
    .bind(&remediation)
    .bind(&filter)
    .bind(&app_filter)
    .bind(&element_1).bind(&input_1).bind(&selement_1).bind(&condition_1).bind(&sinput_1)
    .bind(&element_2).bind(&input_2).bind(&selement_2).bind(&condition_2).bind(&sinput_2)
    .bind(&element_3).bind(&input_3).bind(&selement_3).bind(&condition_3).bind(&sinput_3)
    .bind(&element_4).bind(&input_4).bind(&selement_4).bind(&condition_4).bind(&sinput_4)
    .bind(&element_5).bind(&input_5).bind(&selement_5).bind(&condition_5).bind(&sinput_5)
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = result {
        let encoded = urlencoding::encode(&format!("Error updating test: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    // Delete existing applicability conditions and re-insert
    if let Err(e) = sqlx::query(
        "DELETE FROM test_conditions WHERE test_id = ? AND tenant_id = ? AND type = 'applicability'"
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    {
        let encoded = urlencoding::encode(&format!("Error clearing applicability conditions: {}", e)).to_string();
        tx.rollback().await.ok();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    // Re-insert applicability conditions if conditional
    if app_type == "conditional" {
        for i in 1..=3 {
            let element = form_data.get(&format!("app_element_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            if element.is_empty() || element == "-- Select --" {
                continue;
            }

            let input = form_data.get(&format!("app_input_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let selement = form_data.get(&format!("app_selement_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let condition = form_data.get(&format!("app_condition_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let sinput = form_data.get(&format!("app_sinput_{}", i))
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();

            if let Err(e) = sqlx::query(
                "INSERT INTO test_conditions (tenant_id, test_id, type, element, input, selement, condition, sinput)
                 VALUES (?, ?, 'applicability', ?, ?, ?, ?, ?)",
            )
            .bind(&auth.tenant_id)
            .bind(id)
            .bind(&element)
            .bind(&input)
            .bind(&selement)
            .bind(&condition)
            .bind(&sinput)
            .execute(&mut *tx)
            .await
            {
                let encoded = urlencoding::encode(&format!("Error saving applicability condition: {}", e)).to_string();
                tx.rollback().await.ok();
                return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
            }
        }
    }

    if let Err(e) = tx.commit().await {
        let encoded = urlencoding::encode(&format!("Commit error: {}", e)).to_string();
        return Redirect::to(&format!("/tests?error_message={}", encoded)).into_response();
    }

    let _ = sync_tx.send(()).await;
    info!("Test ID {} updated by '{}'.", id, auth.username);
    Redirect::to("/tests").into_response()
}


