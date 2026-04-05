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
    let row_result = sqlx::query("
                SELECT id,name,description,severity,rational,remediation,filter,
                element_1,input_1,selement_1,condition_1,sinput_1,
                element_2,input_2,selement_2,condition_2,sinput_2,
                element_3,input_3,selement_3,condition_3,sinput_3,
                element_4,input_4,selement_4,condition_4,sinput_4,
                element_5,input_5,selement_5,condition_5,sinput_5
                from tests where id=?")
    .bind(id)
    .fetch_optional(&*pool)
    .await;

    // Handle potential Database Errors AND missing rows
    let row = match row_result {
        Ok(Some(r)) => r, // We found the test
        Ok(None) => {     // The query worked, but no test found
            return Redirect::to("/tests?error_message=Test+not+found").into_response();
        }
        Err(e) => {      // Database error (connection lost, etc.)
            error!("Database error: {}", e);
            return Redirect::to("/tests?error_message=Database+error").into_response();
        }
    };


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
    render_template(&tera, Some(&pool), "tests_edit.html", context, Some(auth)).await.into_response()
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


