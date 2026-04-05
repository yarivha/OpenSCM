use axum::response::{Html, Response, IntoResponse, Redirect};
use axum::http::{StatusCode,header} ;
use axum::extract::{RawForm, Extension, Query, Path};
use axum::Form; 
use http_body_util::Full;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use std::error::Error;
use std::fs;
use urlencoding;
use std::collections::BTreeMap;
use tracing::error;
use chrono::Local;
use genpdf::{elements, style, Element};


use crate::models::ErrorQuery;
use crate::models::SystemGroup;
use crate::models::Test;
use crate::models::Policy;
use crate::models::SystemInsidePolicy;
use crate::models::TestInsidePolicy;
use crate::models::PolicyCompliance;
use crate::models::ReportData;
use crate::models::TestMeta;
use crate::models::SystemReport;
use crate::models::IndividualResult;
use crate::auth::AuthSession;
use crate::handlers::render_template;
use crate::handlers::parse_form_data;
use crate::handlers::not_found;



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

let row_result = sqlx::query("
                SELECT id,name,version,description from policies where id=?")
    .bind(id)
    .fetch_optional(&*pool)
    .await;

    // Handle potential Database Errors AND missing rows
    let row = match row_result {
        Ok(Some(r)) => r, // We found the test
        Ok(None) => {     // The query worked, but no test found
            return Redirect::to("/policies?error_message=Policy+not+found").into_response();
        }
        Err(e) => {      // Database error (connection lost, etc.)
            error!("Database error: {}", e);
            return Redirect::to("/tests?error_message=Database+error").into_response();
        }
    };

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
    render_template(&tera,Some(&pool), "policies_edit.html", context, Some(auth)).await.into_response()

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


// policies_report
pub async fn policies_report(auth: AuthSession,  Path(id): Path<i32>,pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>)
    -> Result<Html<String>, StatusCode> {


    // Safely get the username
    let submitter_name = auth.username.clone();

    // 1. Fetch Policy
    let policy_row = sqlx::query("SELECT id, name, version, description FROM policies WHERE id = ?")
        .bind(id)
        .fetch_one(&*pool)
        .await
        .map_err(|e| {
            eprintln!("Database Error (Policy): {}", e);
            StatusCode::NOT_FOUND 
        })?;

    // 2. Fetch Tests
    let test_rows = sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation 
        FROM tests t
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE tip.policy_id = ?"#)
        .bind(id)
        .fetch_all(&*pool)
        .await
        .map_err(|e| {
            eprintln!("Database Error (Tests): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR 
        })?;

    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| {
        TestMeta {
            name: row.get("name"),
            description: row.get("description"),
            rational: row.get("rational"),
            remediation: row.get("remediation"),
        }
    }).collect();

    // 3. Fetch Results
    let result_rows = sqlx::query(r#"
        SELECT DISTINCT
            s.name as system_name,
            t.name as test_name,
            r.result as status
        FROM results r
        JOIN systems s ON r.system_id = s.id
        JOIN tests t ON r.test_id = t.id
        JOIN systems_in_groups sig ON s.id = sig.system_id
        JOIN systems_in_policy sip ON sig.group_id = sip.group_id
        JOIN tests_in_policy tip ON t.id = tip.test_id
        WHERE sip.policy_id = ?
          AND tip.policy_id = ?"#)
        .bind(id)
        .bind(id)
        .fetch_all(&*pool)
        .await
        .map_err(|e| {
            eprintln!("Database Error (Results): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // 4. Group results by System Name
    let mut system_map: BTreeMap<String, Vec<IndividualResult>> = BTreeMap::new();
    for row in result_rows {
        // Use Option to handle cases where a system name might be NULL
        let system_name = row.get::<Option<String>, _>("system_name")
            .unwrap_or_else(|| "Unknown System".to_string());
            
        let test_name: String = row.get("test_name");
        let status_str: String = row.get("status");
        let status = status_str == "true";

        system_map
            .entry(system_name)
            .or_insert_with(Vec::new)
            .push(IndividualResult { test_name, status });
    }

    // Convert the BTreeMap into a Vec<SystemReport>
    let system_reports: Vec<SystemReport> = system_map
    .into_iter()
    .map(|(name, results)| {
        // A system is passed ONLY if all its results are true
        let is_passed = results.iter().all(|r| r.status);

        SystemReport {
            system_name: name,
            results,
            is_passed, // Pass the pre-calculated value
        }
    })
    .collect();


    // Build context
    let report_data = ReportData {
        policy_id: policy_row.get("id"),
        policy_name: policy_row.get("name"),
        version: policy_row.get("version"),
        description: policy_row.get::<Option<String>, _>("description").unwrap_or_default(),
        submission_date: Local::now().format("%Y-%m-%d %H:%M").to_string(),
        submitter_name,
        tests_metadata,
        system_reports, // Now this variable exists!
    };

    let mut context = Context::new();
    context.insert("report", &report_data);
    render_template(&tera,Some(&pool),"policies_report.html", context, Some(auth)).await
}


pub async fn policies_report_save(
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    // --- 1. DATA FETCHING ---
    // In a real scenario, you'd join your policies, tests, and results tables here.
    // For this example, we'll build the ReportData object based on the ID.
    let policy_name = "Standard Security Hardening";

    // Example: Fetching the policy description from DB
    let description = match sqlx::query("SELECT description FROM policies WHERE id = ?")
        .bind(id)
        .fetch_one(&pool)
        .await {
            Ok(row) => row.get::<String, _>("description"),
            Err(_) => "OpenSCM Compliance Policy".to_string(),
        };

    // --- 2. PDF INITIALIZATION ---
    let font_dir = "./static/dist/fonts";
    let font_family = match genpdf::fonts::from_files(font_dir, "LiberationSans", None) {
        Ok(f) => f,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Font files missing in /dist/fonts").into_response(),
    };

    let mut doc = genpdf::Document::new(font_family);
    doc.set_title(format!("OpenSCM Report - {}", policy_name));

    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // --- 3. BUILDING THE PDF CONTENT ---

    // Header Section
    doc.push(elements::Text::new("OpenSCM Compliance Report")
        .styled(style::Style::new().with_color(style::Color::Rgb(0, 0, 128)).bold()));
    doc.push(elements::Break::new(1.5));
    doc.push(elements::Paragraph::new(format!("Policy: {}", policy_name)));
    doc.push(elements::Paragraph::new(format!("Report ID: {}", id)));
    doc.push(elements::Paragraph::new(format!("Description: {}", description)));
    doc.push(elements::Break::new(2.0));

    // Results Table (Example with one system - you would loop through your DB results here)
    doc.push(elements::Text::new("System Results").styled(style::Style::new().bold()));
    doc.push(elements::Break::new(1.0));

    let mut table = elements::TableLayout::new(vec![3, 1]);
    table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

    // Table Header (Must be Boxed)
    table.push_row(vec![
        Box::new(elements::Text::new("Security Control").styled(style::Style::new().bold())),
        Box::new(elements::Text::new("Status").styled(style::Style::new().bold())),
    ]);

    // Example Row (You would put your 'for' loop here)
    let test_status = true; // Mock status
    let (status_text, status_color) = if test_status {
        ("PASS", style::Color::Rgb(0, 128, 0))
    } else {
        ("FAIL", style::Color::Rgb(200, 0, 0))
    };

    table.push_row(vec![
        Box::new(elements::Text::new("Ensure Password Complexity is Enabled")),
        Box::new(elements::Text::new(status_text)
            .styled(style::Style::new().with_color(status_color).bold())),
    ]);

    doc.push(table);

    // --- 4. RENDERING & RESPONSE ---
    let mut buffer = Vec::new();
    if let Err(e) = doc.render(&mut buffer) {
        return (StatusCode::INTERNAL_SERVER_ERROR, "PDF Render Error").into_response();
    }

    // --- NEW: SAVE TO SERVER LOGIC ---
    
    // 1. Define the storage path
    let storage_dir = "./storage/reports";
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let file_path = format!("{}/report_{}_{}.pdf", storage_dir, id, timestamp);

    // 2. Create the directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(storage_dir) {
        tracing::error!("Failed to create storage directory: {}", e);
        // We continue anyway so the user still gets their download
    } else {
        // 3. Write the buffer to the server's disk asynchronously
        if let Err(e) = fs::write(&file_path, &buffer) {
            tracing::error!("Failed to save report to server: {}", e);
        } else {
            println!("Report saved successfully to: {}", file_path);
            
            // OPTIONAL: Update your DB to record the file path
            // let _ = sqlx::query("UPDATE policies SET last_report_path = ? WHERE id = ?")
            //     .bind(&file_path).bind(id).execute(&pool).await;
        }
    }

    // --- RETURN TO BROWSER ---
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION, 
            format!("attachment; filename=\"OpenSCM_Report_{}.pdf\"", id)
        )
        .body(axum::body::Body::from(buffer))
        .unwrap()
        .into_response()
}
