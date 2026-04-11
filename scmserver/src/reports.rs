use axum::response::{Html, Response, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{Extension, Query, Path};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use tracing::error;
use serde_json;
use std::collections::HashMap;
use genpdf::{fonts, elements, style, Element};

use crate::auth::{self, UserRole, AuthSession};
use crate::handlers::render_template;
use crate::models::ReportData;
use crate::models::TestMeta;
use crate::models::SystemReport;
use crate::models::IndividualResult;
use crate::models::Report;
use crate::models::ErrorQuery;

//////////////////// Reports /////////////////////////
// reports
pub async fn reports(auth: AuthSession, Query(query): Query<ErrorQuery>,pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>) 
            -> impl IntoResponse {
        
     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
       return redir;
    }

    let rows = sqlx::query("
        SELECT
                id, submission_date, policy_name, policy_version, submitter_name from reports")
        .fetch_all(&*pool)
        .await
        .unwrap();

    let reports: Vec<Report> = rows.into_iter().map(|row| {
        Report {
            id: row.get("id"),
            submission_date: row.get("submission_date"),
            policy_name: row.get("policy_name"),
            policy_version: row.get("policy_version"),
            policy_description: None, 
            submitter_name: row.get("submitter_name"),
            tests_metadata: None,
            report_results: None,
        }
    }).collect();

    // Prepare handler-specific context
    let mut context = Context::new();
    
    if let Some(error_message) = query.error_message {
        context.insert("error_message", &error_message);
    }
    context.insert("reports", &reports);

    // Use the generic render function to render the template with global data
    render_template(&tera, Some(&pool), "reports.html", context, Some(auth)).await.into_response()
}



// reports_save
pub async fn reports_save(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

      // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
       return redir;
    }

    // 1. Fetch Policy Header
    let policy_row = match sqlx::query("SELECT name, version, description FROM policies WHERE id = ?")
        .bind(id)
        .fetch_one(&pool)
        .await {
            Ok(row) => row,
            Err(_) => return Redirect::to("/policies?error_message=Policy+not+found").into_response(),
        };

    // 2. Fetch Tests Metadata (Join tests_in_policy + tests)
    let test_rows = sqlx::query(
        r#"
        SELECT t.name, t.description, t.rational, t.remediation 
        FROM tests t
        JOIN tests_in_policy tp ON t.id = tp.test_id
        WHERE tp.policy_id = ?
        "#
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| TestMeta {
        name: row.get("name"),
        description: row.get("description"),
        rational: row.get("rational"),
        remediation: row.get("remediation"),
    }).collect();

    // 3. Fetch System Results (Join tests_in_policy + results + systems)
    let raw_results = sqlx::query(
        r#"
        SELECT 
            s.name AS system_name, 
            t.name AS test_name, 
            res.result AS status_text
        FROM tests_in_policy tip
        JOIN tests t ON tip.test_id = t.id
        JOIN results res ON t.id = res.test_id
        JOIN systems s ON res.system_id = s.id
        WHERE tip.policy_id = ?
        "#
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    // 4. Group results by system
    let mut reports_map: HashMap<String, SystemReport> = HashMap::new();
    for row in raw_results {
        let s_name: String = row.get("system_name");
        let t_name: String = row.get("test_name");
        let status_str: String = row.get("status_text");

        // 1. Calculate the boolean (checking for old "true" and new "pass" formats)
        let t_status: bool = status_str.to_lowercase() == "pass" || status_str == "true";

        // 2. Convert that bool to the String the struct expects
        let status_label = if t_status { "PASS".to_string() } else { "FAIL".to_string() };

        let entry = reports_map.entry(s_name.clone()).or_insert(SystemReport {
            system_name: s_name,
            results: Vec::new(),
            is_passed: true,
        });

        // 3. Push using the string label
        entry.results.push(IndividualResult { 
            test_name: t_name, 
            status: status_label 
        });

        if !t_status { 
            entry.is_passed = false; 
        }
    }

    let system_reports: Vec<SystemReport> = reports_map.into_values().collect();

    // 5. Serialize to JSON
    // We serialize the vectors directly to match your 'reports' table columns
    let tests_json = serde_json::to_string(&tests_metadata).unwrap_or_else(|_| "[]".to_string());
    let results_json = serde_json::to_string(&system_reports).unwrap_or_else(|_| "[]".to_string());

    // 6. Archive the snapshot
    let insert_result = sqlx::query(
          r#"
          INSERT INTO reports 
            (policy_name, policy_version, policy_description, submitter_name, tests_metadata, report_results) 
            VALUES (?, ?, ?, ?, ?, ?)
            "#
    )
    .bind(policy_row.get::<String, _>("name"))
    .bind(policy_row.get::<String, _>("version"))
    .bind(policy_row.get::<String, _>("description"))
    .bind(&auth.username)
    .bind(tests_json)
    .bind(results_json)
    .execute(&pool)
    .await;

    match insert_result {
        Ok(_) => Redirect::to("/policies?success_message=Report+saved").into_response(),
        Err(e) => {
            eprintln!("Archive Error: {}", e);
            Redirect::to("/policies?error_message=Failed+to+save+report").into_response()
        }
    }
}



// reports_view
pub async fn reports_view(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
       return redir;
    }    
    
    // 1. Fetch the single report row
    let row = match sqlx::query(
            "SELECT id, submission_date, policy_name, policy_version, policy_description, submitter_name, tests_metadata, report_results 
            FROM reports WHERE id = ?"
    )   
    .bind(id)
    .fetch_one(&*pool)
    .await 
    {
        Ok(r) => r,
        Err(e) => {
            // Use structured logging to track which report failed
            error!(error = ?e, report_id = %id, "Database Error: Failed to retrieve report for viewing");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // 2. Deserialize the JSON columns
    // SQLite returns these as Strings, so we parse them into our Rust Vecs
    let tests_metadata_raw: String = row.get("tests_metadata");
    let system_reports_raw: String = row.get("report_results");

    let tests_metadata: Vec<TestMeta> = match serde_json::from_str(&tests_metadata_raw) {
        Ok(metadata) => metadata,
        Err(e) => {
            // Log the JSON error and the raw string (if safe) to help debug the mismatch
            error!(error = ?e, "JSON Deserialization Error: Failed to parse TestMeta from database string");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let system_reports: Vec<SystemReport> = match serde_json::from_str(&system_reports_raw) {
        Ok(reports) => reports,
        Err(e) => {
            // Log the failure with tracing::error
            error!(
                error = ?e, 
                "JSON Deserialization Error: Failed to parse system_reports_raw into Vec<SystemReport>"
            );
        
            // Stop execution and return a 500 to the browser
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };


    // 3. Reconstruct the ReportData for the template
    let report_data = ReportData {
        policy_id: row.get("id"), // Or keep as 0 if the original policy ID isn't in this table
        policy_name: row.get("policy_name"),
        version: row.get("policy_version"),
        description: row.get::<Option<String>, _>("policy_description").unwrap_or_default(),
        submission_date: row.get("submission_date"),
        submitter_name: row.get("submitter_name"),
        tests_metadata,
        system_reports,
    };

    // 4. Render using the same template
    let mut context = Context::new();
    context.insert("report", &report_data);
    
    render_template(&tera, Some(&pool), "reports_view.html", context, Some(auth)).await.into_response()
}



// reports_delete
pub async fn reports_delete(auth: AuthSession, Path(id): Path<i32>, pool: Extension<SqlitePool>) 
    -> impl IntoResponse {
    
     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
       return redir;
    }

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = format!("Database error: {}", e);
            let encoded_message = urlencoding::encode(&error_message);
            return Redirect::to(&format!("/reports?error_message={}", encoded_message)).into_response();
        }
    };


    let delete_report_result = sqlx::query(
        "DELETE FROM reports WHERE id=?"
    )
    .bind(&id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = delete_report_result {
        let error_message = format!("Error deleting report: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        tx.rollback().await.ok(); // Ensure the transaction is rolled back
        return Redirect::to(&format!("/reports?error_message={}", encoded_message)).into_response();
    }

    // Commit the transaction if all queries were successful
    if let Err(e) = tx.commit().await {
        let error_message = format!("Error committing transaction: {}", e);
        let encoded_message = urlencoding::encode(&error_message);
        return Redirect::to(&format!("/reports?error_message={}", encoded_message)).into_response();
    }

    Redirect::to("/reports").into_response()
}


pub async fn reports_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {


     // check authorization
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
       return redir;
    }

    // 1. Fetch the single report row
    let row = match sqlx::query(
            "SELECT id, submission_date, policy_name, policy_version, policy_description, submitter_name, tests_metadata, report_results 
            FROM reports WHERE id = ?"
    )   
    .bind(id)
    .fetch_one(&pool)
    .await 
    {
        Ok(r) => r,
        Err(e) => {
            // Use structured logging to track which report failed
            error!(error = ?e, report_id = %id, "Database Error: Failed to retrieve report for viewing");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // 2. Deserialize the JSON columns
    // SQLite returns these as Strings, so we parse them into our Rust Vecs
    let tests_metadata_raw: String = row.get("tests_metadata");
    let system_reports_raw: String = row.get("report_results");

    let tests_metadata: Vec<TestMeta> = match serde_json::from_str(&tests_metadata_raw) {
        Ok(metadata) => metadata,
        Err(e) => {
            // Log the JSON error and the raw string (if safe) to help debug the mismatch
            error!(error = ?e, "JSON Deserialization Error: Failed to parse TestMeta from database string");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let system_reports: Vec<SystemReport> = match serde_json::from_str(&system_reports_raw) {
        Ok(reports) => reports,
        Err(e) => {
            // Log the failure with tracing::error
            error!(
                error = ?e, 
                "JSON Deserialization Error: Failed to parse system_reports_raw into Vec<SystemReport>"
            );
        
            // Stop execution and return a 500 to the browser
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };


    // 3. Reconstruct the ReportData for the template
    let report_data = ReportData {
        policy_id: row.get("id"), // Or keep as 0 if the original policy ID isn't in this table
        policy_name: row.get("policy_name"),
        version: row.get("policy_version"),
        description: row.get::<Option<String>, _>("policy_description").unwrap_or_default(),
        submission_date: row.get("submission_date"),
        submitter_name: row.get("submitter_name"),
        tests_metadata,
        system_reports,
    };

    
    // PDF GENERATION - load fonts
    const FONT_REGULAR: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES: &[u8] = include_bytes!("../static/dist/img/Logo_report.jpg");

    // Load Fonts
    let font_family = fonts::FontFamily {
        regular: fonts::FontData::new(FONT_REGULAR.to_vec(), None)
            .expect("Failed to load regular font"),
        bold: fonts::FontData::new(FONT_BOLD.to_vec(), None)
            .expect("Failed to load bold font"),
        italic: fonts::FontData::new(FONT_ITALIC.to_vec(), None)
            .expect("Failed to load italic font"),
        bold_italic: fonts::FontData::new(FONT_BOLD_ITALIC.to_vec(), None)
            .expect("Failed to load bold-italic font"),
    };

    let mut doc = genpdf::Document::new(font_family);
    let cursor = std::io::Cursor::new(LOGO_BYTES);
    let mut logo = elements::Image::from_reader(cursor).expect("Failed to load logo");

    doc.set_title(format!("OpenSCM Compliance Report - {}", report_data.policy_name));
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // Main Title
    let mut title = elements::Paragraph::new("OpenSCM Compliance Report");
    title.set_alignment(genpdf::Alignment::Center);
    doc.push(title.styled(style::Style::new().with_font_size(30).bold().with_color(style::Color::Rgb(0, 0, 128))));
    doc.push(elements::Break::new(2.0));
    let mut submitter = elements::Paragraph::new(format!("Generated on {} by {}", report_data.submission_date, report_data.submitter_name));
    submitter.set_alignment(genpdf::Alignment::Center);
    doc.push(submitter);
    doc.push(elements::Break::new(0.5));

    // Put logo to openscm
    logo.set_dpi(40.0);
    logo.set_alignment(genpdf::Alignment::Center);
    doc.push(logo);
    doc.push(elements::Break::new(1.0));


    // policy information
    // Report Details Table
    doc.push(elements::Text::new("Report Details").styled(style::Style::new().bold()));
    let mut details_table = elements::TableLayout::new(vec![1, 3]);
    details_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));
    details_table.push_row(vec![
        Box::new(elements::Text::new("Policy Name")),
        Box::new(elements::Text::new(format!(": {} v{}", report_data.policy_name, report_data.version))),
    ]);
    details_table.push_row(vec![
        Box::new(elements::Text::new("Description")),
        Box::new(elements::Text::new(format!(": {}", report_data.description))),
    ]);
    doc.push(details_table);


    doc.push(elements::PageBreak::new());

    // Per-System Audit Section
    for system in report_data.system_reports {
        doc.push(elements::Text::new(format!("Host Name: {}", system.system_name)).styled(style::Style::new().bold().with_font_size(14)));
        doc.push(elements::Break::new(0.5));

        // System Compliance Summary
        let compliant_count = system.results.iter().filter(|r| r.status == "PASS" || r.status == "true").count();
        let violation_count = system.results.len() - compliant_count;


        let mut summary_table = elements::TableLayout::new(vec![1, 1]);
        summary_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));
        summary_table.push_row(vec![
            Box::new(elements::Text::new("Compliance Status")),
            Box::new(elements::Text::new(if system.is_passed { ": Compliant" } else { ": Non-Compliant" })
                .styled(style::Style::new().with_color(if system.is_passed { style::Color::Rgb(0, 128, 0) } else { style::Color::Rgb(200, 0, 0) }).bold())),
        ]);
        summary_table.push_row(vec![
            Box::new(elements::Text::new("Violation Rule Count")),
            Box::new(elements::Text::new(format!(": Critical - {}", violation_count))),
        ]);
        summary_table.push_row(vec![
            Box::new(elements::Text::new("Compliant Rule Count")),
            Box::new(elements::Text::new(format!(": {}", compliant_count))),
        ]);
        doc.push(summary_table);
        doc.push(elements::Break::new(1.0));

        // Detailed Rules Breakdown
        doc.push(elements::Text::new("Audit Rules Detailed Breakdown").styled(style::Style::new().bold()));
        let mut rules_table = elements::TableLayout::new(vec![2, 1, 4]);
        rules_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));
        rules_table.push_row(vec![
            Box::new(elements::Text::new("Rule Name").styled(style::Style::new().bold())),
            Box::new(elements::Text::new("Status").styled(style::Style::new().bold())),
            Box::new(elements::Text::new("Description").styled(style::Style::new().bold())),
        ]);

        for res in &system.results {
            let desc = report_data.tests_metadata.iter()
                .find(|t| t.name == res.test_name)
                .map(|t| t.description.as_str())
                .unwrap_or("No description provided");

            let is_pass = res.status == "PASS" || res.status == "true";

            let (status_text, status_color) = if is_pass {
                ("PASS", style::Color::Rgb(0, 128, 0))
            } else {
                ("FAIL", style::Color::Rgb(200, 0, 0))
            };


            rules_table.push_row(vec![
                Box::new(elements::Text::new(&res.test_name)),
                Box::new(elements::Text::new(status_text).styled(style::Style::new().with_color(status_color).bold())),
                Box::new(elements::Text::new(desc)),
            ]);
        }
        doc.push(rules_table);
        doc.push(elements::PageBreak::new());
    }

    // Confidentiality Footer
    doc.push(elements::Break::new(2.0));
    doc.push(elements::Paragraph::new("Note: This report contains confidential information about your infrastructure and should be treated as such. Unauthorized distribution is strictly prohibited.")
        .styled(style::Style::new().with_font_size(10).with_color(style::Color::Rgb(100, 100, 100))));

    // 3. RENDER & RESPONSE
    let mut buffer = Vec::new();
    doc.render(&mut buffer).unwrap();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"OpenSCM_Report_{}.pdf\"", id))
        .body(axum::body::Body::from(buffer))
        .unwrap()
        .into_response()
}
