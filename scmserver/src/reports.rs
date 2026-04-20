use axum::response::{Response, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{Extension, Query, Path};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use std::collections::BTreeMap;
use tracing::{info, error};
use serde_json;
use urlencoding;
use genpdf::{fonts, elements, style, Element};

use crate::auth::{self};
use crate::handlers::{render_template, normalize_status};
use crate::models::{
    UserRole, TestMeta, SystemReport, IndividualResult,
    Report, ErrorQuery, AuthSession,
};


// ============================================================
// HANDLERS
// ============================================================

pub async fn reports(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let rows_result = sqlx::query(
        "SELECT id, submission_date, policy_name, policy_version, submitter_name
         FROM reports
         WHERE tenant_id = ?
         ORDER BY submission_date DESC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&*pool)
    .await;

    let reports: Vec<Report> = match rows_result {
        Ok(rows) => rows
            .into_iter()
            .map(|row| Report {
                id: row.get("id"),
                tenant_id: auth.tenant_id.clone(),
                submission_date: row.get("submission_date"),
                policy_name: row.get("policy_name"),
                policy_version: row.get("policy_version"),
                policy_description: None,
                submitter_name: row.get("submitter_name"),
                tests_metadata: None,
                report_results: None,
            })
            .collect(),
        Err(e) => {
            error!("Failed to fetch reports: {}", e);
            let mut context = Context::new();
            context.insert("error_message", "Failed to load reports.");
            context.insert("reports", &Vec::<Report>::new());
            return render_template(&tera, Some(&pool), "reports.html", context, Some(auth))
                .await
                .into_response();
        }
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    context.insert("reports", &reports);
    render_template(&tera, Some(&pool), "reports.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn reports_save(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    // Fetch policy header — verify tenant ownership
    let policy_row = match sqlx::query(
        "SELECT name, version, description FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return Redirect::to("/policies?error_message=Policy+not+found").into_response(),
        Err(e) => {
            error!("Failed to fetch policy {} for report save: {}", id, e);
            return Redirect::to("/policies?error_message=Database+error").into_response();
        }
    };

    // Fetch tests metadata
    let test_rows = match sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation
        FROM tests t
        JOIN tests_in_policy tp ON t.id = tp.test_id
        WHERE tp.policy_id = ? AND tp.tenant_id = ?
    "#)
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch tests for report save {}: {}", id, e);
            return Redirect::to("/policies?error_message=Failed+to+fetch+tests").into_response();
        }
    };

    let tests_metadata: Vec<TestMeta> = test_rows
        .into_iter()
        .map(|row| TestMeta {
            name: row.get("name"),
            description: row.get("description"),
            rational: row.get("rational"),
            remediation: row.get("remediation"),
        })
        .collect();

    // Fetch system results
    let raw_results = match sqlx::query(r#"
        SELECT
            s.name AS system_name,
            t.name AS test_name,
            res.result AS status_text
        FROM tests_in_policy tip
        JOIN tests t ON tip.test_id = t.id
        JOIN results res ON t.id = res.test_id
        JOIN systems s ON res.system_id = s.id
        WHERE tip.policy_id = ? AND tip.tenant_id = ?
    "#)
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch results for report save {}: {}", id, e);
            return Redirect::to("/policies?error_message=Failed+to+fetch+results").into_response();
        }
    };

    // Group results by system using BTreeMap for consistent ordering
    let mut reports_map: BTreeMap<String, SystemReport> = BTreeMap::new();
    for row in raw_results {
        let s_name: String = row.get("system_name");
        let t_name: String = row.get("test_name");
        let status_raw: String = row.get("status_text");
        let status = normalize_status(&status_raw).to_string();
        let passed = status == "PASS";

        let entry = reports_map.entry(s_name.clone()).or_insert(SystemReport {
            system_name: s_name,
            results: Vec::new(),
            is_passed: true,
        });

        entry.results.push(IndividualResult {
            test_name: t_name,
            status,
        });

        if !passed {
            entry.is_passed = false;
        }
    }

    let system_reports: Vec<SystemReport> = reports_map.into_values().collect();

    // Serialize to JSON for storage
    let tests_json = match serde_json::to_string(&tests_metadata) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize tests metadata: {}", e);
            return Redirect::to("/policies?error_message=Failed+to+serialize+report").into_response();
        }
    };

    let results_json = match serde_json::to_string(&system_reports) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize system reports: {}", e);
            return Redirect::to("/policies?error_message=Failed+to+serialize+report").into_response();
        }
    };

    // Archive the snapshot
    match sqlx::query(r#"
        INSERT INTO reports
            (tenant_id, policy_name, policy_version, policy_description,
             submitter_name, tests_metadata, report_results)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    "#)
    .bind(&auth.tenant_id)
    .bind(policy_row.get::<String, _>("name"))
    .bind(policy_row.get::<String, _>("version"))
    .bind(policy_row.get::<Option<String>, _>("description"))
    .bind(&auth.username)
    .bind(tests_json)
    .bind(results_json)
    .execute(&pool)
    .await
    {
        Ok(_) => {
            info!("Report saved for policy {} by '{}'.", id, auth.username);
            Redirect::to("/policies?success_message=Report+saved").into_response()
        }
        Err(e) => {
            error!("Failed to archive report for policy {}: {}", id, e);
            Redirect::to("/policies?error_message=Failed+to+save+report").into_response()
        }
    }
}


pub async fn reports_view(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
    tera: Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    // Fetch the saved report
    let report = match sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, submission_date, policy_name, policy_version,
                policy_description, submitter_name, tests_metadata, report_results
         FROM reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&*pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to fetch report for viewing");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Deserialize JSON fields
    let tests_metadata: Vec<TestMeta> = match serde_json::from_str(
        report.tests_metadata.as_deref().unwrap_or("[]"),
    ) {
        Ok(m) => m,
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to deserialize tests metadata");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let system_reports: Vec<SystemReport> = match serde_json::from_str(
        report.report_results.as_deref().unwrap_or("[]"),
    ) {
        Ok(r) => r,
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to deserialize system reports");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let fail_count = system_reports.iter().filter(|s| !s.is_passed).count();

    let mut context = Context::new();
    context.insert("report", &report);
    context.insert("tests_metadata", &tests_metadata);
    context.insert("system_reports", &system_reports);
    context.insert("fail_count", &fail_count);
    render_template(&tera, Some(&pool), "reports_view.html", context, Some(auth))
        .await
        .into_response()
}


pub async fn reports_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    pool: Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    if let Err(e) = sqlx::query("DELETE FROM reports WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&*pool)
        .await
    {
        error!("Failed to delete report {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting report: {}", e)).to_string();
        return Redirect::to(&format!("/reports?error_message={}", encoded)).into_response();
    }

    info!("Report ID {} deleted by '{}'.", id, auth.username);
    Redirect::to("/reports").into_response()
}


pub async fn reports_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    // Fetch the saved report
    let report = match sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, submission_date, policy_name, policy_version,
                policy_description, submitter_name, tests_metadata, report_results
         FROM reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to fetch report for download");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };


    let system_reports: Vec<SystemReport> = match serde_json::from_str(
        report.report_results.as_deref().unwrap_or("[]"),
    ) {
        Ok(r) => r,
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to deserialize system reports for download");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // PDF Generation
    const FONT_REGULAR: &[u8] =
        include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD: &[u8] =
        include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC: &[u8] =
        include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] =
        include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES: &[u8] =
        include_bytes!("../static/dist/img/Logo_report.jpg");

    let font_family = match (
        fonts::FontData::new(FONT_REGULAR.to_vec(), None),
        fonts::FontData::new(FONT_BOLD.to_vec(), None),
        fonts::FontData::new(FONT_ITALIC.to_vec(), None),
        fonts::FontData::new(FONT_BOLD_ITALIC.to_vec(), None),
    ) {
        (Ok(regular), Ok(bold), Ok(italic), Ok(bold_italic)) => fonts::FontFamily {
            regular,
            bold,
            italic,
            bold_italic,
        },
        _ => {
            error!("Failed to load PDF fonts for report download {}", id);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut doc = genpdf::Document::new(font_family);

    let cursor = std::io::Cursor::new(LOGO_BYTES);
    let mut logo = match elements::Image::from_reader(cursor) {
        Ok(img) => img,
        Err(e) => {
            error!("Failed to load PDF logo for report {}: {}", id, e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    doc.set_title(format!("OpenSCM Compliance Report - {}", report.policy_name));
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // Title
    let mut title = elements::Paragraph::new("OpenSCM Compliance Report");
    title.set_alignment(genpdf::Alignment::Center);
    doc.push(title.styled(
        style::Style::new()
            .with_font_size(30)
            .bold()
            .with_color(style::Color::Rgb(0, 0, 128)),
    ));
    doc.push(elements::Break::new(2.0));

    let mut submitter = elements::Paragraph::new(format!(
        "Generated on {} by {}",
        report.submission_date,
        report.submitter_name.as_deref().unwrap_or("Unknown"),
    ));
    submitter.set_alignment(genpdf::Alignment::Center);
    doc.push(submitter);
    doc.push(elements::Break::new(0.5));

    logo.set_dpi(40.0);
    logo.set_alignment(genpdf::Alignment::Center);
    doc.push(logo);
    doc.push(elements::Break::new(1.0));

    // Report details table
    doc.push(elements::Text::new("Report Details")
        .styled(style::Style::new().bold().with_font_size(14)));
    doc.push(elements::Break::new(0.5));
    let mut details_table = elements::TableLayout::new(vec![1, 3]);
    details_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

    if let Err(e) = details_table.push_row(vec![
        Box::new(elements::Text::new("Policy Name").styled(style::Style::new().bold())),
        Box::new(elements::Paragraph::new(format!(
            " {} v{}",
            report.policy_name,
            report.policy_version.as_deref().unwrap_or(""),
        ))),
    ]) {
        error!("Failed to add policy name row to PDF: {}", e);
    }

    if let Err(e) = details_table.push_row(vec![
        Box::new(elements::Text::new("Description").styled(style::Style::new().bold())),
        Box::new(elements::Paragraph::new(format!(
            " {}",
            report.policy_description.as_deref().unwrap_or(""),
        ))),
    ]) {
        error!("Failed to add description row to PDF: {}", e);
    }

    doc.push(details_table);
    doc.push(elements::PageBreak::new());

    // Per-system audit section
    for system in &system_reports {
        doc.push(
            elements::Text::new(format!("Host Name: {}", system.system_name))
                .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        let compliant_count = system.results.iter().filter(|r| r.status == "PASS").count();
        let violation_count = system.results.len() - compliant_count;

        let mut summary_table = elements::TableLayout::new(vec![1, 1]);
        summary_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Compliance Status").styled(style::Style::new().bold())),
            Box::new(
                elements::Text::new(if system.is_passed {
                    " Compliant"
                } else {
                    " Non-Compliant"
                })
                .styled(
                    style::Style::new()
                        .with_color(if system.is_passed {
                            style::Color::Rgb(0, 128, 0)
                        } else {
                            style::Color::Rgb(200, 0, 0)
                        })
                        .bold(),
                ),
            ),
        ]) {
            error!("Failed to add compliance status row to PDF: {}", e);
        }

        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Violation Rule Count").styled(style::Style::new().bold())),
            Box::new(elements::Text::new(format!(" Critical - {}", violation_count))),
        ]) {
            error!("Failed to add violation count row to PDF: {}", e);
        }

        if let Err(e) = summary_table.push_row(vec![
            Box::new(elements::Text::new("Compliant Rule Count").styled(style::Style::new().bold())),
            Box::new(elements::Text::new(format!(" {}", compliant_count))),
        ]) {
            error!("Failed to add compliant count row to PDF: {}", e);
        }

        doc.push(summary_table);
        doc.push(elements::Break::new(1.0));

        // Rules breakdown
        doc.push(
            elements::Text::new("Audit Rules Detailed Breakdown")
                .styled(style::Style::new().bold().with_font_size(14)),   
        );
        doc.push(elements::Break::new(0.5));
        let mut rules_table = elements::TableLayout::new(vec![4, 1]);
        rules_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = rules_table.push_row(vec![
            Box::new(elements::Text::new("Rule Name").styled(style::Style::new().bold())),
            Box::new(elements::Text::new("Status").styled(style::Style::new().bold())),
        ]) {
            error!("Failed to add rules table header to PDF: {}", e);
        }

        for res in &system.results {
            let is_pass = res.status == "PASS";
            let (status_text, status_color) = if is_pass {
                ("PASS", style::Color::Rgb(0, 128, 0))
            } else {
                ("FAIL", style::Color::Rgb(200, 0, 0))
            };

            if let Err(e) = rules_table.push_row(vec![
                Box::new(elements::Paragraph::new(&res.test_name)),
                Box::new(
                    elements::Text::new(status_text)
                        .styled(style::Style::new().with_color(status_color).bold()),
                ),
            ]) {
                error!("Failed to add rule row to PDF: {}", e);
            }
        }

        doc.push(rules_table);
        doc.push(elements::PageBreak::new());
    }

    doc.push(elements::Break::new(2.0));
    doc.push(
        elements::Paragraph::new(
            "Note: This report contains confidential information about your infrastructure \
             and should be treated as such. Unauthorized distribution is strictly prohibited.",
        )
        .styled(
            style::Style::new()
                .with_font_size(10)
                .with_color(style::Color::Rgb(100, 100, 100)),
        ),
    );

    // Render PDF
    let mut buffer = Vec::new();
    if let Err(e) = doc.render(&mut buffer) {
        error!("Failed to render PDF for report {}: {}", id, e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"OpenSCM_Report_{}.pdf\"", id),
        )
        .body(axum::body::Body::from(buffer))
        .unwrap_or_else(|e| {
            error!("Failed to build PDF response for report {}: {}", id, e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}
