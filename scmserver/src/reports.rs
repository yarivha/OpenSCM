// =============================================================================
// reports.rs — saved report CRUD, PDF download, and bulk actions
//
// Handles both policy reports (snapshots of policy compliance results) and
// system reports (snapshots of per-system compliance data). All routes are
// tenant-scoped. Viewer for reads; Runner to save; Editor for deletes.
// =============================================================================

use axum::response::{Response, IntoResponse, Redirect};
use axum::http::{StatusCode, header};
use axum::extract::{RawForm, Extension, Query, Path};
use bytes::Bytes;
use tera::{Tera, Context};
use sqlx::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use std::collections::BTreeMap;
use tracing::{info, error};
use serde_json;
use urlencoding;
use genpdf::{fonts, elements, style, Element, Margins};

use crate::auth::{self};
use crate::handlers::{render_template, normalize_status, parse_form_data, is_system_passed};
use crate::models::{
    UserRole, TestMeta, SystemReport, IndividualResult,
    Report, SavedSystemReport, ErrorQuery, AuthSession, SystemReportData,
};
use crate::systems::fetch_system_report_data;


// ============================================================
// HANDLERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// GET /reports
// List all saved policy reports and system reports for the current tenant.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports(
    auth: AuthSession,
    Query(query): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    // Fetch policy reports
    let policy_reports: Vec<Report> = match sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                policy_name, policy_version, NULL as policy_description,
                submitter_name, NULL as tests_metadata, NULL as report_results
         FROM reports
         WHERE tenant_id = ?
         ORDER BY submission_date DESC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch policy reports: {}", e);
            vec![]
        }
    };

    // Fetch system reports
    let system_reports: Vec<SavedSystemReport> = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, NULL as report_data
         FROM system_reports
         WHERE tenant_id = ?
         ORDER BY submission_date DESC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Failed to fetch system reports: {}", e);
            vec![]
        }
    };

    let mut context = Context::new();
    if let Some(msg) = query.error_message {
        context.insert("error_message", &msg);
    }
    if let Some(msg) = query.success_message {
        context.insert("success_message", &msg);
    }
    context.insert("reports", &policy_reports);
    context.insert("system_reports", &system_reports);
    render_template(&tera, Some(&pool), "reports.html", context, Some(auth))
        .await
        .into_response()
}



// ─────────────────────────────────────────────────────────────────────────────
// Helper: save_policy_report_logic
// Snapshots current policy compliance results to the reports table.
// Called by the HTTP handler and the background scheduler.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn save_policy_report_logic(
    id: i64,
    pool: &SqlitePool,
    tenant_id: &str,
    submitter_name: &str,
) -> Result<(), sqlx::Error> {

    // Fetch policy header
    let policy_row = match sqlx::query(
        "SELECT name, version, description FROM policies WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    {
        Some(row) => row,
        None => {
            error!("Policy {} not found for report save.", id);
            return Ok(());
        }
    };

    // Fetch tests metadata
    let test_rows = sqlx::query(r#"
        SELECT t.name, t.description, t.rational, t.remediation
        FROM tests t
        JOIN tests_in_policy tp ON t.id = tp.test_id
        WHERE tp.policy_id = ? AND tp.tenant_id = ?
    "#)
    .bind(id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let tests_metadata: Vec<TestMeta> = test_rows.into_iter().map(|row| TestMeta {
        name: row.get("name"),
        description: row.get("description"),
        rational: row.get("rational"),
        remediation: row.get("remediation"),
    }).collect();

    // Fetch system results — tenant_id is enforced on every join (M2 tenant isolation fix).
    let raw_results = sqlx::query(r#"
        SELECT
            s.name AS system_name,
            t.name AS test_name,
            res.result AS status_text
        FROM tests_in_policy tip
        JOIN tests t ON tip.test_id = t.id
        JOIN results res ON t.id = res.test_id AND res.tenant_id = tip.tenant_id
        JOIN systems s ON res.system_id = s.id AND s.tenant_id = tip.tenant_id
        WHERE tip.policy_id = ? AND tip.tenant_id = ?
    "#)
    .bind(id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    // Group results by system
    let mut reports_map: BTreeMap<String, SystemReport> = BTreeMap::new();
    for row in raw_results {
        let s_name: String = row.get("system_name");
        let t_name: String = row.get("test_name");
        let status_raw: String = row.get("status_text");
        let status = normalize_status(&status_raw).to_string();

        let entry = reports_map.entry(s_name.clone()).or_insert(SystemReport {
            system_name: s_name,
            results: Vec::new(),
            is_passed: false,
            pass_count: 0,
            fail_count: 0,
        });

        entry.results.push(IndividualResult { test_name: t_name, status: status.clone() });
    }

    // Recalculate is_passed, pass_count, and fail_count after all results are collected.
    // A system passes when it has no FAILs AND at least one PASS.
    // All-NA systems (pass_count == 0 && fail_count == 0) are shown as "NOT APPLICABLE"
    // by the template — is_passed value does not affect their display.
    for entry in reports_map.values_mut() {
        entry.pass_count = entry.results.iter().filter(|r| r.status == "PASS").count();
        entry.fail_count = entry.results.iter().filter(|r| r.status == "FAIL").count();
        entry.is_passed = is_system_passed(entry.pass_count, entry.fail_count);
    }

    let system_reports: Vec<SystemReport> = reports_map.into_values().collect();

    // Serialize
    let tests_json = serde_json::to_string(&tests_metadata)
        .map_err(|e| sqlx::Error::Protocol(format!("Failed to serialize tests: {}", e)))?;
    let results_json = serde_json::to_string(&system_reports)
        .map_err(|e| sqlx::Error::Protocol(format!("Failed to serialize results: {}", e)))?;

    // Save report
    sqlx::query(r#"
        INSERT INTO reports
            (tenant_id, policy_name, policy_version, policy_description,
             submitter_name, tests_metadata, report_results)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    "#)
    .bind(tenant_id)
    .bind(policy_row.get::<String, _>("name"))
    .bind(policy_row.get::<String, _>("version"))
    .bind(policy_row.get::<Option<String>, _>("description"))
    .bind(submitter_name)
    .bind(tests_json)
    .bind(results_json)
    .execute(pool)
    .await?;

    info!("Report saved for policy {} by '{}'.", id, submitter_name);
    Ok(())
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/save/{id}
// Save a snapshot of the current policy compliance results.
// Role: Runner
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_save(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    match save_policy_report_logic(id, &pool, &auth.tenant_id, &auth.username).await {
        Ok(_) => {
            info!("Report saved for policy {} by '{}'.", id, auth.username);
            Redirect::to(&format!("/policies/report/{}?success_message=Report+saved", id)).into_response()
        }
        Err(e) => {
            error!("Failed to save report for policy {}: {}", id, e);
            Redirect::to(&format!("/policies/report/{}?error_message=Failed+to+save+report", id)).into_response()
        }
    }
}



// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/view/{id}
// View a saved policy compliance report snapshot.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_view(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(query): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    // Fetch the saved report
    let report = match sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                policy_name, policy_version, policy_description,
                submitter_name, tests_metadata, report_results
         FROM reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/reports?error_message=Report+not+found").into_response(),
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

    let mut system_reports: Vec<SystemReport> = match serde_json::from_str(
        report.report_results.as_deref().unwrap_or("[]"),
    ) {
        Ok(r) => r,
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to deserialize system reports");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Backfill pass_count/fail_count for reports saved before those fields existed.
    for s in &mut system_reports {
        if s.pass_count == 0 && s.fail_count == 0 && !s.results.is_empty() {
            s.pass_count = s.results.iter().filter(|r| r.status == "PASS").count();
            s.fail_count = s.results.iter().filter(|r| r.status == "FAIL").count();
            s.is_passed  = is_system_passed(s.pass_count, s.fail_count);
        }
    }

    // Check if the originating policy still exists (by name + version)
    let live_policy_id: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM policies WHERE name = ? AND version = ? AND tenant_id = ?",
    )
    .bind(&report.policy_name)
    .bind(report.policy_version.as_deref().unwrap_or(""))
    .bind(&auth.tenant_id)
    .fetch_optional(&pool)
    .await
    .unwrap_or(None);

    let fail_count = system_reports.iter().filter(|s| s.fail_count > 0).count();

    let mut context = Context::new();
    context.insert("report", &report);
    context.insert("tests_metadata", &tests_metadata);
    context.insert("system_reports", &system_reports);
    context.insert("fail_count", &fail_count);
    context.insert("live_policy_id", &live_policy_id);
    context.insert("is_smtp_configured", &is_smtp_configured(&pool).await);
    if let Some(msg) = query.success_message { context.insert("success_message", &msg); }
    if let Some(msg) = query.error_message   { context.insert("error_message",   &msg); }
    render_template(&tera, Some(&pool), "reports_view.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/delete/{id}
// Delete a saved policy compliance report.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    if let Err(e) = sqlx::query("DELETE FROM reports WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
    {
        error!("Failed to delete report {}: {}", id, e);
        let encoded = urlencoding::encode(&format!("Error deleting report: {}", e)).to_string();
        return Redirect::to(&format!("/reports?error_message={}", encoded)).into_response();
    }

    info!("Report ID {} deleted by '{}'.", id, auth.username);
    Redirect::to("/reports").into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: cell
// Wraps a PDF element with uniform cell padding for table layout.
// ─────────────────────────────────────────────────────────────────────────────
fn cell<E: Element + 'static>(e: E) -> Box<dyn Element> {
    Box::new(elements::PaddedElement::new(e, Margins::trbl(1.5, 2.0, 1.5, 2.0)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers shared by the four "Email Me PDF" handlers (reports_email,
// system_reports_email, policies_report_email, system_report_live_email).
// Kept tiny and stringly-typed because the flash flow is the same across all
// four endpoints — flag SMTP missing, missing user email, render failure,
// SMTP failure, success — and we want the same wording everywhere.
// ─────────────────────────────────────────────────────────────────────────────

// is_smtp_configured — used by the four report-view handlers to decide
// whether to render the "Email Me PDF" button on the page.
pub async fn is_smtp_configured(pool: &SqlitePool) -> bool {
    let host: String = sqlx::query_scalar(
        "SELECT value FROM settings WHERE tenant_id = 'default' AND skey = 'smtp_host'",
    )
    .fetch_optional(pool).await.unwrap_or(None).unwrap_or_default();
    !host.trim().is_empty()
}

// user_email — fetch the logged-in user's email from the users table,
// returning None for empty/missing values so callers can flash a clear
// error rather than try to send to "".
pub(crate) async fn user_email(pool: &SqlitePool, user_id: i32, tenant_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT email FROM users WHERE id = ? AND tenant_id = ?",
    )
    .bind(user_id).bind(tenant_id)
    .fetch_optional(pool).await
    .unwrap_or(None).flatten()
    .filter(|e| !e.trim().is_empty())
}

// flash_back — redirect to `back` with a flash message. Single helper so
// every email handler reads the same way. `ok = true` becomes success_message,
// `ok = false` becomes error_message.
pub(crate) fn flash_back(back: &str, ok: bool, msg: &str) -> Response {
    let key = if ok { "success_message" } else { "error_message" };
    let encoded = urlencoding::encode(msg).to_string();
    let sep = if back.contains('?') { '&' } else { '?' };
    Redirect::to(&format!("{}{}{}={}", back, sep, key, encoded)).into_response()
}

// report_email_body — short HTML wrapper for the report email itself.
// Kept generic so the same body works for policy-archive, policy-live,
// system-archive, and system-live reports.
pub(crate) fn report_email_body(name: &str, version: &str, when: &str) -> String {
    let version_line = if version.is_empty() {
        String::new()
    } else {
        format!("<p><strong>Version:</strong> {}</p>", version)
    };
    format!(
        r#"<p>The OpenSCM compliance report you requested is attached as a PDF.</p>
<p><strong>Report:</strong> {name}</p>
{version_line}
<p><strong>Generated:</strong> {when}</p>
<p>This report contains confidential information about your infrastructure
and should be treated as such.</p>"#
    )
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: fetch_archive_policy_report
// Pulls a saved policy report + its system_reports + tests_metadata in the
// shape the PDF builder wants. Returns None if the row doesn't exist for
// the caller's tenant. Shared by reports_download and reports_email so the
// fetch path stays in one place.
// ─────────────────────────────────────────────────────────────────────────────
async fn fetch_archive_policy_report(
    pool: &SqlitePool,
    tenant_id: &str,
    id: i64,
) -> Result<Option<(Report, Vec<SystemReport>, Vec<TestMeta>)>, sqlx::Error> {
    let row = sqlx::query_as::<_, Report>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                policy_name, policy_version, policy_description,
                submitter_name, tests_metadata, report_results
         FROM reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(tenant_id)
    .fetch_optional(pool).await?;

    let Some(report) = row else { return Ok(None); };

    let mut system_reports: Vec<SystemReport> = serde_json::from_str(
        report.report_results.as_deref().unwrap_or("[]"),
    ).unwrap_or_default();

    // Backfill pass_count/fail_count for reports saved before those fields existed.
    for s in &mut system_reports {
        if s.pass_count == 0 && s.fail_count == 0 && !s.results.is_empty() {
            s.pass_count = s.results.iter().filter(|r| r.status == "PASS").count();
            s.fail_count = s.results.iter().filter(|r| r.status == "FAIL").count();
            s.is_passed  = is_system_passed(s.pass_count, s.fail_count);
        }
    }

    let tests_metadata: Vec<TestMeta> = serde_json::from_str(
        report.tests_metadata.as_deref().unwrap_or("[]"),
    ).unwrap_or_default();

    Ok(Some((report, system_reports, tests_metadata)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build_archive_policy_pdf
// Renders a saved-policy compliance report into a PDF byte buffer. The
// download and email handlers both call into this so there is one canonical
// place where the PDF layout lives.
// ─────────────────────────────────────────────────────────────────────────────
fn build_archive_policy_pdf(
    report: &Report,
    system_reports: &[SystemReport],
    tests_metadata: &[TestMeta],
) -> Result<Vec<u8>, ()> {
    const FONT_REGULAR:     &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD:        &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC:      &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES:       &[u8] = include_bytes!("../static/dist/img/Logo_report.jpg");

    let font_family = match (
        fonts::FontData::new(FONT_REGULAR.to_vec(), None),
        fonts::FontData::new(FONT_BOLD.to_vec(), None),
        fonts::FontData::new(FONT_ITALIC.to_vec(), None),
        fonts::FontData::new(FONT_BOLD_ITALIC.to_vec(), None),
    ) {
        (Ok(regular), Ok(bold), Ok(italic), Ok(bold_italic)) =>
            fonts::FontFamily { regular, bold, italic, bold_italic },
        _ => { error!("Failed to load PDF fonts for archive policy report"); return Err(()); }
    };

    let mut doc = genpdf::Document::new(font_family);

    let cursor = std::io::Cursor::new(LOGO_BYTES);
    let mut logo = match elements::Image::from_reader(cursor) {
        Ok(img) => img,
        Err(e) => { error!("Failed to load PDF logo: {}", e); return Err(()); }
    };

    doc.set_title(format!("OpenSCM Compliance Report - {}", report.policy_name));
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // Title
    let mut title = elements::Paragraph::new("OpenSCM Compliance Report");
    title.set_alignment(genpdf::Alignment::Center);
    doc.push(title.styled(
        style::Style::new().with_font_size(30).bold()
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
        cell(elements::Text::new("Policy Name").styled(style::Style::new().bold())),
        cell(elements::Paragraph::new(format!(
            "{} v{}",
            report.policy_name,
            report.policy_version.as_deref().unwrap_or(""),
        ))),
    ]) { error!("Failed to add policy name row to PDF: {}", e); }

    if let Err(e) = details_table.push_row(vec![
        cell(elements::Text::new("Description").styled(style::Style::new().bold())),
        cell(elements::Paragraph::new(
            report.policy_description.as_deref().unwrap_or("").to_string(),
        )),
    ]) { error!("Failed to add description row to PDF: {}", e); }

    doc.push(details_table);

    // Tests Summary — name + description of every test in the policy.
    if !tests_metadata.is_empty() {
        doc.push(elements::Break::new(1.0));
        doc.push(
            elements::Text::new(format!("Tests in this Policy ({})", tests_metadata.len()))
                .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        let mut tests_table = elements::TableLayout::new(vec![2, 5]);
        tests_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = tests_table.push_row(vec![
            cell(elements::Text::new("Test Name").styled(style::Style::new().bold())),
            cell(elements::Text::new("Description").styled(style::Style::new().bold())),
        ]) { error!("Failed to add tests summary header to PDF: {}", e); }

        for tm in tests_metadata {
            let desc = if tm.description.trim().is_empty() { "—".to_string() } else { tm.description.clone() };
            if let Err(e) = tests_table.push_row(vec![
                cell(elements::Paragraph::new(&tm.name)),
                cell(elements::Paragraph::new(&desc)),
            ]) { error!("Failed to add tests summary row to PDF: {}", e); }
        }
        doc.push(tests_table);
    }

    doc.push(elements::PageBreak::new());

    // Per-system audit section
    for system in system_reports {
        doc.push(
            elements::Text::new(format!("Host Name: {}", system.system_name))
                .styled(style::Style::new().bold().with_font_size(14)),
        );
        doc.push(elements::Break::new(0.5));

        let compliant_count = system.results.iter().filter(|r| r.status == "PASS").count();
        let violation_count = system.results.iter().filter(|r| r.status == "FAIL").count();

        let mut summary_table = elements::TableLayout::new(vec![1, 1]);
        summary_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Compliance Status").styled(style::Style::new().bold())),
            cell(elements::Text::new(if system.is_passed { "Compliant" } else { "Non-Compliant" })
                .styled(style::Style::new()
                    .with_color(if system.is_passed { style::Color::Rgb(0, 128, 0) } else { style::Color::Rgb(200, 0, 0) })
                    .bold())),
        ]) { error!("Failed to add compliance status row to PDF: {}", e); }

        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Violation Rule Count").styled(style::Style::new().bold())),
            cell(elements::Text::new(format!("Critical — {}", violation_count))),
        ]) { error!("Failed to add violation count row to PDF: {}", e); }

        if let Err(e) = summary_table.push_row(vec![
            cell(elements::Text::new("Compliant Rule Count").styled(style::Style::new().bold())),
            cell(elements::Text::new(format!("{}", compliant_count))),
        ]) { error!("Failed to add compliant count row to PDF: {}", e); }

        doc.push(summary_table);
        doc.push(elements::Break::new(1.0));

        // Rules breakdown
        doc.push(elements::Text::new("Audit Rules Detailed Breakdown")
            .styled(style::Style::new().bold().with_font_size(14)));
        doc.push(elements::Break::new(0.5));
        let mut rules_table = elements::TableLayout::new(vec![4, 1]);
        rules_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));

        if let Err(e) = rules_table.push_row(vec![
            cell(elements::Text::new("Rule Name").styled(style::Style::new().bold())),
            cell(elements::Text::new("Status").styled(style::Style::new().bold())),
        ]) { error!("Failed to add rules table header to PDF: {}", e); }

        for res in &system.results {
            let (status_text, status_color) = match res.status.as_str() {
                "PASS" => ("PASS", style::Color::Rgb(0, 128, 0)),
                "FAIL" => ("FAIL", style::Color::Rgb(200, 0, 0)),
                "NA"   => ("NA",   style::Color::Rgb(100, 100, 100)),
                _      => ("—",    style::Color::Rgb(150, 150, 150)),
            };
            if let Err(e) = rules_table.push_row(vec![
                cell(elements::Paragraph::new(&res.test_name)),
                cell(elements::Text::new(status_text)
                    .styled(style::Style::new().with_color(status_color).bold())),
            ]) { error!("Failed to add rule row to PDF: {}", e); }
        }
        doc.push(rules_table);
        doc.push(elements::PageBreak::new());
    }

    doc.push(elements::Break::new(2.0));
    doc.push(elements::Paragraph::new(
        "Note: This report contains confidential information about your infrastructure \
         and should be treated as such. Unauthorized distribution is strictly prohibited.",
    ).styled(style::Style::new().with_font_size(10).with_color(style::Color::Rgb(100, 100, 100))));

    let mut buffer = Vec::new();
    doc.render(&mut buffer).map_err(|e| { error!("Failed to render archive policy PDF: {}", e); })?;
    Ok(buffer)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/download/{id}
// Generate and stream a PDF of a saved policy compliance report.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let (report, system_reports, tests_metadata) =
        match fetch_archive_policy_report(&pool, &auth.tenant_id, id).await {
            Ok(Some(tup)) => tup,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                error!(error = ?e, report_id = %id, "Failed to fetch report for download");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let buffer = match build_archive_policy_pdf(&report, &system_reports, &tests_metadata) {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

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

// ─────────────────────────────────────────────────────────────────────────────
// POST /reports/email/{id}
// Email the archive-policy report PDF to the logged-in user's address.
// Role: Viewer (same as download — no information escapes outside the
// configured mail relay; less privileged than the download itself).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_email(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let back = format!("/reports/view/{}", id);

    let mailer = match crate::email::Mailer::from_db(&pool).await {
        Some(m) => m,
        None => return flash_back(&back, false, "Email is not configured. Configure SMTP in Settings first."),
    };

    let to = match user_email(&pool, auth.userid, &auth.tenant_id).await {
        Some(e) => e,
        None => return flash_back(&back, false, "Your account has no email address. Edit your profile and add one first."),
    };

    let (report, system_reports, tests_metadata) =
        match fetch_archive_policy_report(&pool, &auth.tenant_id, id).await {
            Ok(Some(tup)) => tup,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                error!(error = ?e, report_id = %id, "Failed to fetch report for email");
                return flash_back(&back, false, "Failed to load report.");
            }
        };

    let bytes = match build_archive_policy_pdf(&report, &system_reports, &tests_metadata) {
        Ok(b) => b,
        Err(_) => return flash_back(&back, false, "Failed to generate PDF report."),
    };

    let subject = format!("OpenSCM Compliance Report — {}", report.policy_name);
    let html_body = report_email_body(
        &report.policy_name,
        report.policy_version.as_deref().unwrap_or(""),
        &report.submission_date,
    );
    let filename = format!("OpenSCM_Report_{}.pdf", id);

    match mailer.send_with_attachment(&to, &subject, &html_body, &filename, "application/pdf", bytes).await {
        Ok(_) => flash_back(&back, true, &format!("Report emailed to {}.", to)),
        Err(e) => flash_back(&back, false, &format!("SMTP send failed: {}", e)),
    }
}


// ============================================================
// BULK ACTIONS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// POST /reports/bulk/delete
// Bulk delete selected saved policy compliance reports.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn reports_bulk_delete(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let bytes: Bytes = raw_form.0;
    let raw_string = match String::from_utf8(bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => return Redirect::to("/reports?error_message=Invalid+form+data").into_response(),
    };

    let form_data = parse_form_data(&raw_string);
    let ids: Vec<i64> = form_data
        .get("ids")
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    if ids.is_empty() {
        return Redirect::to("/reports?error_message=No+reports+selected").into_response();
    }

    let mut deleted = 0usize;
    for id in &ids {
        if let Err(e) = sqlx::query("DELETE FROM reports WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(&auth.tenant_id)
            .execute(&pool)
            .await
        {
            error!("Bulk delete: failed for report {}: {}", id, e);
        } else {
            deleted += 1;
        }
    }

    info!("Bulk deleted {} reports by '{}'.", deleted, auth.username);
    let msg = urlencoding::encode(&format!("{} report(s) deleted.", deleted)).to_string();
    Redirect::to(&format!("/reports?success_message={}", msg)).into_response()
}


// ============================================================
// SYSTEM REPORT HANDLERS
// ============================================================

// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/report/{id}/save
// Save a snapshot of the live system compliance report to system_reports.
// Role: Runner
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_save(
    auth: AuthSession,
    Path(system_id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Runner) {
        return redir;
    }

    let data = match fetch_system_report_data(system_id, &auth.tenant_id, &pool).await {
        Ok(d) => d,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %system_id, "Failed to fetch system data for snapshot");
            return Redirect::to("/reports?error_message=Failed+to+save+report").into_response();
        }
    };

    let report_json = match serde_json::to_string(&data) {
        Ok(j) => j,
        Err(e) => {
            error!("Failed to serialize system report data: {}", e);
            return Redirect::to("/reports?error_message=Failed+to+save+report").into_response();
        }
    };

    match sqlx::query(
        "INSERT INTO system_reports (tenant_id, system_id, system_name, submitter_name, report_data)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&auth.tenant_id)
    .bind(system_id)
    .bind(&data.system_name)
    .bind(&auth.username)
    .bind(&report_json)
    .execute(&pool)
    .await
    {
        Ok(_) => {
            info!("System report snapshot saved for system '{}' by '{}'.", data.system_name, auth.username);
            let msg = urlencoding::encode(&format!("Report saved for {}.", data.system_name)).to_string();
            Redirect::to(&format!("/systems/report/{}?success_message={}", system_id, msg)).into_response()
        }
        Err(e) => {
            error!("Failed to insert system report snapshot: {}", e);
            Redirect::to(&format!("/systems/report/{}?error_message=Failed+to+save+report", system_id)).into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/system/view/{id}
// View a saved system compliance report snapshot.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_view(
    auth: AuthSession,
    Path(id): Path<i32>,
    Query(query): Query<ErrorQuery>,
    Extension(pool): Extension<SqlitePool>,
    Extension(tera): Extension<Arc<Tera>>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let row = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, report_data
         FROM system_reports
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
            error!(error = ?e, report_id = %id, "Failed to fetch system report");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let report_data: SystemReportData = match serde_json::from_str(
        row.report_data.as_deref().unwrap_or("{}"),
    ) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to deserialize system report data: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let compliance_sat: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_sat'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(80);

    let compliance_marginal: i64 = sqlx::query_scalar(
        "SELECT CAST(value AS INTEGER) FROM settings WHERE tenant_id = ? AND skey = 'compliance_marginal'"
    )
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(60);

    let system_exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM systems WHERE id = ? AND tenant_id = ?)"
    )
    .bind(row.system_id)
    .bind(&auth.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap_or(0);

    let mut context = Context::new();
    context.insert("meta", &row);
    context.insert("report", &report_data);
    context.insert("compliance_sat", &compliance_sat);
    context.insert("compliance_marginal", &compliance_marginal);
    context.insert("system_exists", &system_exists);
    context.insert("is_smtp_configured", &is_smtp_configured(&pool).await);
    if let Some(msg) = query.success_message { context.insert("success_message", &msg); }
    if let Some(msg) = query.error_message   { context.insert("error_message",   &msg); }
    render_template(&tera, Some(&pool), "system_report_view.html", context, Some(auth))
        .await
        .into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/system/delete/{id}
// Delete a saved system compliance report.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_delete(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    match sqlx::query("DELETE FROM system_reports WHERE id = ? AND tenant_id = ?")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&pool)
        .await
    {
        Ok(_) => Redirect::to("/reports?success_message=System+report+deleted.").into_response(),
        Err(e) => {
            error!("Failed to delete system report {}: {}", id, e);
            Redirect::to("/reports?error_message=Failed+to+delete+report.").into_response()
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /reports/system/bulk/delete
// Bulk delete selected saved system compliance reports.
// Role: Editor
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_bulk_delete(
    auth: AuthSession,
    Extension(pool): Extension<SqlitePool>,
    raw_form: RawForm,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Editor) {
        return redir;
    }

    let body = match std::str::from_utf8(&raw_form.0) {
        Ok(s) => s.to_string(),
        Err(_) => return Redirect::to("/reports?error_message=Invalid+form+data.").into_response(),
    };

    let form_data = parse_form_data(&body);
    let ids: Vec<i64> = form_data
        .get("ids")
        .map(|v| v.iter().filter_map(|s| s.parse::<i64>().ok()).collect())
        .unwrap_or_default();

    if ids.is_empty() {
        return Redirect::to("/reports?error_message=No+reports+selected.").into_response();
    }

    let mut deleted = 0usize;
    for id in &ids {
        if sqlx::query("DELETE FROM system_reports WHERE id = ? AND tenant_id = ?")
            .bind(id)
            .bind(&auth.tenant_id)
            .execute(&pool)
            .await
            .is_ok()
        {
            deleted += 1;
        }
    }

    info!("Bulk deleted {} system reports by '{}'.", deleted, auth.username);
    let msg = urlencoding::encode(&format!("{} system report(s) deleted.", deleted)).to_string();
    Redirect::to(&format!("/reports?success_message={}", msg)).into_response()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: build_system_report_pdf
// Builds a PDF byte buffer for a system compliance report.
// Used by both the live-download and saved-snapshot download handlers.
// ─────────────────────────────────────────────────────────────────────────────
fn build_system_report_pdf(data: &SystemReportData, subtitle: &str) -> Result<Vec<u8>, ()> {
    const FONT_REGULAR:     &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Regular.ttf");
    const FONT_BOLD:        &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Bold.ttf");
    const FONT_ITALIC:      &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-Italic.ttf");
    const FONT_BOLD_ITALIC: &[u8] = include_bytes!("../static/dist/fonts/LiberationSans-BoldItalic.ttf");
    const LOGO_BYTES:       &[u8] = include_bytes!("../static/dist/img/Logo_report.jpg");

    let font_family = match (
        fonts::FontData::new(FONT_REGULAR.to_vec(), None),
        fonts::FontData::new(FONT_BOLD.to_vec(), None),
        fonts::FontData::new(FONT_ITALIC.to_vec(), None),
        fonts::FontData::new(FONT_BOLD_ITALIC.to_vec(), None),
    ) {
        (Ok(regular), Ok(bold), Ok(italic), Ok(bold_italic)) =>
            fonts::FontFamily { regular, bold, italic, bold_italic },
        _ => return Err(()),
    };

    let mut doc = genpdf::Document::new(font_family);
    doc.set_title(format!("OpenSCM System Report - {}", data.system_name));
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // Title
    let mut title = elements::Paragraph::new("OpenSCM System Compliance Report");
    title.set_alignment(genpdf::Alignment::Center);
    doc.push(title.styled(style::Style::new().with_font_size(28).bold()
        .with_color(style::Color::Rgb(0, 0, 128))));
    doc.push(elements::Break::new(1.0));

    let mut sub = elements::Paragraph::new(subtitle);
    sub.set_alignment(genpdf::Alignment::Center);
    doc.push(sub.styled(style::Style::new().with_font_size(10)
        .with_color(style::Color::Rgb(100, 100, 100))));
    doc.push(elements::Break::new(0.5));

    let cursor = std::io::Cursor::new(LOGO_BYTES);
    if let Ok(mut logo) = elements::Image::from_reader(cursor) {
        logo.set_dpi(40.0);
        logo.set_alignment(genpdf::Alignment::Center);
        doc.push(logo);
    }
    doc.push(elements::Break::new(1.0));

    // System details table
    doc.push(elements::Text::new("System Details")
        .styled(style::Style::new().bold().with_font_size(13)));
    doc.push(elements::Break::new(0.5));

    let mut details = elements::TableLayout::new(vec![1, 3]);
    details.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));
    for (label, value) in &[
        ("System Name",  data.system_name.as_str()),
        ("OS",           data.os.as_str()),
        ("Architecture", data.arch.as_deref().unwrap_or("—")),
        ("IP Address",   data.ip.as_deref().unwrap_or("—")),
        ("Last Seen",    data.last_seen.as_deref().unwrap_or("—")),
    ] {
        let _ = details.push_row(vec![
            cell(elements::Text::new(*label).styled(style::Style::new().bold())),
            cell(elements::Paragraph::new(value.to_string())),
        ]);
    }
    let score_text = if data.compliance_score < 0.0 {
        "Not Scanned".to_string()
    } else {
        format!("{:.0}%  ({} pass / {} fail / {} na)",
            data.compliance_score, data.total_pass, data.total_fail, data.total_na)
    };
    let _ = details.push_row(vec![
        cell(elements::Text::new("Compliance Score").styled(style::Style::new().bold())),
        cell(elements::Paragraph::new(score_text)),
    ]);
    doc.push(details);
    doc.push(elements::PageBreak::new());

    // Per-policy sections
    for policy in &data.policy_groups {
        let exempt = policy.pass_count == 0 && policy.fail_count == 0;
        let verdict = if exempt { "NOT APPLICABLE" } else if policy.is_passed { "COMPLIANT" } else { "NON-COMPLIANT" };
        let verdict_color = if exempt {
            style::Color::Rgb(100, 100, 100)
        } else if policy.is_passed {
            style::Color::Rgb(0, 128, 0)
        } else {
            style::Color::Rgb(200, 0, 0)
        };

        doc.push(elements::Text::new(format!("{} — v{}", policy.policy_name, policy.policy_version))
            .styled(style::Style::new().bold().with_font_size(13)));
        if let Some(desc) = &policy.policy_description {
            if !desc.is_empty() {
                doc.push(elements::Break::new(0.2));
                doc.push(elements::Paragraph::new(desc.as_str())
                    .styled(style::Style::new().with_font_size(9)
                        .with_color(style::Color::Rgb(100, 100, 100))));
            }
        }
        doc.push(elements::Break::new(0.3));
        doc.push(elements::Text::new(format!("Verdict: {}", verdict))
            .styled(style::Style::new().bold().with_color(verdict_color)));
        doc.push(elements::Break::new(0.5));

        let mut rules_table = elements::TableLayout::new(vec![5, 1]);
        rules_table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, true));
        let _ = rules_table.push_row(vec![
            cell(elements::Text::new("Security Requirement").styled(style::Style::new().bold())),
            cell(elements::Text::new("Status").styled(style::Style::new().bold())),
        ]);
        for res in &policy.results {
            let (status_text, color) = match res.status.as_str() {
                "PASS" => ("PASS", style::Color::Rgb(0, 128, 0)),
                "FAIL" => ("FAIL", style::Color::Rgb(200, 0, 0)),
                "NA"   => ("NA",   style::Color::Rgb(100, 100, 100)),
                _      => ("—",    style::Color::Rgb(150, 150, 150)),
            };
            let _ = rules_table.push_row(vec![
                cell(elements::Paragraph::new(&res.test_name)),
                cell(elements::Text::new(status_text)
                    .styled(style::Style::new().with_color(color).bold())),
            ]);
        }
        doc.push(rules_table);
        doc.push(elements::PageBreak::new());
    }

    doc.push(elements::Break::new(2.0));
    doc.push(elements::Paragraph::new(
        "Note: This report contains confidential information about your infrastructure \
         and should be treated as such. Unauthorized distribution is strictly prohibited.",
    ).styled(style::Style::new().with_font_size(10).with_color(style::Color::Rgb(100, 100, 100))));

    let mut buffer = Vec::new();
    doc.render(&mut buffer).map_err(|_| ())?;
    Ok(buffer)
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /reports/system/download/{id}
// Download a saved system compliance report as a PDF file.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_download(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let row = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, report_data
         FROM system_reports
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
            error!(error = ?e, report_id = %id, "Failed to fetch system report for download");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let data: SystemReportData = match serde_json::from_str(row.report_data.as_deref().unwrap_or("{}")) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to deserialize system report data for PDF: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let subtitle = format!(
        "Saved on {}  ·  by {}",
        row.submission_date,
        row.submitter_name.as_deref().unwrap_or("Unknown"),
    );

    let buffer = match build_system_report_pdf(&data, &subtitle) {
        Ok(b) => b,
        Err(_) => {
            error!("Failed to render system report PDF {}", id);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"OpenSCM_SystemReport_{}_{}.pdf\"",
                data.system_name.replace(' ', "_"), id),
        )
        .body(axum::body::Body::from(buffer))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}


// ─────────────────────────────────────────────────────────────────────────────
// GET /systems/report/{id}/download
// Generate and stream a PDF of the live (current) system compliance report.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_live_download(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {

    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let data = match fetch_system_report_data(id, &auth.tenant_id, &pool).await {
        Ok(d) => d,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %id, "Failed to fetch live system report for PDF");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    use chrono::Local;
    let subtitle = format!("Live Report  ·  {}", Local::now().format("%Y-%m-%d %H:%M"));

    let buffer = match build_system_report_pdf(&data, &subtitle) {
        Ok(b) => b,
        Err(_) => {
            error!("Failed to render live system report PDF for system {}", id);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"OpenSCM_SystemReport_{}_live.pdf\"",
                data.system_name.replace(' ', "_")),
        )
        .body(axum::body::Body::from(buffer))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /reports/system/email/{id}
// Email the archive system-report PDF to the logged-in user's address.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_reports_email(
    auth: AuthSession,
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let back = format!("/reports/system/view/{}", id);

    let mailer = match crate::email::Mailer::from_db(&pool).await {
        Some(m) => m,
        None => return flash_back(&back, false, "Email is not configured. Configure SMTP in Settings first."),
    };

    let to = match user_email(&pool, auth.userid, &auth.tenant_id).await {
        Some(e) => e,
        None => return flash_back(&back, false, "Your account has no email address. Edit your profile and add one first."),
    };

    let row = match sqlx::query_as::<_, SavedSystemReport>(
        "SELECT id, tenant_id, CAST(submission_date AS TEXT) AS submission_date,
                system_id, system_name, submitter_name, report_data
         FROM system_reports
         WHERE id = ? AND tenant_id = ?",
    )
    .bind(id).bind(&auth.tenant_id)
    .fetch_optional(&pool).await
    {
        Ok(Some(r)) => r,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            error!(error = ?e, report_id = %id, "Failed to fetch system report for email");
            return flash_back(&back, false, "Failed to load report.");
        }
    };

    let data: SystemReportData = match serde_json::from_str(row.report_data.as_deref().unwrap_or("{}")) {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to deserialize system report data for email: {}", e);
            return flash_back(&back, false, "Failed to load report data.");
        }
    };

    let subtitle = format!(
        "Saved on {}  ·  by {}",
        row.submission_date,
        row.submitter_name.as_deref().unwrap_or("Unknown"),
    );

    let bytes = match build_system_report_pdf(&data, &subtitle) {
        Ok(b) => b,
        Err(_) => return flash_back(&back, false, "Failed to generate PDF report."),
    };

    let subject = format!("OpenSCM System Report — {}", data.system_name);
    let html_body = report_email_body(&data.system_name, "", &row.submission_date);
    let filename = format!("OpenSCM_SystemReport_{}_{}.pdf",
        data.system_name.replace(' ', "_"), id);

    match mailer.send_with_attachment(&to, &subject, &html_body, &filename, "application/pdf", bytes).await {
        Ok(_) => flash_back(&back, true, &format!("Report emailed to {}.", to)),
        Err(e) => flash_back(&back, false, &format!("SMTP send failed: {}", e)),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// POST /systems/report/{id}/email
// Email the live system-report PDF (computed against the current state) to
// the logged-in user's address.
// Role: Viewer
// ─────────────────────────────────────────────────────────────────────────────
pub async fn system_report_live_email(
    auth: AuthSession,
    Path(id): Path<i32>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    if let Some(redir) = auth::authorize(&auth.role, UserRole::Viewer) {
        return redir;
    }

    let back = format!("/systems/report/{}", id);

    let mailer = match crate::email::Mailer::from_db(&pool).await {
        Some(m) => m,
        None => return flash_back(&back, false, "Email is not configured. Configure SMTP in Settings first."),
    };

    let to = match user_email(&pool, auth.userid, &auth.tenant_id).await {
        Some(e) => e,
        None => return flash_back(&back, false, "Your account has no email address. Edit your profile and add one first."),
    };

    let data = match fetch_system_report_data(id, &auth.tenant_id, &pool).await {
        Ok(d) => d,
        Err(e) if matches!(e, sqlx::Error::RowNotFound) => {
            return Redirect::to("/systems?error_message=System+not+found").into_response();
        }
        Err(e) => {
            error!(error = ?e, system_id = %id, "Failed to fetch live system report for email");
            return flash_back(&back, false, "Failed to load report.");
        }
    };

    use chrono::Local;
    let now = Local::now().format("%Y-%m-%d %H:%M").to_string();
    let subtitle = format!("Live Report  ·  {}", now);

    let bytes = match build_system_report_pdf(&data, &subtitle) {
        Ok(b) => b,
        Err(_) => return flash_back(&back, false, "Failed to generate PDF report."),
    };

    let subject = format!("OpenSCM System Report — {} (live)", data.system_name);
    let html_body = report_email_body(&data.system_name, "", &now);
    let filename = format!("OpenSCM_SystemReport_{}_live.pdf",
        data.system_name.replace(' ', "_"));

    match mailer.send_with_attachment(&to, &subject, &html_body, &filename, "application/pdf", bytes).await {
        Ok(_) => flash_back(&back, true, &format!("Report emailed to {}.", to)),
        Err(e) => flash_back(&back, false, &format!("SMTP send failed: {}", e)),
    }
}
