// =============================================================================
// models.rs — all data model structs and enums
//
// These are pure data types shared across all route modules. No business logic
// lives here — only field definitions and standard trait derivations.
// =============================================================================

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sqlx::FromRow;
use chrono::{DateTime, Utc};


// Query parameters used on pages that show flash messages.
#[derive(Deserialize)]
pub struct ErrorQuery {
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}


// A portal user account (id, username, role, display name, email).
#[derive(Deserialize, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub name: Option<String>,
    pub email: Option<String>,
}


// A managed agent system as stored in the systems table.
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct System {
    pub id: Option<i32>,
    pub name: String,
    pub ver: Option<String>,
    pub ip: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub status: Option<String>,
    pub groups: Option<String>,
    pub auth_signature: Option<String>,
    pub auth_public_key: Option<String>,
    pub trust_challenge: Option<String>,
    pub trust_proof: Option<String>,
    pub created_date: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Computed server-side: true when last_seen is older than offline_threshold.
    #[serde(default)]
    pub is_offline: bool,
}

// A named group of systems used to link systems to policies.
#[derive(Serialize, Deserialize, Default)]
pub struct SystemGroup {
    pub id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub systems: Option<String>,
}


// Many-to-many join row: a system assigned to a group.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInsideGroup {
    pub system_id: i32,
    pub group_id:  i32,
}

// A compliance test definition (name, severity, filter, remediation, etc.).
#[derive(Debug, Serialize, Deserialize, FromRow, Default, Clone)]
pub struct Test {
    pub id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub rational: Option<String>,
    pub remediation: Option<String>,
    pub severity: Option<String>,
    pub filter: Option<String>,
    pub app_filter: Option<String>,
}


// One condition (or applicability rule) row in the test_conditions table.
#[derive(Debug, sqlx::FromRow, Serialize, Deserialize, Clone)]
pub struct TestCondition {
    pub id: i64,
    pub tenant_id: String,
    pub test_id: i64,
    pub r#type: String,
    pub element: String,
    pub input: String,
    pub selement: String,
    pub condition: Option<String>,
    pub sinput: Option<String>,
}


// A test bundled with its conditions and applicability rules (sent to agents).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TestWithConditions {
    #[serde(flatten)]
    pub test: Test,
    pub conditions: Vec<TestCondition>,
    pub applicability: Option<Vec<TestCondition>>,
}

// Flat wire-format for sending a test + conditions to an agent.
// Mirrors the client's Test struct exactly — no #[serde(flatten)] so
// serialization is deterministic and the Ed25519 signature round-trips cleanly.
#[derive(Debug, Serialize, Clone)]
pub struct TestPayload {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub rational: Option<String>,
    pub remediation: Option<String>,
    pub severity: Option<String>,
    pub filter: Option<String>,
    pub app_filter: Option<String>,
    pub conditions: Vec<TestCondition>,
    pub applicability: Option<Vec<TestCondition>>,
}

impl From<TestWithConditions> for TestPayload {
    fn from(twc: TestWithConditions) -> Self {
        TestPayload {
            id:          twc.test.id.map(|i| i as i64),
            name:        twc.test.name,
            description: twc.test.description,
            rational:    twc.test.rational,
            remediation: twc.test.remediation,
            severity:    twc.test.severity,
            filter:      twc.test.filter,
            app_filter:  twc.test.app_filter,
            conditions:  twc.conditions,
            applicability: twc.applicability,
        }
    }
}


// A security policy (name, version, description).
#[derive(Serialize, Deserialize)]
pub struct Policy {
    pub id: Option<i32>,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
}

// An automated scan or report schedule for a policy.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PolicySchedule {
    pub id: i32,
    pub tenant_id: String,
    pub policy_id: i32,
    pub enabled: i64, // AnyPool CAST(enabled AS INTEGER) yields BIGINT; Tera treats 0/1 as falsy/truthy
    pub schedule_type: String, // "scan" or "report"
    pub frequency: String, // "daily", "weekly", "monthly", "custom"
    pub cron_expression: Option<String>, // Only used for "custom"
    pub next_run: String, // Stored as ISO 8601 string in SQLite
    pub last_run: Option<String>, // Null until the first successful execution
}



// One row from the compliance_history table used by dashboard trend charts.
#[derive(sqlx::FromRow, serde::Serialize, Clone)]
pub struct ComplianceHistoryRow {
    pub check_date: String,
    pub systems_score: f64,
    pub policies_score: f64, // <--- ADD THIS LINE
}


// Many-to-many join row: a test assigned to a policy.
#[derive(Debug, Serialize, Deserialize)]
pub struct TestInsidePolicy {
    pub policy_id: i32,
    pub test_id:  i32,
}

// Many-to-many join row: a system group assigned to a policy.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInsidePolicy {
    pub policy_id: i32,
    pub group_id:  i32,
}

// A user notification row from the notify table.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Notification {
    pub id: i64,
    pub tenant_id: String,
    pub r#type: String,
    pub timestamp: String,
    pub owner_id: i32,
    pub message: String,
}


// The deserialized body of an agent's heartbeat or registration request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnsignedPayload {
    pub id: String,
    #[serde(alias = "tenant_id")]
    pub organization: String,
    pub hostname: String,
    pub ver: String,
    pub ip: String,
    pub os: String,
    pub arch: String,
    pub timestamp: String,
    pub public_key: Option<String>,
}


// An agent heartbeat/registration request with a raw JSON payload and signature.
// payload is stored as RawValue to preserve byte order for signature verification.
#[derive(Debug, Deserialize)]
pub struct SignedRequest {
    pub payload: Box<RawValue>,
    pub signature: String,
}


// An agent compliance result submission with a raw JSON payload and signature.
#[derive(Deserialize)]
pub struct SignedResult {
    pub payload: Box<RawValue>,
    pub signature: String,
}

// The server's signed response sent back to the agent.
#[derive(Serialize, Deserialize)]
pub struct SignedResponse {
    pub payload: serde_json::Value,
    pub signature: String,
}

// The deserialized body of an agent compliance result (POST /result).
#[derive(Serialize, Deserialize)]
pub struct ComplianceResult {
    pub client_id: i64,
    #[serde(alias = "tenant_id")]
    pub organization: String,
    pub test_id: i64,
    pub result: String,
}


// Aggregated compliance data for a single policy (used by the policies list page).
#[derive(FromRow, Serialize, Deserialize)]
pub struct PolicyCompliance {
    pub policy_id: i64,
    pub policy_name: String,
    pub policy_version: String,
    pub policy_description: Option<String>,
    pub compliance: f64,
    pub test_count: i64,    // Added
    pub system_count: i64,  // Added
    pub systems_passed: Option<i64>,
    pub systems_failed: Option<i64>,
}


// A row in the "highest risk assets" dashboard query result.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct SystemFailRow {
    pub system_id: i32,
    pub system_name: String,
    pub os: String,
    pub compliance: f64, // Alias for compliance_score
    pub tests_passed: i32,
    pub tests_failed: i32,
    pub tests_na: i64,
}

// One policy's worth of compliance results for a single system.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResultGroup {
    pub policy_id: i32,
    pub policy_name: String,
    pub policy_version: String,
    pub policy_description: Option<String>,
    pub results: Vec<IndividualResult>,
    pub is_passed: bool,
    pub pass_count: usize,
    pub fail_count: usize,
}

// All data needed to render the system live-report page or a saved snapshot.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemReportData {
    pub system_id: i32,
    pub system_name: String,
    pub os: String,
    pub arch: Option<String>,
    pub ip: Option<String>,
    pub compliance_score: f64,
    pub last_seen: Option<String>,
    pub policy_groups: Vec<PolicyResultGroup>,
    pub total_pass: usize,
    pub total_fail: usize,
    pub total_na: usize,
}

// A row in the "critical policy failures" dashboard query result.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct PolicyFailRow {
    pub policy_id: i32,
    pub policy_name: String, // Alias for test_name
    pub policy_version: String,
    pub compliance: f64,     // Alias for compliance_score
    pub systems_passed: i32,
    pub systems_failed: i32,
}



// A test condition element (e.g. FILE, REGISTRY, CMD) from the elements table.
#[derive(Serialize, Deserialize)]
pub struct Element {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}


// A secondary element modifier (e.g. EXISTS, CONTENT) from the selements table.
#[derive(Serialize, Deserialize)]
pub struct SElement {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}

// A comparison operator (e.g. EQUALS, CONTAINS) from the conditions table.
#[derive(Serialize, Deserialize)]
pub struct Condition {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}


// Full policy compliance report data (used for both HTML view and PDF export).
#[derive(Serialize, Deserialize)]
pub struct ReportData {
    pub policy_id: i32,
    pub policy_name: String,
    pub version: String,
    pub description: String,
    pub submission_date: String,
    pub submitter_name: String,
    pub tests_metadata: Vec<TestMeta>,
    pub system_reports: Vec<SystemReport>,
}



// Metadata for a single test as stored in a saved report (name, description, etc.).
#[derive(Serialize, Deserialize)]
pub struct TestMeta {
    pub name: String,
    pub description: String,
    pub rational: String,
    pub remediation: String,
}

// One system's compliance results grouped into a report.
#[derive(Serialize, Deserialize)]
pub struct SystemReport {
    pub system_name: String,
    pub results: Vec<IndividualResult>,
    pub is_passed: bool,
    /// Number of PASS results — used by templates for the all-NA "exempt" check.
    pub pass_count: usize,
    /// Number of FAIL results — used by templates for the all-NA "exempt" check.
    pub fail_count: usize,
}

// A single test result (test name + PASS/FAIL/NA status) inside a report.
#[derive(Debug, Serialize, Deserialize)]
pub struct IndividualResult {
    pub test_name: String,
    pub status: String,
}


// A saved system compliance report snapshot row from the system_reports table.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SavedSystemReport {
    pub id: i32,
    pub tenant_id: String,
    pub submission_date: String,
    pub system_id: i32,
    pub system_name: String,
    pub submitter_name: Option<String>,
    pub report_data: Option<String>, // JSON-serialised SystemReportData
}

// A saved policy compliance report row from the reports table.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Report {
    pub id: i32,
    pub tenant_id: String,
    pub submission_date: String,
    pub policy_name: String,
    pub policy_version: Option<String>,
    pub policy_description: Option<String>,
    pub submitter_name: Option<String>,
    pub tests_metadata: Option<String>,
    pub report_results: Option<String>,
}




// The authenticated session extracted from the signed cookie on every request.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub username: String,
    pub userid: i32,
    pub tenant_id: String,
    pub role: String,
}


// Role hierarchy used for authorization checks (Viewer < Runner < Editor < Admin < Superuser).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UserRole {
    Viewer = 0,
    Runner = 1,
    Editor = 2,
    Admin = 3,
    Superuser = 4,
}


impl From<&str> for UserRole {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "superuser" => UserRole::Superuser,
            "admin" => UserRole::Admin,
            "editor" => UserRole::Editor,
            "runner" => UserRole::Runner,
            _ => UserRole::Viewer,
        }
    }
}

