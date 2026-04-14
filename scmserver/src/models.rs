use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};



#[derive(Deserialize)]
pub struct ErrorQuery {
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}


#[derive(Deserialize, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub name: Option<String>,
    pub email: Option<String>,
}


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
}

#[derive(Serialize, Deserialize, Default)]
pub struct SystemGroup {
    pub id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub systems: Option<String>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInsideGroup {
    pub system_id: i32,
    pub group_id:  i32,
}

#[derive(Debug, Serialize, Deserialize, FromRow, Default)]
pub struct Test {
    pub id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub rational: Option<String>,
    pub remediation: Option<String>,
    pub severity: Option<String>,
    pub filter: Option<String>,
    pub element_1: Option<String>,
    pub input_1: Option<String>,
    pub selement_1: Option<String>,
    pub condition_1: Option<String>,
    pub sinput_1: Option<String>,
    pub element_2: Option<String>,
    pub input_2: Option<String>,
    pub selement_2: Option<String>,
    pub condition_2: Option<String>,
    pub sinput_2: Option<String>,
    pub element_3: Option<String>,
    pub input_3: Option<String>,
    pub selement_3: Option<String>,
    pub condition_3: Option<String>,
    pub sinput_3: Option<String>,
    pub element_4: Option<String>,
    pub input_4: Option<String>,
    pub selement_4: Option<String>,
    pub condition_4: Option<String>,
    pub sinput_4: Option<String>,
    pub element_5: Option<String>,
    pub input_5: Option<String>,
    pub selement_5: Option<String>,
    pub condition_5: Option<String>,
    pub sinput_5: Option<String>,
}


#[derive(Serialize, Deserialize)]
pub struct Policy {
    pub id: Option<i32>,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PolicySchedule {
    pub id: i32,
    pub policy_id: i32,
    pub enabled: bool, // sqlx handles SQLite 0/1 to bool automatically
    pub frequency: String, // "daily", "weekly", "monthly", "custom"
    pub cron_expression: Option<String>, // Only used for "custom"
    pub next_run: String, // Stored as ISO 8601 string in SQLite
    pub last_run: Option<String>, // Null until the first successful execution
}



#[derive(sqlx::FromRow, serde::Serialize, Clone)]
pub struct ComplianceHistoryRow {
    pub check_date: String,
    pub systems_score: f64,
    pub policies_score: f64, // <--- ADD THIS LINE
}


#[derive(Debug, Serialize, Deserialize)]
pub struct TestInsidePolicy {
    pub policy_id: i32,
    pub test_id:  i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemInsidePolicy {
    pub policy_id: i32,
    pub group_id:  i32,
}

#[derive(Debug, serde::Serialize)]
pub struct Notification {
    pub id: i64,
    pub r#type: String,
    pub timestamp: String,
    pub message: String,
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnsignedPayload {
    pub id: String,
    pub hostname: String,
    pub ver: String,
    pub ip: String,
    pub os: String,
    pub arch: String,
    pub timestamp: String,
    pub public_key: Option<String>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct SignedRequest<T> {
    pub payload: T,
    pub signature: String,
}


#[derive(Deserialize)]
pub struct SignedResult {
    pub payload: ComplianceResult,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignedResponse {
    pub payload: serde_json::Value,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct ComplianceResult {
    pub client_id: i64,
    pub test_id: i64,
    pub result: String,
}


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


#[derive(sqlx::FromRow, serde::Serialize)]
pub struct SystemFailRow {
    pub system_name: String,
    pub os: String,
    pub compliance: f64, // Alias for compliance_score
    pub tests_passed: i32,
    pub tests_failed: i32,
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct PolicyFailRow {
    pub policy_name: String, // Alias for test_name
    pub policy_version: String,
    pub compliance: f64,     // Alias for compliance_score
    pub systems_passed: i32,
    pub systems_failed: i32,
}



#[derive(Serialize, Deserialize)]
pub struct Element {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}


#[derive(Serialize, Deserialize)]
pub struct SElement {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Condition {
    pub id: i32,
    pub name: String,
    pub description: Option<String>,
}


#[derive(Serialize, Deserialize)]
pub struct ReportData {
    // Page 1: Policy Header Info
    pub policy_id: i32,
    pub policy_name: String,
    pub version: String,
    pub description: String,
    pub submission_date: String,
    pub submitter_name: String,
    pub tests_metadata: Vec<TestMeta>,
    pub system_reports: Vec<SystemReport>,
}

/// Details for the "Policy Specification" page
#[derive(Serialize, Deserialize)]
pub struct TestMeta {
    pub name: String,
    pub description: String,
    pub rational: String,
    pub remediation: String,
}

#[derive(Serialize, Deserialize)]
pub struct SystemReport {
    pub system_name: String,
    pub results: Vec<IndividualResult>,
    pub is_passed: bool,
}

#[derive(Serialize, Deserialize)]
pub struct IndividualResult {
    pub test_name: String,
    pub status: String, 
}


#[derive(Serialize)]
pub struct Report {
    pub id: i32,
    pub submission_date: DateTime<Utc>,
    pub policy_name: Option<String>,
    pub policy_version: Option<String>,
    pub policy_description: Option<String>,
    pub submitter_name: Option<String>,
    pub tests_metadata: Option<String>,
    pub report_results: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UserRole {
    Viewer = 0,
    Runner = 1,
    Editor = 2,
    Admin = 3,
}


impl From<&str> for UserRole {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "admin" => UserRole::Admin,
            "editor" => UserRole::Editor,
            "runner" => UserRole::Runner,
            _ => UserRole::Viewer,
        }
    }
}

