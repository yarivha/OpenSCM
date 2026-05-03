use serde::{Serialize, Deserialize};

// =========================
// 1. IDENTITY & HEARTBEAT
// =========================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnsignedPayload {
    pub id: String,
    pub organization: String,
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

// =========================
// 2. SERVER COMMANDS
// =========================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedResponse {
    pub payload: serde_json::Value,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Test {
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


#[derive(Debug, Serialize, Deserialize, Clone)]
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


// =========================
// 3. RESULTS
// =========================

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub client_id: i64,
    pub organization: String,
    pub test_id: i64,
    pub result: String, // "PASS", "FAIL", or "NA"
}

