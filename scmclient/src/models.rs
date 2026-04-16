use serde::{Serialize, Deserialize};

// =========================
// 1. IDENTITY & HEARTBEAT
// =========================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnsignedPayload {
    pub id: String,
    pub tenant_id: Option<String>,
    pub hostname: String,
    pub ver: String,
    pub ip: String,
    pub os: String,
    pub arch: String,
    pub timestamp: String,
    pub public_key: Option<String>, // Option for Mutual Handshake
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedRequest<T> {
    pub payload: T,
    pub signature: String, // Base64
}

// =========================
// 2. SERVER COMMANDS
// =========================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedResponse {
    pub payload: serde_json::Value, // Flexible for REGISTER, TEST, or NONE
    pub signature: String,          // Server's signature
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Test {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub rational: Option<String>,
    pub remediation: Option<String>,
    pub business_impact: Option<String>,
    pub severity: Option<String>,
    pub filter: Option<String>,
    // Elements 1-5
    pub element_1: Option<String>, pub input_1: Option<String>, pub selement_1: Option<String>,
    pub condition_1: Option<String>, pub sinput_1: Option<String>,
    pub element_2: Option<String>, pub input_2: Option<String>, pub selement_2: Option<String>,
    pub condition_2: Option<String>, pub sinput_2: Option<String>,
    pub element_3: Option<String>, pub input_3: Option<String>, pub selement_3: Option<String>,
    pub condition_3: Option<String>, pub sinput_3: Option<String>,
    pub element_4: Option<String>, pub input_4: Option<String>, pub selement_4: Option<String>,
    pub condition_4: Option<String>, pub sinput_4: Option<String>,
    pub element_5: Option<String>, pub input_5: Option<String>, pub selement_5: Option<String>,
    pub condition_5: Option<String>, pub sinput_5: Option<String>,
}

// =========================
// 3. RESULTS
// =========================

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub client_id: i64,
    pub test_id: i64,
    pub result: String, // "true", "false", "NA"
}

// We use SignedRequest<ComplianceResult> for sending results back
pub type SignedResult = SignedRequest<ComplianceResult>;


