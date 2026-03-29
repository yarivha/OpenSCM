use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct System {
    pub id: String,
    pub name: String,
    pub ver: String,
    pub ip: String,
    pub os: String,
    pub arch: String,
}


// Struct to be signed (everything but the signature)
#[derive(Serialize, Deserialize, Debug)]
pub struct UnsignedPayload {
    pub id: String,
    pub hostname: String,
    pub ver: String,
    pub ip: String,
    pub os: String,
    pub arch: String,
    pub timestamp: String,
    pub public_key: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct SignedRequest<T> {
    pub payload: T,
    pub signature: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Test {
    pub id: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub rational: Option<String>,
    pub remediation: Option<String>,
    pub business_impact: Option<String>,
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



#[derive(Debug, Deserialize)]
pub struct CommandResponse {
    pub id: Option<u32>,
    pub command: String,
    pub server_public_key: Option<String>,
    pub parameters: Option<serde_json::Value>,
    pub command_id: Option<u32>,
}


#[derive(Serialize)]
pub struct TestResult {
    pub client_id: i64,
    pub test_id: i32,
    pub result: String, // "true", "false", "NA"
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPayload {
    pub id: i64,           // server-side generated ID for client
    pub command: String,   // "REGISTER", "NONE", "TEST"
    pub data: Option<Vec<Test>>, // present if command=="TEST"
    pub timestamp: String, // optional timestamp for signature freshness
}


#[derive(Debug, Serialize, Deserialize)]
pub struct SignedServerPayload {
    pub payload: ServerPayload,
    pub signature: String, // base64
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub client_id: i64,
    pub test_id: i64,
    pub result: String,
}
