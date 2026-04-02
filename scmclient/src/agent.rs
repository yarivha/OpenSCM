use sys_info;
use tracing::{debug, info, warn, error};
use ed25519_dalek::{SigningKey, Signer};
use std::fs;
use std::path::PathBuf;
use chrono; // Using chrono for cleaner timestamping

use crate::models::{UnsignedPayload, SignedRequest, Test, ComplianceResult};
use crate::config::Config;
use crate::compliance::evaluate;

pub async fn send_system_info(
    config: &mut Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. COLLECT STATIC INFO
    // We do this once per heartbeat to ensure we have the latest IP/Hostname
    let my_local_ip = local_ip_address::local_ip()?.to_string();
    let my_hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let my_os = format!("{} {}", sys_info::os_type()?, sys_info::os_release()?);
    let my_arch = std::env::consts::ARCH.to_string();
    let my_ver = env!("CARGO_PKG_VERSION").to_string();

    // 2. CONSTRUCT DYNAMIC URLS
    let base_url = format!(
        "http://{}:{}",
        config.server.host.as_deref().unwrap_or("localhost"),
        config.server.port.as_deref().unwrap_or("8000")
    );
    let send_url = format!("{}/send", base_url);
    let result_url = format!("{}/result", base_url);

    // 3. LOAD KEYS DYNAMICALLY
    let key_dir = PathBuf::from(config.key.key_path.as_deref().ok_or("Key path missing in config")?);
    
    let pub_path = key_dir.join(config.key.pub_key.as_deref().unwrap_or("scmclient.pub"));
    let priv_path = key_dir.join(config.key.priv_key.as_deref().unwrap_or("scmclient.key"));

    let public_base64 = fs::read_to_string(&pub_path)
        .map_err(|e| format!("Failed to read public key {:?}: {}", pub_path, e))?
        .trim().to_string();
        
    let private_base64 = fs::read_to_string(&priv_path)
        .map_err(|e| format!("Failed to read private key {:?}: {}", priv_path, e))?;
        
    let private_bytes = base64::decode(private_base64.trim())
        .map_err(|_| "Private key file contains invalid base64")?;
        
    let key_bytes: [u8; 32] = private_bytes.as_slice().try_into()
        .map_err(|_| "Private key is not 32 bytes (incorrect Ed25519 format)")?;
    
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15)) // Slightly longer timeout for busy servers
        .build()?;

    // 4. COMMUNICATION LOOP
    loop {
        let mut current_id = config.client.id.clone().unwrap_or_else(|| "0".to_string());

        let unsigned_payload = UnsignedPayload {
            id: current_id.clone(),
            hostname: my_hostname.clone(),
            ver: my_ver.clone(),
            ip: my_local_ip.clone(),
            os: my_os.clone(),
            arch: my_arch.clone(),
            timestamp: chrono::Utc::now().timestamp().to_string(),
            public_key: public_base64.clone(),
        };

        // Sign the payload
        let message_bytes = bincode::serialize(&unsigned_payload)?;
        let signature = signing_key.sign(&message_bytes);
        
        let request = SignedRequest {
            payload: unsigned_payload,
            signature: base64::encode(signature.to_bytes()),
        };

        // Network call with explicit error handling
        let response = match client.post(&send_url).json(&request).send().await {
            Ok(res) => res,
            Err(e) => {
                error!("Connection failed to {}: {}", send_url, e);
                return Err(e.into());
            }
        };

        // Handle Re-registration (404)
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            warn!("Agent ID {} not recognized. Resetting to 0 and re-registering.", current_id);
            config.client.id = Some("0".to_string());
            config.save()?; 
            continue; 
        }

        if !response.status().is_success() {
            error!("Server error ({}). Skipping this cycle.", response.status());
            return Ok(());
        }

        let json: serde_json::Value = response.json().await?;

        // 5. PROCESS COMMANDS
        match json["command"].as_str() {
            Some("REGISTER") => {
                if let Some(new_id) = json["id"].as_i64() {
                    let id_str = new_id.to_string();
                    info!("Registered successfully. New ID: {}", id_str);
                    config.client.id = Some(id_str);
                    config.save()?;
                }
            },
            Some("TEST") => {
                if let Some(tests_value) = json.get("data") {
                    let tests: Vec<Test> = serde_json::from_value(tests_value.clone())?;
                    process_compliance_tests(tests, &current_id, &signing_key, &client, &result_url).await;
                }
            },
            Some("NONE") => debug!("No pending commands from server."),
            _ => warn!("Received unknown command: {:?}", json["command"]),
        }

        break; 
    }

    Ok(())
}

/// Helper function to process tests without cluttering the main loop
async fn process_compliance_tests(
    tests: Vec<Test>, 
    client_id: &str, 
    signing_key: &SigningKey, 
    http_client: &reqwest::Client, 
    result_url: &str
) {
    info!("Processing {} compliance tests", tests.len());

    for test in tests {
        let test_id = test.id.unwrap_or(0);
        let mut results = Vec::new();

        // Check each of the 5 elements defined in the model
        let conditions = [
            (&test.element_1, &test.input_1, &test.selement_1, &test.condition_1, &test.sinput_1),
            (&test.element_2, &test.input_2, &test.selement_2, &test.condition_2, &test.sinput_2),
            (&test.element_3, &test.input_3, &test.selement_3, &test.condition_3, &test.sinput_3),
            (&test.element_4, &test.input_4, &test.selement_4, &test.condition_4, &test.sinput_4),
            (&test.element_5, &test.input_5, &test.selement_5, &test.condition_5, &test.sinput_5),
        ];

        for (e, i, se, c, si) in conditions {
            if let (Some(el), Some(inp), Some(sel)) = (e, i, se) {
                if el == "None" { continue; }
                results.push(evaluate(el, inp, sel, c.as_deref().unwrap_or(""), si.as_deref().unwrap_or("")));
            }
        }

        let final_result = if results.is_empty() {
            "NA".to_string()
        } else {
            let passed = match test.filter.as_deref().unwrap_or("all") {
                "any" => results.iter().any(|&r| r),
                _ => results.iter().all(|&r| r),
            };
            passed.to_string()
        };

        let payload = ComplianceResult {
            client_id: client_id.parse().unwrap_or(0),
            test_id,
            result: final_result,
        };

        // Sign and Send Result
        if let Ok(bytes) = bincode::serialize(&payload) {
            let signature = signing_key.sign(&bytes);
            let req = SignedRequest {
                payload,
                signature: base64::encode(signature.to_bytes()),
            };

            let _ = http_client.post(result_url).json(&req).send().await;
        }
    }
}
