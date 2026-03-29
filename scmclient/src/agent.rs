use sys_info;
use tracing::{debug, info, warn, error};
use ed25519_dalek::{SigningKey, Signer};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{UnsignedPayload, SignedRequest, Test, ComplianceResult};
use crate::config::Config;
use crate::compliance::evaluate;

fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}


pub async fn send_system_info(
    config: &mut Config,
    config_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // === System Info ===
    let my_local_ip = local_ip_address::local_ip()?.to_string();
    let my_hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let my_os = format!("{} {}", sys_info::os_type()?, sys_info::os_release()?);
    let my_arch = std::env::consts::ARCH.to_string();
    let my_ver = env!("CARGO_PKG_VERSION");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let base_url = format!(
        "http://{}:{}",
        config.server.host.clone().unwrap_or_else(|| "localhost".to_string()),
        config.server.port.clone().unwrap_or_else(|| "8000".to_string())
    );
    let send_url = format!("{}/send", base_url);
    let result_url = format!("{}/result", base_url);

    // === Keys ===
    let keys_path = config.key.key_path.as_ref().expect("key_path is missing");
    let public_path = PathBuf::from(keys_path).join("scmclient.pub");
    let private_path = PathBuf::from(keys_path).join("scmclient.key");

    let public_base64 = fs::read_to_string(&public_path)?.trim().to_string();
    let private_base64 = fs::read_to_string(&private_path)?.trim().to_string();
    let private_bytes = base64::decode(private_base64)?;
    let key_bytes: [u8; 32] = private_bytes.as_slice().try_into()?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // === Prepare Payload ===
    let mut current_id = config.client.id.clone().unwrap_or_else(|| "0".to_string());

    loop {
        let unsigned_payload = UnsignedPayload {
            id: current_id.clone(),
            hostname: my_hostname.clone(),
            ip: my_local_ip.clone(),
            os: my_os.clone(),
            arch: my_arch.clone(),
            timestamp: get_timestamp().to_string(),
            public_key: public_base64.clone(),
        };

        let message_bytes = bincode::serialize(&unsigned_payload)?;
        let signature = signing_key.sign(&message_bytes);
        let signature_base64 = base64::encode(signature.to_bytes());

        let request = SignedRequest {
            payload: unsigned_payload,
            signature: signature_base64,
        };

        // === Send ===
        let response = client.post(&send_url).json(&request).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            warn!("Agent ID {} not found on server, re-registering...", current_id);
            current_id = "0".to_string(); // reset local ID to force registration
            config.client.id = Some(current_id.clone());
            config.save_to(config_path.to_str().unwrap())?;
            continue; // re-send with new ID
        }

        if !response.status().is_success() {
            error!("HTTP Error: {}", response.status());
            return Ok(());
        }

        let json: serde_json::Value = response.json().await?;
        debug!("Server response: {}", serde_json::to_string_pretty(&json)?);

        // === Handle Commands ===
        match json["command"].as_str() {
            Some("REGISTER") => {
                info!("REGISTER command received");
                if let Some(server_id) = json.get("id").and_then(|v| v.as_i64()) {
                    let server_id_str = server_id.to_string();
                    if config.client.id.as_deref() != Some(&server_id_str) {
                        info!("Saving new client ID: {}", server_id_str);
                        config.client.id = Some(server_id_str.clone());
                        current_id = server_id_str;
                        config.save_to(config_path.to_str().unwrap())?;
                    }
                }
            }
            Some("NONE") => info!("No commands received"),

            Some("TEST") => {
                let tests_json = json.get("data").cloned().unwrap_or_default();
                let tests: Vec<Test> = match serde_json::from_value(tests_json) {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Failed to parse tests: {}", e);
                        return Ok(());
                    }
                };

                info!("Received {} tests", tests.len());

                for test in tests {
                    let test_id = test.id.unwrap_or(0);
                    info!("Test Name: {}", test.name);

                    let mut results = Vec::new();

                    let conditions = vec![
                        (test.element_1.as_deref(), test.input_1.as_deref(), test.selement_1.as_deref(), test.condition_1.as_deref(), test.sinput_1.as_deref()),
                        (test.element_2.as_deref(), test.input_2.as_deref(), test.selement_2.as_deref(), test.condition_2.as_deref(), test.sinput_2.as_deref()),
                        (test.element_3.as_deref(), test.input_3.as_deref(), test.selement_3.as_deref(), test.condition_3.as_deref(), test.sinput_3.as_deref()),
                        (test.element_4.as_deref(), test.input_4.as_deref(), test.selement_4.as_deref(), test.condition_4.as_deref(), test.sinput_4.as_deref()),
                        (test.element_5.as_deref(), test.input_5.as_deref(), test.selement_5.as_deref(), test.condition_5.as_deref(), test.sinput_5.as_deref()),
                    ];

                    for (element, input, selement, condition, sinput) in conditions {
                        if element.unwrap_or("None") == "None" {
                            continue;
                        }
                        if let (Some(e), Some(i), Some(se)) = (element, input, selement) {
                            let res = evaluate(
                                e,
                                i,
                                se,
                                condition.unwrap_or(""),
                                sinput.unwrap_or(""),
                            );
                            results.push(res);
                        }
                    }

                    let result = if results.is_empty() {
                        "NA".to_string()
                    } else {
                        match test.filter.as_deref().unwrap_or("all") {
                            "any" => {
                                if results.iter().any(|&r| r) { "true".to_string() } else { "false".to_string() }
                            }
                            _ => {
                                if results.iter().all(|&r| r) { "true".to_string() } else { "false".to_string() }
                            }
                        }
                    };

                    let result_payload = ComplianceResult {
                        client_id: current_id.parse().unwrap_or(0),
                        test_id,
                        result,
                    };

                    let result_bytes = bincode::serialize(&result_payload)?;
                    let signature = signing_key.sign(&result_bytes);
                    let signature_base64 = base64::encode(signature.to_bytes());

                    let signed_request = SignedRequest {
                        payload: result_payload,
                        signature: signature_base64,
                    };

                    if let Err(e) = client.post(&result_url).json(&signed_request).send().await {
                        error!("Failed to send result for {}: {}", test.name, e);
                    } else {
                        info!("Result sent for test {}", test.name);
                    }
                }
            }

            other => error!("Unknown command from server: {:?}", other),
        }

        break; // exit loop if send successful
    }

    Ok(())
}

