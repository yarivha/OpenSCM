use sys_info;
use os_info;
use tracing::{info, warn, error, debug};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use std::fs;
use std::path::PathBuf;
use base64::{engine::general_purpose, Engine as _};
use reqwest;
use chrono;
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;

// Project-specific imports
use crate::models::{UnsignedPayload, SignedRequest, SignedResponse, Test, ComplianceResult};
use crate::config::Config;
use crate::compliance::evaluate;

/// Generates a consistent 8-character hex prefix based on the server URL.
fn get_url_namespace(url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(url.trim_end_matches('/').as_bytes());
    let result = hasher.finalize();
    hex::encode(result)[..8].to_string()
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

        // Check each of the 5 potential conditions in the OpenSCM test model
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
            if passed { "PASS".to_string() } else { "FAIL".to_string() }
        };

        let payload = ComplianceResult {
            client_id: client_id.parse().unwrap_or(0),
            test_id,
            result: final_result,
        };

        // Sign and Send Result back to the server
        if let Ok(bytes) = bincode::serialize(&payload) {
            let signature = signing_key.sign(&bytes);
            let req = SignedRequest {
                payload,
                signature: general_purpose::STANDARD.encode(signature.to_bytes()),
            };

            match http_client.post(result_url).json(&req).send().await {
                Ok(_) => debug!("Test {} result sent successfully.", test_id),
                Err(e) => error!("Failed to send test {} result: {}", test_id, e),
            }
        }
    }
}


pub async fn send_system_info(
    config: &Config, // Removed 'mut' - we don't need to save the config anymore
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. DERIVE NAMESPACED PATHS
    let namespace = get_url_namespace(&config.server.url);
    let key_dir = PathBuf::from(config.key.key_path.as_deref().unwrap_or("."));

    // Identity is now stored in files like 'client_a1b2c3d4.id'
    let id_path = key_dir.join(format!("client_{}.id", namespace));
    let priv_path = key_dir.join(format!("client_{}.key", namespace));
    let pub_path = key_dir.join(format!("client_{}.pub", namespace));
    let server_pub_path = key_dir.join(format!("server_{}.pub", namespace));

    // 2. ENSURE CLIENT KEYS EXIST (Self-generate if missing for this namespace)
    if !priv_path.exists() {
        info!("No identity found for namespace {}. Generating new keys...", namespace);
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);
        
        fs::write(&priv_path, general_purpose::STANDARD.encode(signing_key.to_bytes()))?;
        fs::write(&pub_path, general_purpose::STANDARD.encode(verifying_key.to_bytes()))?;
    }

    // 3. LOAD IDENTITY
    let current_id = if id_path.exists() {
        fs::read_to_string(&id_path)?.trim().to_string()
    } else {
        "0".to_string()
    };

    let private_base64 = fs::read_to_string(&priv_path)?;
    let private_bytes = general_purpose::STANDARD.decode(private_base64.trim())?;
    let signing_key = SigningKey::from_bytes(&private_bytes.try_into().map_err(|_| "Invalid key format")?);
    let public_base64 = fs::read_to_string(&pub_path)?.trim().to_string();

    // 4. COLLECT SYSTEM METADATA
    
    let osinfo = os_info::get();

    let my_local_ip = local_ip_address::local_ip()?.to_string();
    let my_hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let my_os = format!("{} {}", osinfo.os_type(), osinfo.version());
    let my_arch = std::env::consts::ARCH.to_string();
    let my_ver = env!("CARGO_PKG_VERSION").to_string();

    let base_url = config.server.url.trim_end_matches('/').to_string();
    let send_url = format!("{}/send", base_url);
    let result_url = format!("{}/result", base_url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // 5. COMMUNICATION LOOP
    loop {
        let needs_handshake = current_id == "0" || !server_pub_path.exists();

        let unsigned_payload = UnsignedPayload {
            id: current_id.clone(),
            tenant_id: config.server.tenant_id.clone(),
            hostname: my_hostname.clone(),
            ver: my_ver.clone(),
            ip: my_local_ip.clone(),
            os: my_os.clone(),
            arch: my_arch.clone(),
            timestamp: chrono::Utc::now().timestamp().to_string(),
            public_key: if needs_handshake { Some(public_base64.clone()) } else { None },
        };

        let message_bytes = bincode::serialize(&unsigned_payload)?;
        let signature = signing_key.sign(&message_bytes);
        let request = SignedRequest {
            payload: unsigned_payload,
            signature: general_purpose::STANDARD.encode(signature.to_bytes()),
        };

        let response = client.post(&send_url).json(&request).send().await?;

        // Handle 404 (Server lost our ID for this specific URL)
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            warn!("Server at {} rejected ID {}. Resetting identity.", base_url, current_id);
            let _ = fs::remove_file(&id_path);
            let _ = fs::remove_file(&server_pub_path);
            return Ok(()); // Exit loop to trigger re-registration on next start
        }

        if !response.status().is_success() {
            error!("Server error: {}", response.status());
            return Ok(());
        }

        let signed_res: SignedResponse = response.json().await?;
        let inner_json = &signed_res.payload;

        // VERIFY SERVER IDENTITY (Only if we have the server key)
        if server_pub_path.exists() {
            let server_pub_bytes = general_purpose::STANDARD.decode(fs::read_to_string(&server_pub_path)?.trim())?;
            let verifier = VerifyingKey::from_bytes(&server_pub_bytes.try_into().map_err(|_| "Bad server key")?)?;
            let sig_bytes = general_purpose::STANDARD.decode(&signed_res.signature)?;
            let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| "Bad sig")?);
            
            if verifier.verify(&bincode::serialize(inner_json)?, &signature).is_err() {
                error!("SECURITY ALERT: Mismatch on {}! Connection dropped.", base_url);
                return Ok(()); 
            }
        }

        // PROCESS COMMANDS
        if let Some(server_key) = inner_json.get("server_public_key").and_then(|k| k.as_str()) {
            fs::write(&server_pub_path, server_key.trim())?;
            info!("Server key saved for namespace {}", namespace);
        }

        match inner_json.get("command").and_then(|c| c.as_str()) {
            Some("REGISTER") => {
                if let Some(new_id) = inner_json.get("id").and_then(|id| id.as_i64()) {
                    fs::write(&id_path, new_id.to_string())?;
                    info!("Registered as ID: {} for {}", new_id, base_url);
                }
            },
            Some("TEST") => {
                if let Some(tests_val) = inner_json.get("data") {
                    let tests: Vec<Test> = serde_json::from_value(tests_val.clone())?;
                    process_compliance_tests(tests, &current_id, &signing_key, &client, &result_url).await;
                }
            },
            _ => debug!("Heartbeat OK."),
        }
        break; 
    }
    Ok(())
}
