use sys_info;
use tracing::{info, warn, error, debug};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use std::fs;
use std::path::PathBuf;
use base64::{engine::general_purpose, Engine as _};
use reqwest;
use chrono;

// Project-specific imports
use crate::models::{UnsignedPayload, SignedRequest, SignedResponse, Test, ComplianceResult};
use crate::config::Config;
use crate::compliance::evaluate;

pub async fn send_system_info(
    config: &mut Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. COLLECT SYSTEM METADATA
    let my_local_ip = local_ip_address::local_ip()?.to_string();
    let my_hostname = gethostname::gethostname().to_string_lossy().into_owned();
    let my_os = format!("{} {}", sys_info::os_type()?, sys_info::os_release()?);
    let my_arch = std::env::consts::ARCH.to_string();
    let my_ver = env!("CARGO_PKG_VERSION").to_string();

    // 2. CONSTRUCT URLS
    let base_url = format!(
        "http://{}:{}",
        config.server.host.as_deref().unwrap_or("localhost"),
        config.server.port.as_deref().unwrap_or("8000")
    );
    let send_url = format!("{}/send", base_url);
    let result_url = format!("{}/result", base_url);

    // 3. LOAD CLIENT IDENTITY KEYS
    let key_dir = PathBuf::from(config.key.key_path.as_deref().ok_or("Key path missing in config")?);
    let pub_path = key_dir.join(config.key.pub_key.as_deref().unwrap_or("scmclient.pub"));
    let priv_path = key_dir.join(config.key.priv_key.as_deref().unwrap_or("scmclient.key"));
    let server_pub_path = key_dir.join(config.key.server_key.as_deref().unwrap_or("scmserver.pub"));

    let public_base64 = fs::read_to_string(&pub_path)?.trim().to_string();
    let private_base64 = fs::read_to_string(&priv_path)?;
    let private_bytes = general_purpose::STANDARD.decode(private_base64.trim())?;
    
    let signing_key = SigningKey::from_bytes(&private_bytes.try_into().map_err(|_| "Invalid private key format")?);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // 4. COMMUNICATION LOOP
    loop {
        let current_id = config.client.id.clone().unwrap_or_else(|| "0".to_string());

        // HANDSHAKE LOGIC: Send our key if we are new (ID 0) OR if we lost the server's public key
        let needs_handshake = current_id == "0" || !server_pub_path.exists();

        let unsigned_payload = UnsignedPayload {
            id: current_id.clone(),
            hostname: my_hostname.clone(),
            ver: my_ver.clone(),
            ip: my_local_ip.clone(),
            os: my_os.clone(),
            arch: my_arch.clone(),
            timestamp: chrono::Utc::now().timestamp().to_string(),
            public_key: if needs_handshake { Some(public_base64.clone()) } else { None },
        };

        // Sign the request
        let message_bytes = bincode::serialize(&unsigned_payload)?;
        let signature = signing_key.sign(&message_bytes);
        let request = SignedRequest {
            payload: unsigned_payload,
            signature: general_purpose::STANDARD.encode(signature.to_bytes()),
        };

        // Dispatch Heartbeat
        let response = match client.post(&send_url).json(&request).send().await {
            Ok(res) => res,
            Err(e) => {
                error!("Connection failed to {}: {}", send_url, e);
                return Err(e.into());
            }
        };

        // Handle 404 (Server lost our ID)
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            warn!("Agent ID {} not recognized by server. Resetting to 0.", current_id);
            config.client.id = Some("0".to_string());
            config.save()?;
            continue; 
        }

        if !response.status().is_success() {
            error!("Server returned error status: {}", response.status());
            return Ok(());
        }

        // ==========================================
        // 5. UNWRAP AND VERIFY SERVER RESPONSE
        // ==========================================
        let signed_res: SignedResponse = response.json().await?;
        debug!("Message received: Secure envelope successfully extracted.");

        let inner_json = &signed_res.payload;

        // Verify Signature if we have the server's public key
        if server_pub_path.exists() {
            let server_pub_base64 = fs::read_to_string(&server_pub_path)?;
            let server_pub_bytes = general_purpose::STANDARD.decode(server_pub_base64.trim())?;
            let verifier = VerifyingKey::from_bytes(&server_pub_bytes.try_into().map_err(|_| "Invalid server pubkey")?)?;
            
            let sig_bytes = general_purpose::STANDARD.decode(&signed_res.signature)?;
            let signature = Signature::from_bytes(&sig_bytes.try_into().map_err(|_| "Invalid signature length")?);
            
            let payload_bytes = bincode::serialize(inner_json)?;
            
            if let Err(e) = verifier.verify(&payload_bytes, &signature) {
                error!("SECURITY ALERT: Server signature verification FAILED! Packet dropped. Error: {}", e);
                return Ok(()); 
            }
            info!("✅ Server identity verified. Signature approved.");
        } else {
            warn!("Handshake in progress: Processing unsigned response (Initial trust).");
        }

        // ==========================================
        // 6. PROCESS VERIFIED PAYLOAD
        // ==========================================
        
        // Check for Server Public Key (Self-Healing Handshake)
        if let Some(server_key) = inner_json.get("server_public_key").and_then(|k| k.as_str()) {
            fs::write(&server_pub_path, server_key.trim())?;
            info!("Identity Handshake: Server public key saved successfully.");
        }

        // Extract and Match Command
        match inner_json.get("command").and_then(|c| c.as_str()) {
            Some("REGISTER") => {
                if let Some(new_id_val) = inner_json.get("id").and_then(|id| id.as_i64()) {
                    let id_str = new_id_val.to_string();
                    info!("Registration Complete: New Agent ID assigned: {}", id_str);
                    config.client.id = Some(id_str);
                    config.save()?;
                }
            },
            Some("TEST") => {
                if let Some(tests_value) = inner_json.get("data") {
                    let tests: Vec<Test> = serde_json::from_value(tests_value.clone())?;
                    info!("Verified command received: Processing {} compliance tests.", tests.len());
                    
                    process_compliance_tests(
                        tests, 
                        &current_id, 
                        &signing_key, 
                        &client, 
                        &result_url
                    ).await;
                }
            },
            Some("NONE") => debug!("Heartbeat successful: No pending commands."),
            _ => warn!("Received unknown or empty command from server."),
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
                signature: general_purpose::STANDARD.encode(signature.to_bytes()),
            };

            let _ = http_client.post(result_url).json(&req).send().await;
        }
    }
}
