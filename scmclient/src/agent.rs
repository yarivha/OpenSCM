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

use crate::models::{UnsignedPayload, SignedRequest, SignedResponse, Test, ComplianceResult};
use crate::config::{Config, key_path};
use crate::compliance::{evaluate, EvalResult};


// ============================================================
// HELPERS
// ============================================================

/// Generate a consistent 8-character hex prefix based on the server URL.
/// Used to namespace key and identity files per server.
fn get_url_namespace(url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(url.trim_end_matches('/').as_bytes());
    let result = hasher.finalize();
    hex::encode(result)[..8].to_string()
}


/// Decode a base64-encoded Ed25519 public key into a VerifyingKey.
fn decode_public_key(base64_key: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let bytes = general_purpose::STANDARD.decode(base64_key.trim())?;
    let key_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Public key must be exactly 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&key_array)?)
}


/// Decode a base64-encoded Ed25519 signature.
fn decode_signature(base64_sig: &str) -> Result<Signature, Box<dyn std::error::Error>> {
    let bytes = general_purpose::STANDARD.decode(base64_sig.trim())?;
    let sig_array: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "Signature must be exactly 64 bytes")?;
    Ok(Signature::from_bytes(&sig_array))
}


/// Sign a serializable payload using serde_json for cross-platform determinism.
fn sign_payload<T: serde::Serialize>(
    payload: &T,
    signing_key: &SigningKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(payload)?;
    let signature = signing_key.sign(&bytes);
    Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
}


/// Verify a server response signature using serde_json serialization.
fn verify_server_response(
    payload: &serde_json::Value,
    signature_b64: &str,
    verifier: &VerifyingKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let signature = decode_signature(signature_b64)?;
    verifier
        .verify(&payload_bytes, &signature)
        .map_err(|_| "Server signature verification failed".into())
}


/// Write a file with restricted permissions (0o600) on Unix.
/// On non-Unix platforms falls back to a regular write.
fn write_private_file(path: &PathBuf, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true).mode(0o600);
        let mut file = options.open(path)?;
        use std::io::Write;
        file.write_all(contents.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)?;
    }

    Ok(())
}


// ============================================================
// COMPLIANCE TEST PROCESSING
// ============================================================

async fn process_compliance_tests(
    tests: Vec<Test>,
    client_id: &str,
    tenant_id: &str,
    signing_key: &SigningKey,
    http_client: &reqwest::Client,
    result_url: &str,
) {
    info!("Processing {} compliance test(s).", tests.len());

    // Parse client_id once — reject if invalid
    let client_id_int: i64 = match client_id.parse() {
        Ok(id) if id > 0 => id,
        _ => {
            error!("Invalid client_id '{}' — cannot send results.", client_id);
            return;
        }
    };

    for test in tests {
        let test_id = test.id.unwrap_or(0);

        let conditions = [
            (&test.element_1, &test.input_1, &test.selement_1, &test.condition_1, &test.sinput_1),
            (&test.element_2, &test.input_2, &test.selement_2, &test.condition_2, &test.sinput_2),
            (&test.element_3, &test.input_3, &test.selement_3, &test.condition_3, &test.sinput_3),
            (&test.element_4, &test.input_4, &test.selement_4, &test.condition_4, &test.sinput_4),
            (&test.element_5, &test.input_5, &test.selement_5, &test.condition_5, &test.sinput_5),
        ];

        let mut results = Vec::new();
        for (e, i, se, c, si) in conditions {
            if let (Some(el), Some(inp), Some(sel)) = (e, i, se) {
                if el == "None" {
                    continue;
                }
                results.push(evaluate(
                    el,
                    inp,
                    sel,
                    c.as_deref().unwrap_or(""),
                    si.as_deref().unwrap_or(""),
                ));
            }
        }

        
        let final_result = if results.is_empty() {
            "NA".to_string()
        } else {
            match test.filter.as_deref().unwrap_or("all") {
                "any" => {
                    // ANY: if at least one PASS → PASS
                    // if all NA → NA
                    // otherwise FAIL
                    if results.iter().any(|r| *r == EvalResult::Pass) {
                        "PASS".to_string()
                    } else if results.iter().all(|r| *r == EvalResult::Na) {
                        "NA".to_string()
                    } else {
                        "FAIL".to_string()
                    }
                }
                _ => {
                    // ALL: if any FAIL → FAIL
                    // if all NA → NA
                    // if all PASS (or mix of PASS+NA) → PASS
                    if results.iter().any(|r| *r == EvalResult::Fail) {
                        "FAIL".to_string()
                    } else if results.iter().all(|r| *r == EvalResult::Na) {
                        "NA".to_string()
                    } else {
                        "PASS".to_string()
                    }
                }
            }
        };


        debug!("Test ID {} result: {}", test_id, final_result);

        let payload = ComplianceResult {
            client_id: client_id_int,
            tenant_id: tenant_id.to_string(),
            test_id,
            result: final_result,
        };

        // Sign with serde_json for cross-platform determinism
        let signature = match sign_payload(&payload, signing_key) {
            Ok(sig) => sig,
            Err(e) => {
                error!("Failed to sign result for test {}: {}", test_id, e);
                continue;
            }
        };

        let req = SignedRequest {
            payload,
            signature,
        };

        match http_client.post(result_url).json(&req).send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!("Test {} result sent successfully.", test_id);
            }
            Ok(resp) => {
                error!(
                    "Server rejected result for test {} with status: {}",
                    test_id,
                    resp.status()
                );
            }
            Err(e) => {
                error!("Failed to send result for test {}: {}", test_id, e);
            }
        }
    }
}


// ============================================================
// MAIN AGENT FUNCTION
// ============================================================

pub async fn send_system_info(
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {

    // 1. Derive namespaced file paths per server URL
    let namespace = get_url_namespace(&config.server.url);
    let key_dir = std::path::Path::new(key_path()).parent().expect("Core key directory must have a parent path");

    let id_path         = key_dir.join(format!("client_{}.id", namespace));
    let priv_path       = key_dir.join(format!("client_{}.key", namespace));
    let pub_path        = key_dir.join(format!("client_{}.pub", namespace));
    let server_pub_path = key_dir.join(format!("server_{}.pub", namespace));

    // 2. Generate client keys if missing for this namespace
    if !priv_path.exists() {
        info!(
            "No identity found for namespace '{}'. Generating new Ed25519 keypair...",
            namespace
        );
        let mut csprng = OsRng;
        let signing_key   = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);

        // Write private key with restricted permissions
        write_private_file(
            &priv_path,
            &general_purpose::STANDARD.encode(signing_key.to_bytes()),
        )?;

        fs::write(
            &pub_path,
            general_purpose::STANDARD.encode(verifying_key.to_bytes()),
        )?;

        info!("New keypair generated for namespace '{}'.", namespace);
    }

    // 3. Load identity and keys
    let current_id = if id_path.exists() {
        fs::read_to_string(&id_path)?.trim().to_string()
    } else {
        "0".to_string()
    };

    let private_base64 = fs::read_to_string(&priv_path)?;
    let private_bytes  = general_purpose::STANDARD.decode(private_base64.trim())?;
    let key_array: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| "Invalid private key length: expected 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&key_array);

    let public_base64 = fs::read_to_string(&pub_path)?.trim().to_string();

    // 4. Collect system metadata
    let osinfo       = os_info::get();
    let my_local_ip  = local_ip_address::local_ip()?.to_string();
    let my_hostname  = gethostname::gethostname().to_string_lossy().into_owned();
    let my_os        = format!("{} {}", osinfo.os_type(), osinfo.version());
    let my_arch      = std::env::consts::ARCH.to_string();
    let my_ver       = env!("CARGO_PKG_VERSION").to_string();

    let base_url   = config.server.url.trim_end_matches('/').to_string();
    let send_url   = format!("{}/send", base_url);
    let result_url = format!("{}/result", base_url);

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // 5. Build and sign payload
    let needs_handshake = current_id == "0" || !server_pub_path.exists();

    let unsigned_payload = UnsignedPayload {
        id:         current_id.clone(),
        tenant_id:  config.server.tenant_id.clone(),
        hostname:   my_hostname.clone(),
        ver:        my_ver.clone(),
        ip:         my_local_ip.clone(),
        os:         my_os.clone(),
        arch:       my_arch.clone(),
        timestamp:  chrono::Utc::now().timestamp().to_string(),
        public_key: if needs_handshake { Some(public_base64.clone()) } else { None },
    };

    // Sign with serde_json for cross-platform determinism
    let signature = sign_payload(&unsigned_payload, &signing_key)?;

    let request = SignedRequest {
        payload:   unsigned_payload,
        signature,
    };

    // 6. Send to server
    let response = http_client
        .post(&send_url)
        .json(&request)
        .send()
        .await?;

    // Handle 404 — server lost our identity, reset and re-register next cycle
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        warn!(
            "Server at '{}' rejected ID '{}'. Resetting identity for re-registration.",
            base_url, current_id
        );
        let _ = fs::remove_file(&id_path);
        let _ = fs::remove_file(&server_pub_path);
        return Ok(());
    }

    if !response.status().is_success() {
        error!("Server returned error status: {}", response.status());
        return Ok(());
    }

    let signed_res: SignedResponse = response.json().await?;
    let inner_json = &signed_res.payload;

    // 7. Verify server signature (only if we have the server public key)
    if server_pub_path.exists() {
        let server_pub_b64 = fs::read_to_string(&server_pub_path)?;
        match decode_public_key(&server_pub_b64) {
            Ok(verifier) => {
                if let Err(e) =
                    verify_server_response(inner_json, &signed_res.signature, &verifier)
                {
                    error!(
                        "SECURITY ALERT: Invalid server signature from '{}': {}. Connection dropped.",
                        base_url, e
                    );
                    return Ok(());
                }
                debug!("Server signature verified for '{}'.", base_url);
            }
            Err(e) => {
                error!("Failed to load server public key: {}", e);
                return Ok(());
            }
        }
    }

    // 8. Process server response

    // Save server public key if provided
    if let Some(server_key) = inner_json
        .get("server_public_key")
        .and_then(|k| k.as_str())
    {
        fs::write(&server_pub_path, server_key.trim())?;
        info!("Server public key saved for namespace '{}'.", namespace);
    }

    // Handle commands
    match inner_json.get("command").and_then(|c| c.as_str()) {
        Some("REGISTER") => {
            if let Some(new_id) = inner_json.get("id").and_then(|id| id.as_i64()) {
                let new_id_str = new_id.to_string();
                fs::write(&id_path, &new_id_str)?;
                info!(
                    "Registered with server '{}' as Agent ID: {}.",
                    base_url, new_id
                );
            } else {
                error!("REGISTER command received but no ID in response.");
            }
        }

        Some("TEST") => {
            if let Some(tests_val) = inner_json.get("data") {
                match serde_json::from_value::<Vec<Test>>(tests_val.clone()) {
                    Ok(tests) => {
                        process_compliance_tests(
                            tests,
                            &current_id,
                            &config.server.tenant_id,
                            &signing_key,
                            &http_client,
                            &result_url,
                        )
                        .await;
                    }
                    Err(e) => {
                        error!("Failed to deserialize test data: {}", e);
                    }
                }
            } else {
                warn!("TEST command received but no data in response.");
            }
        }

        Some("NONE") | None => {
            debug!("Heartbeat OK — no commands pending.");
        }

        Some(unknown) => {
            warn!("Unknown command received from server: '{}'.", unknown);
        }
    }

    Ok(())
}
