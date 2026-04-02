//config.rs
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::error::Error;
use std::io::{Write, Read};
use std::fs::File;
use tracing::{info, warn, error};
use toml;

// Windows-specific imports
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;


use crate::get_config_path;

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub key: KeyPair,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ServerConfig {
    pub port: Option<String>,
    pub host: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ClientConfig {
    pub id: Option<String>,
    pub heartbeat: Option<String>,
    pub loglevel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub key_path: Option<String>,
    pub pub_key: Option<String>,
    pub priv_key: Option<String>,
    pub server_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {

        let config_dir = get_config_path()
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let keys_path = config_dir.join("keys").to_string_lossy().into_owned();
        Self {
            server: ServerConfig {
                host: Some("127.0.0.1".to_string()),
                port: Some("8000".to_string()),
            },
            client: ClientConfig {
                id: Some("0".to_string()),
                heartbeat: Some("300".to_string()),
                loglevel: Some("info".to_string()),
            },
            key: KeyPair {
                key_path: Some(keys_path.to_string()),
                pub_key: Some("scmclient.pub".to_string()),
                priv_key: Some("scmclient.key".to_string()),
                server_key: Some("scmserver.pub".to_string()),
            },
        }
    }
}


pub fn load_and_validate_config(file_path: &Path) -> Result<Config, Box<dyn Error>> {
    let mut valid = true;

    // --- SCENARIO 1: WINDOWS (Registry Only) ---
    #[cfg(target_os = "windows")]
    let mut config = {
        let _ = file_path; // Mark as unused on Windows to avoid warnings
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        // Open the key created by your NSIS installer
        let key = hklm.open_subkey("SOFTWARE\\OpenSCM")
            .map_err(|_| "OpenSCM Registry key not found. Please run the installer.")?;

        let name: String = key.get_value("ServerName").unwrap_or_else(|_| "localhost".to_string());
        let port: String = key.get_value("ServerPort").unwrap_or_else(|_| "8000".to_string());
        let heartbeat: String = key.get_value("Heartbeat").unwrap_or_else(|_| "300".to_string());
        let log_level: String = key.get_value("LogLevel").unwrap_or_else(|_| "info".to_string());

        // Initialize your Config struct with Registry values
        // Note: You must ensure other fields have defaults
        Config {
            server: ServerConfig { host: Some(name), port: Some(port) },
            client: ClientConfig { heartbeat: Some(heartbeat), loglevel: Some(log_level) },
            key: KeyConfig::default(), // Assuming KeyConfig has a Default implementation
            ..Config::default() 
        }
    };

    // --- SCENARIO 2: UNIX (TOML File Only) ---
    #[cfg(unix)]
    let mut config = {
        let mut file = File::open(file_path).map_err(|e| {
            format!("Could not open config file {:?}: {}", file_path, e)
        })?;

        let mut content = String::new();
        file.read_to_string(&mut content)?;
        
        let cfg: Config = toml::from_str(&content).map_err(|e| {
            format!("Failed to parse TOML in {:?}: {}", file_path, e)
        })?;
        cfg
    };

    // 1. Port Validation
    if let Some(p) = &config.server.port {
        if p.parse::<u16>().is_err() {
            error!("Invalid port: {}", p);
            valid = false;
        }
    }

    // 2. Heartbeat Validation
    if let Some(h) = &config.client.heartbeat {
        if h.parse::<u32>().is_err() {
            error!("Invalid heartbeat: {}", h);
            valid = false;
        }
    }

    // 3. LogLevel Validation
    if let Some(l) = &config.client.loglevel {
        let levels = ["trace", "debug", "info", "warn", "error"];
        if !levels.contains(&l.to_lowercase().as_str()) {
            warn!("Unknown log level '{}'. Defaulting to 'info'.", l);
            config.client.loglevel = Some("info".to_string());
        }
    }


    // --- COMMON LOGIC: Keys Management ---
    // On Windows, we'll use the executable folder as the base for keys
    let base_dir = if cfg!(windows) {
        std::env::current_exe()?.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        file_path.parent().unwrap_or(Path::new(".")).to_path_buf()
    };

    let key_dir = config.key.key_path.as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir.join("keys"));

    if !key_dir.exists() {
        warn!("Keys dir does not exist. Creating: {}", key_dir.display());
        fs::create_dir_all(&key_dir)?;
    }

    let pub_path = key_dir.join(config.key.pub_key.as_deref().unwrap_or("scmclient.pub"));
    let priv_path = key_dir.join(config.key.priv_key.as_deref().unwrap_or("scmclient.key"));

    generate_keys_if_missing(
        &pub_path.to_string_lossy(),
        &priv_path.to_string_lossy(),
    )?;

    if valid {
        Ok(config)
    } else {
        Err(format!("Invalid configuration detected.").into())
    }
}



impl Config {
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let toml_string = toml::to_string_pretty(self)?;
        std::fs::write(path, toml_string)?;
        Ok(())
    }
}


pub fn generate_keys_if_missing(public_key_path: &str, private_key_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pub_exists = Path::new(public_key_path).exists();
    let priv_exists = Path::new(private_key_path).exists();

    if pub_exists && priv_exists {
        return Ok(());
    }

    warn!("One or both key files are missing. Generating new Ed25519 keypair.");

    let mut csprng = OsRng; // Use a cryptographically secure random number generator
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = VerifyingKey::from(&signing_key);

    // Save private key (base64 encoded)
    let mut priv_file = fs::File::create(private_key_path)?;
    priv_file.write_all(base64::encode(signing_key.to_bytes()).as_bytes())?;

    // Save public key (base64) - This part was already correct
    let mut pub_file = fs::File::create(public_key_path)?;
    pub_file.write_all(&base64::encode(verify_key.to_bytes()).as_bytes())?;

    info!("Generated and saved new Ed25519 keypair.");

    Ok(())
}



