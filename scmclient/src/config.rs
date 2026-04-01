//config.rs
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::error::Error;
use std::io::Write;
use std::fs::File;
use tracing::{info, warn, error};
use toml;

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
    pub heartbeat_secs: Option<String>,
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
                heartbeat_secs: Some("300".to_string()),
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


use std::io::Read; // חשוב לצורך קריאת הקובץ למחרוזת

pub fn load_and_validate_config(file_path: &Path) -> Result<Config, Box<dyn Error>> {
    let mut valid = true;

    // Open config file
    let mut file = File::open(file_path).map_err(|e| {
        format!("Could not open config file {:?}: {}", file_path, e)
    })?;

    // Read config file
    let mut content = String::new();
    file.read_to_string(&mut content).map_err(|e| {
        format!("Failed to read config file {:?}: {}", file_path, e)
    })?;

    // Parse config file
    let mut config: Config = toml::from_str(&content).map_err(|e| {
        format!("Failed to parse TOML in {:?}: {}", file_path, e)
    })?;



    
    // Port
    if let Some(p) = &config.server.port {
        if p.parse::<u16>().map_or(true, |port| !(1..=65000).contains(&port)) {
            error!("Invalid port: {}. Must be 1–65000.", p);
            valid = false;
        }
    } else {
        config.server.port = Some("8000".to_string());
    }

    
    // Keys
    let base_dir = file_path.parent().unwrap_or(Path::new("."));
    let key_dir = config.key.key_path.as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir.join("keys"));

    if !key_dir.exists() {
        warn!("Keys dir does not exist. Creating: {}", key_dir.display());
        fs::create_dir_all(&key_dir).map_err(|e| {
            format!("Failed to create key directory {}: {}", key_dir.display(), e)
        })?;
    }

    let pub_name = config.key.pub_key.as_deref().unwrap_or("scmclient.pub");
    let priv_name = config.key.priv_key.as_deref().unwrap_or("scmclient.key");
    
    let pub_path = key_dir.join(pub_name);
    let priv_path = key_dir.join(priv_name);

    generate_keys_if_missing(
        &pub_path.to_string_lossy(),
        &priv_path.to_string_lossy(),
    )?;

    if valid {
        Ok(config)
    } else {
        Err(format!("Invalid configuration in file: {:?}", file_path).into())
    }
}


impl Config {
    // שינוי מ-&str ל-AsRef<Path> מאפשר לקבל גם PathBuf וגם &str
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



