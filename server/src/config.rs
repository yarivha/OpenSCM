// src/config.rs
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::io::Write;
use std::error::Error;
use tracing::{info, warn, error};
use toml;

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub key: KeyPair,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ServerConfig {
    pub port: Option<String>,
    pub loglevel: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct KeyPair {
    pub key_path: Option<String>,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: Some("8000".to_string()),
                loglevel: Some("info".to_string()),
            },
            database: DatabaseConfig {
                path: "scm.db".to_string(),
            },
            key: KeyPair {
                key_path: Some("./keys".to_string()),
                public_key: Some("scmserver.pub".to_string()),
                private_key: Some("scmserver.key".to_string()),
            },
        }
    }
}

pub fn load_and_validate_config(file_path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(file_path)?;
    let mut config: Config = toml::from_str(&contents)?;

    let mut valid = true;

    // Port
    config.server.port = match &config.server.port {
        Some(p) => match p.parse::<u16>() {
            Ok(port) if (1..=65000).contains(&port) => Some(p.clone()),
            _ => {
                error!("Invalid port: {:?}. Must be 1–65000.", p);
                valid = false;
                Some("8000".to_string())
            }
        },
        None => {
            error!("Missing port. Using default.");
            Some("8000".to_string())
        }
    };

    
    // Loglevel
    config.server.loglevel = match &config.server.loglevel {
        Some(level) => {
            let level = level.to_lowercase();
            let valid_levels = ["debug", "info", "warn", "error"];
            if valid_levels.contains(&level.as_str()) {
                Some(level)
            } else {
                error!("Invalid loglevel: {}. Must be one of {:?}", level, valid_levels);
                valid = false;
                Some("info".to_string())
            }
        }
        None => {
            error!("Missing loglevel. Using default.");
            Some("info".to_string())
        }
    };
    
    // Keys
    let key_path = config.key.key_path.as_deref().unwrap_or("./keys");
    let key_dir = Path::new(key_path);

    // 1. Create the directory if it doesn't exist
    if !key_dir.exists() {
        warn!("Keys dir does not exist. Creating key directory: {}", key_dir.display());
        fs::create_dir_all(key_dir)?;
    }

    // 2. Full paths to key files
    let public_path = key_dir.join(config.key.public_key.as_ref().expect("Missing public_key"));
    let private_path = key_dir.join(config.key.private_key.as_ref().expect("Missing private_key"));
    generate_keys_if_missing(
        public_path.to_str().unwrap(),
        private_path.to_str().unwrap(),
    )?;


    if valid {
        Ok(config)
    } else {
        Err(format!("Invalid configuration in file: {}", file_path).into())
    }
}



impl Config {
    pub fn save_to(&self, path: &str) -> Result<(), Box<dyn Error>> {
        let toml_string = toml::to_string_pretty(self)?;
        fs::write(path, toml_string)?;
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


