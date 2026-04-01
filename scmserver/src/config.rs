// src/config.rs
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;
use std::error::Error;
use tracing::{info, warn, error};
use base64::{engine::general_purpose, Engine as _};
use toml;

use crate::get_config_path;

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
        
        let config_path = get_config_path();
        let base_dir = config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let keys_path = base_dir.join("keys").to_string_lossy().into_owned();
        let db_path = base_dir.join("scm.db").to_string_lossy().into_owned();

        Self {
            server: ServerConfig {
                port: Some("8000".to_string()),
                loglevel: Some("info".to_string()),
            },
            database: DatabaseConfig {
                path: db_path, // הנתיב יהיה מסונכרן למיקום הקונפיג
            },
            key: KeyPair {
                key_path: Some(keys_path), // הנתיב יהיה מסונכרן למיקום הקונפיג
                public_key: Some("scmserver.pub".to_string()),
                private_key: Some("scmserver.key".to_string()),
            },
        }
    }
}


pub fn load_and_validate_config(file_path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(file_path).map_err(|e| {
        format!("Could not read config file {:?}: {}", file_path, e)
    })?;

    let mut config: Config = toml::from_str(&contents).map_err(|e| {
        format!("Failed to parse TOML in {:?}: {}", file_path, e)
    })?;

    let mut valid = true;

    config.server.port = match &config.server.port {
        Some(p) => match p.parse::<u16>() {
            Ok(port) if (1..=65000).contains(&port) => Some(p.clone()),
            _ => {
                error!("Invalid port: {:?}. Must be 1–65000.", p);
                valid = false;
                Some("8000".to_string())
            }
        },
        None => Some("8000".to_string())
    };

    config.server.loglevel = match &config.server.loglevel {
        Some(level) => {
            let level = level.to_lowercase();
            let valid_levels = ["debug", "info", "warn", "error"];
            if valid_levels.contains(&level.as_str()) { Some(level) }
            else { Some("info".to_string()) }
        }
        None => Some("info".to_string())
    };

    let base_dir = file_path.parent().unwrap_or(Path::new("."));

    let key_dir = config.key.key_path.as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir.join("keys"));

    if !key_dir.exists() {
        warn!("Keys dir does not exist. Creating: {}", key_dir.display());
        fs::create_dir_all(&key_dir)?;
    }

    let public_path = key_dir.join(config.key.public_key.as_deref().unwrap_or("scmserver.pub"));
    let private_path = key_dir.join(config.key.private_key.as_deref().unwrap_or("scmserver.key"));

    generate_keys_if_missing(
        &public_path,
        &private_path,
    )?;

    if valid {
        Ok(config)
    } else {
        Err(format!("Invalid configuration in file: {:?}", file_path).into())
    }
}



impl Config {
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let toml_string = toml::to_string_pretty(self)?;
        std::fs::write(path.as_ref(), toml_string)?;
        Ok(())
    }
}


pub fn generate_keys_if_missing<P: AsRef<Path>>(public_key_path: P, private_key_path: P) -> Result<(), Box<dyn std::error::Error>> {
    let pub_path = public_key_path.as_ref();
    let priv_path = private_key_path.as_ref();

    // Check if keys exits
    if pub_path.exists() && priv_path.exists() {
        return Ok(());
    }

    warn!("Key files missing at {:?}. Generating new Ed25519 keypair.", priv_path.parent().unwrap_or(Path::new(".")));

    if let Some(parent) = priv_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Create Keys
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = VerifyingKey::from(&signing_key);

    let priv_bytes = signing_key.to_bytes();
    let priv_encoded = general_purpose::STANDARD.encode(priv_bytes);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).mode(0o600); 
        let mut priv_file = options.open(priv_path)?;
        priv_file.write_all(priv_encoded.as_bytes())?;
    }
    
    #[cfg(not(unix))]
    {
        let mut priv_file = fs::File::create(priv_path)?;
        priv_file.write_all(priv_encoded.as_bytes())?;
    }

    let pub_bytes = verify_key.to_bytes();
    let pub_encoded = general_purpose::STANDARD.encode(pub_bytes);
    let mut pub_file = fs::File::create(pub_path)?;
    pub_file.write_all(pub_encoded.as_bytes())?;

    info!("Successfully generated and saved new Ed25519 keypair to {:?}", priv_path.parent().unwrap());

    Ok(())
}



