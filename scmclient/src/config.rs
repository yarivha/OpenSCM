use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn, error};
use toml;

// Windows-specific imports
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

// --- Struct Definitions ---

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

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct ClientConfig {
    pub id: Option<String>,
    pub heartbeat: Option<String>,
    pub loglevel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyPair {
    pub key_path: Option<String>,
    pub pub_key: Option<String>,
    pub priv_key: Option<String>,
    pub server_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        // Fallback directory logic for keys if not specified
        let base_dir = get_config_path()
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let keys_path = base_dir.join("keys");

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
                key_path: Some(keys_path.to_string_lossy().into_owned()),
                pub_key: Some("scmclient.pub".to_string()),
                priv_key: Some("scmclient.key".to_string()),
                server_key: Some("scmserver.pub".to_string()),
            },
        }
    }
}



impl Config {
    /// The "Smart Save": Persists changes to the Registry (Windows) or TOML (Unix)
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        #[cfg(target_os = "windows")]
        {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            // create_subkey opens the key for writing (creates it if missing)
            let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM")?;
            
            // Save each field if it exists
            if let Some(h) = &self.server.host { key.set_value("ServerName", h)?; }
            if let Some(p) = &self.server.port { key.set_value("ServerPort", p)?; }
            if let Some(i) = &self.client.id { key.set_value("ClientID", i)?; }
            if let Some(hb) = &self.client.heartbeat { key.set_value("Heartbeat", hb)?; }
            if let Some(ll) = &self.client.loglevel { key.set_value("LogLevel", ll)?; }
    
            // Key Locations
            if let Some(kp) = &self.key.key_path { key.set_value("KeyPath", kp)?; }
            if let Some(pk) = &self.key.pub_key { key.set_value("PubKeyFile", pk)?; }
            if let Some(sk) = &self.key.priv_key { key.set_value("PrivKeyFile", sk)?; }
            if let Some(svk) = &self.key.server_key { key.set_value("ServerKeyFile", svk)?; }

            info!("Configuration successfully saved to Windows Registry.");
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let path = get_config_path(); // Uses the private path helper in this file
            let toml_string = toml::to_string_pretty(self)?;
            fs::write(&path, toml_string)?;
            info!("Configuration successfully saved to {:?}", path);
            Ok(())
        }
    }
}


pub fn get_config() -> Result<Config, Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    {
        load_from_registry()
    }

    #[cfg(not(target_os = "windows"))]
    {
        let path = get_config_path();
        if !path.exists() {
            bootstrap_default_config(&path)?;
        }
        load_from_toml(&path)
    }
}

// --- Private Helpers ---

/// Determines the standard config path for the OS.
fn get_config_path() -> PathBuf {
    {
        PathBuf::from("/etc/openscm/scmclient.config")
    }
}


//  load_from_registry in windows
#[cfg(target_os = "windows")]
fn load_from_registry() -> Result<Config, Box<dyn Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    
    // create_subkey ensures the "OpenSCM" folder exists in the Registry
    let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM")?;

    let mut needs_repair = false;

    // A helper to pull a string or mark that the Registry needs a "save" to fill the gap
    let mut get_val = |name: &str, default: &str| {
        key.get_value(name).unwrap_or_else(|_| {
            needs_repair = true; 
            default.to_string()
        })
    };

    let mut config = Config {
        server: ServerConfig {
            host: Some(get_val("ServerName", "localhost")),
            port: Some(get_val("ServerPort", "8000")),
        },
        client: ClientConfig {
            id: Some(get_val("ClientID", "0")),
            heartbeat: Some(get_val("Heartbeat", "300")),
            loglevel: Some(get_val("LogLevel", "info")),
            ..ClientConfig::default()
        },
        key: KeyPair {
            // Path and dynamic filenames
            key_path: Some(get_val("KeyPath", r"C:\ProgramData\OpenSCM\keys")),
            pub_key: Some(get_val("PubKeyFile", "scmclient.pub")),
            priv_key: Some(get_val("PrivKeyFile", "scmclient.key")),
            server_key: Some(get_val("ServerKeyFile", "scmserver.pub")),
        },
        ..Config::default()
    };

    // If any of the above fallback defaults were used, we save the config 
    // immediately to ensure the Registry is fully populated.
    if needs_repair {
        warn!("Registry configuration was incomplete or corrupted. Performing self-repair...");
        config.save()?; 
    }

    // Now proceed to ensure the physical key files exist on the disk
    validate_and_setup_keys(&mut config)?;
    
    Ok(config)
}



#[cfg(not(target_os = "windows"))]
fn bootstrap_default_config(path: &Path) -> Result<(), Box<dyn Error>> {
    warn!("Config not found at {:?}. Generating default TOML.", path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let default_config = Config::default();
    let toml_string = toml::to_string_pretty(&default_config)?;
    fs::write(path, toml_string)?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn load_from_toml(path: &Path) -> Result<Config, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&content)?;
    validate_and_setup_keys(&mut config)?;
    Ok(config)
}

fn validate_and_setup_keys(config: &mut Config) -> Result<(), Box<dyn Error>> {
    let mut valid = true;

    // 1. Validate Numeric Fields
    if let Some(p) = &config.server.port {
        if p.parse::<u16>().is_err() {
            error!("Invalid port in config: {}", p);
            valid = false;
        }
    }

    if let Some(h) = &config.client.heartbeat {
        if h.parse::<u32>().is_err() {
            error!("Invalid heartbeat in config: {}", h);
            valid = false;
        }
    }

    // 2. Determine base directory for keys
    let base_dir = if cfg!(target_os = "windows") {
        // On Windows, store keys relative to the installation folder
        std::env::current_exe()?.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        // On Linux, store keys relative to the config file (/etc/openscm/keys)
        get_config_path().parent().unwrap_or(Path::new(".")).to_path_buf()
    };

    let key_dir = config.key.key_path.as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir.join("keys"));

    if !key_dir.exists() {
        info!("Creating keys directory at: {}", key_dir.display());
        fs::create_dir_all(&key_dir)?;
    }

    let pub_path = key_dir.join(config.key.pub_key.as_deref().unwrap_or("scmclient.pub"));
    let priv_path = key_dir.join(config.key.priv_key.as_deref().unwrap_or("scmclient.key"));

    generate_keys_if_missing(
        &pub_path.to_string_lossy(),
        &priv_path.to_string_lossy(),
    )?;

    if valid { Ok(()) } else { Err("Configuration validation failed".into()) }
}

pub fn generate_keys_if_missing(public_key_path: &str, private_key_path: &str) -> Result<(), Box<dyn Error>> {
    if Path::new(public_key_path).exists() && Path::new(private_key_path).exists() {
        return Ok(());
    }

    warn!("Key files missing. Generating new Ed25519 keypair...");
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = VerifyingKey::from(&signing_key);

    // Save keys as base64 strings
    fs::write(private_key_path, base64::encode(signing_key.to_bytes()))?;
    fs::write(public_key_path, base64::encode(verify_key.to_bytes()))?;

    info!("Keypair successfully generated and saved.");
    Ok(())
}

