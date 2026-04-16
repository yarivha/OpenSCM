use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn, error};
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
    pub url: String, // Mandatory: Agent can't run without it
    pub tenant_id: Option<String>
}

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct ClientConfig {
    // ID is REMOVED. It is now handled as state in agent.rs
    pub heartbeat: Option<String>,
    pub loglevel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyPair {
    pub key_path: Option<String>, // The directory where hashed keys/IDs are kept
}

impl Default for Config {
    fn default() -> Self {
        let base_dir = if cfg!(target_os = "windows") {
            PathBuf::from(r"C:\ProgramData\OpenSCM\Client")
        } else {
            PathBuf::from("/etc/openscm")
        };

        Self {
            server: ServerConfig {
                url: "http://localhost:8000".to_string(),
                tenant_id: Some("default".to_string()),
            },
            client: ClientConfig {
                heartbeat: Some("300".to_string()),
                loglevel: Some("info".to_string()),
            },
            key: KeyPair {
                key_path: Some(base_dir.join("keys").to_string_lossy().into_owned()),
            },
        }
    }
}

impl Config {
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        #[cfg(target_os = "windows")]
        {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Client")?;
            
            // Note: We no longer save ClientID here.
            key.set_value("ServerURL", &self.server.url)?;
            if let Some(ti) = &self.server.tenant_id { key.set_value("Tenant_id", ti)?; }
            if let Some(hb) = &self.client.heartbeat { key.set_value("Heartbeat", hb)?; }
            if let Some(ll) = &self.client.loglevel { key.set_value("LogLevel", ll)?; }
            if let Some(kp) = &self.key.key_path { key.set_value("KeyPath", kp)?; }

            info!("Configuration saved to Windows Registry.");
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let path = get_config_path();
            let toml_string = toml::to_string_pretty(self)?;
            fs::write(&path, toml_string)?;
            info!("Configuration saved to {:?}", path);
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

fn get_config_path() -> PathBuf {
    PathBuf::from("/etc/openscm/scmclient.config")
}

#[cfg(target_os = "windows")]
fn load_from_registry() -> Result<Config, Box<dyn Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Client")?;

    let mut needs_repair = false;
    let mut get_val = |name: &str, default: &str| {
        key.get_value(name).unwrap_or_else(|_| {
            needs_repair = true; 
            default.to_string()
        })
    };

    let raw_tenant = get_val("Tenant_id", "default");
    let tenant_id = if raw_tenant == "default" || raw_tenant.is_empty() {
        None 
    } else {
        Some(raw_tenant)
    };

    let config = Config {
        server: ServerConfig {
            url: get_val("ServerURL", "http://localhost:8000"),
            tenant_id,
        },
        client: ClientConfig {
            heartbeat: Some(get_val("Heartbeat", "300")),
            loglevel: Some(get_val("LogLevel", "info")),
        },
        key: KeyPair {
            key_path: Some(get_val("KeyPath", r"C:\ProgramData\OpenSCM\Client\keys")),
        },
    };

    if needs_repair {
        warn!("Registry incomplete. Repairing...");
        config.save()?; 
    }

    // Ensure directory exists
    if let Some(path) = &config.key.key_path {
        fs::create_dir_all(path)?;
    }

    Ok(config)
}

#[cfg(not(target_os = "windows"))]
fn bootstrap_default_config(path: &Path) -> Result<(), Box<dyn Error>> {
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
    let config: Config = toml::from_str(&content)?;
    
    // Ensure key directory exists
    if let Some(key_path) = &config.key.key_path {
        fs::create_dir_all(key_path)?;
    }
    
    Ok(config)
}
