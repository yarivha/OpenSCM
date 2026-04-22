use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn, error};
use cfg_if::cfg_if;

// load OS specific modules
cfg_if! {
    if #[cfg(not(target_os = "windows"))] {
        use std::path::Path;
        use toml;
    } else if #[cfg(target_os = "windows")] {
        use winreg::enums::*;
        use winreg::RegKey;
    }
}



// ============================================================
// CONSTANTS
// ============================================================

// --- Constants ---
cfg_if! {
    if #[cfg(target_os = "linux")] {
        const CONFIG_PATH: &str = "/etc/openscm/scmclient.config";
        const KEY_PATH: &str = "/etc/openscm/keys/scmclient";
    } else if #[cfg(target_os = "freebsd")] {
        const CONFIG_PATH: &str = "/usr/local/etc/openscm/scmclient.config";
        const KEY_PATH: &str = "/usr/local/etc/openscm/keys/scmclient";
    } else if #[cfg(target_os = "windows")] {
        const CONFIG_PATH: &str = r"C:\ProgramData\OpenSCM\Client\scmclient.config";
        const KEY_PATH: &str = r"C:\ProgramData\OpenSCM\Client\keys\scmclient";
    }
}

pub fn key_path() -> &'static str { KEY_PATH }
pub fn config_path() -> &'static str { CONFIG_PATH }

// ============================================================
// STRUCTS
// ============================================================

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct ServerConfig {
    pub url: String,
    pub tenant_id: String,
}

#[derive(Debug, Deserialize, Clone, Serialize, Default)]
pub struct ClientConfig {
    pub heartbeat: Option<String>,
    pub loglevel: Option<String>,
}


// ============================================================
// DEFAULT
// ============================================================

impl Default for Config {
    fn default() -> Self {

        Self {
            server: ServerConfig {
                url: "http://localhost:8000".to_string(),
                tenant_id: "default".to_string(),
            },
            client: ClientConfig {
                heartbeat: Some("300".to_string()),
                loglevel: Some("info".to_string()),
            },
        }
    }
}



// ============================================================
// CONFIG IMPLEMENTATION
// ============================================================


impl Config {
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        cfg_if! {
            if #[cfg(target_os = "windows")] {
                // --- Windows Registry Logic ---
                let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
                let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Client")?;

                key.set_value("ServerURL", &self.server.url)?;
                key.set_value("TenantId", &self.server.tenant_id)?;
                
                if let Some(hb) = &self.client.heartbeat { 
                    key.set_value("Heartbeat", hb)?; 
                }
                if let Some(ll) = &self.client.loglevel { 
                    key.set_value("LogLevel", ll)?; 
                }

                info!("Configuration saved to Windows Registry.");
                Ok(())
            } else {
                // --- Unix (FreeBSD/Linux) TOML Logic ---
                let path = PathBuf::from(CONFIG_PATH);
                let toml_string = toml::to_string_pretty(self)?;
                
                fs::write(&path, toml_string)?;
                
                info!("Configuration saved to {:?}.", path);
                Ok(())
            }
        }
    }
}


// ============================================================
// PUBLIC ENTRY POINT
// ============================================================

pub fn get_config() -> Result<Config, Box<dyn Error>> {
    cfg_if! {
        if #[cfg(target_os = "windows")] {
            // Windows logic: Just pull from the Registry
            load_from_registry()
        } else {
            // Unix logic: Handle the TOML file and bootstrapping
            let path = PathBuf::from(CONFIG_PATH);
            
            if !path.exists() {
                warn!(
                    "Config file not found at '{}'. Bootstrapping defaults.",
                    CONFIG_PATH
                );
                bootstrap_default_config(&path)?;
            }
            
            load_from_toml(&path)
        }
    }
}



// ============================================================
// PRIVATE HELPERS
// ============================================================

#[cfg(target_os = "windows")]
fn load_from_registry() -> Result<Config, Box<dyn Error>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Client")?;

    // Read a registry value, stripping null terminators and whitespace.
    // Returns the default string if the value is missing.
    let read_val = |name: &str, default: &str| -> String {
        key.get_value::<String, _>(name)
            .unwrap_or_else(|_| default.to_string())
            .trim_matches(char::from(0))
            .trim()
            .to_string()
    };

    let needs_repair = [
        key.get_value::<String, _>("ServerURL").is_err(),
        key.get_value::<String, _>("TenantId").is_err(),
        key.get_value::<String, _>("Heartbeat").is_err(),
        key.get_value::<String, _>("LogLevel").is_err(),
    ]
    .iter()
    .any(|&missing| missing);

    let url = read_val("ServerURL", "http://localhost:8000");

    if url.is_empty() {
        error!("Registry: ServerURL is empty. Please set a valid server URL.");
        return Err("ServerURL is required but empty in registry".into());
    }

    let config = Config {
        server: ServerConfig {
            url,
            tenant_id: read_val("TenantId", "default"),
        },
        client: ClientConfig {
            heartbeat: Some(read_val("Heartbeat", "300")),
            loglevel:  Some(read_val("LogLevel", "info")),
        },
    };

    if needs_repair {
        warn!("Registry settings incomplete. Performing self-repair...");
        config.save()?;
    }

    Ok(config)
}


#[cfg(not(target_os = "windows"))]
fn bootstrap_default_config(path: &Path) -> Result<(), Box<dyn Error>> {
    let default_config = Config::default();
    let toml_string = toml::to_string_pretty(&default_config)?;
    fs::write(path, &toml_string)?;
    info!("Default configuration written to '{}'.", path.display());
    info!("Please edit the configuration file and set your server URL before running.");
    Ok(())
}


#[cfg(not(target_os = "windows"))]
fn load_from_toml(path: &Path) -> Result<Config, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;

    if config.server.url.trim().is_empty() {
        error!("Configuration error: 'server.url' is empty in '{}'.", path.display());
        return Err("server.url is required but empty in config file".into());
    }

    if config.server.tenant_id.trim().is_empty() {
        error!("Configuration error: 'server.tenant_id' is empty in '{}'.", path.display());
        return Err("server.tenant_id is required but empty in config file".into());
    }

    Ok(config)
}
