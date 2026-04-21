use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn, error};

// Unix specific imports
#[cfg(not(target_os = "windows"))]
use toml;
#[cfg(not(target_os = "windows"))]
use std::path::Path;

// Windows-specific imports
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;


// ============================================================
// CONSTANTS
// ============================================================

#[cfg(target_os = "linux")]
const CONFIG_PATH: &str = "/etc/openscm/scmclient.config";

#[cfg(target_os = "freebsd")]
const CONFIG_PATH: &str = "/usr/local/etc/openscm/scmclient.config";


// ============================================================
// STRUCTS
// ============================================================

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub key: KeyPair,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyPair {
    pub key_path: Option<String>,
}


// ============================================================
// DEFAULT
// ============================================================

impl Default for Config {
    fn default() -> Self {
        #[cfg(target_os = "windows")]
        let base_dir = PathBuf::from(r"C:\ProgramData\OpenSCM\Client");

        #[cfg(target_os = "freebsd")]
        let base_dir = PathBuf::from("/usr/local/etc/openscm");

        #[cfg(target_os = "linux")]
        let base_dir = PathBuf::from("/etc/openscm");

        Self {
            server: ServerConfig {
                url: "http://localhost:8000".to_string(),
                tenant_id: "default".to_string(),
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


// ============================================================
// DIRECTORY SETUP
// ============================================================

fn create_required_directories(config: &Config) {
    #[cfg(target_os = "windows")]
    let dirs: Vec<&str> = vec![
        r"C:\ProgramData\OpenSCM\Client\keys",
        r"C:\ProgramData\OpenSCM\Client\logs",
    ];

    #[cfg(target_os = "freebsd")]
    let dirs: Vec<&str> = vec![
        "/usr/local/etc/openscm/keys",
        "/var/log/openscm",
    ];

    #[cfg(target_os = "linux")]
    let dirs: Vec<&str> = vec![
        "/etc/openscm/keys",
        "/var/log/openscm",
    ];

    for dir in dirs {
        if let Err(e) = fs::create_dir_all(dir) {
            warn!("Could not create directory {}: {}", dir, e);
        }
    }

    // Also create key directory from config path
    if let Some(key_path) = &config.key.key_path {
        if let Err(e) = fs::create_dir_all(key_path) {
            warn!("Could not create key directory {}: {}", key_path, e);
        }
    }
}


// ============================================================
// CONFIG IMPLEMENTATION
// ============================================================

impl Config {
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        #[cfg(target_os = "windows")]
        {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Client")?;

            key.set_value("ServerURL", &self.server.url)?;
            key.set_value("TenantId", &self.server.tenant_id)?;
            if let Some(hb) = &self.client.heartbeat { key.set_value("Heartbeat", hb)?; }
            if let Some(ll) = &self.client.loglevel  { key.set_value("LogLevel", ll)?; }
            if let Some(kp) = &self.key.key_path     { key.set_value("KeyPath", kp)?; }

            info!("Configuration saved to Windows Registry.");
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let path = PathBuf::from(CONFIG_PATH);
            let toml_string = toml::to_string_pretty(self)?;
            fs::write(&path, toml_string)?;
            info!("Configuration saved to {:?}.", path);
            Ok(())
        }
    }
}


// ============================================================
// PUBLIC ENTRY POINT
// ============================================================

pub fn get_config() -> Result<Config, Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    {
        load_from_registry()
    }

    #[cfg(not(target_os = "windows"))]
    {
        let path = PathBuf::from(CONFIG_PATH);
        if !path.exists() {
            warn!(
                "Config file not found at '{}'. Bootstrapping defaults.",
                CONFIG_PATH
            );
            let default_config = Config::default();
            create_required_directories(&default_config);
            bootstrap_default_config(&path)?;
            return load_from_toml(&path);
        }
        load_from_toml(&path)
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
        key.get_value::<String, _>("KeyPath").is_err(),
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
        key: KeyPair {
            key_path: Some(read_val("KeyPath", r"C:\ProgramData\OpenSCM\Client\keys")),
        },
    };

    if needs_repair {
        warn!("Registry settings incomplete. Performing self-repair...");
        config.save()?;
    }

    create_required_directories(&config);
    Ok(config)
}


#[cfg(not(target_os = "windows"))]
fn bootstrap_default_config(path: &Path) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
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

    create_required_directories(&config);
    Ok(config)
}
