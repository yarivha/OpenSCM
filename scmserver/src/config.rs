use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::error::Error;
use tracing::{info, warn, error};
use base64::{engine::general_purpose, Engine as _};


// Unix specific imports
#[cfg(not(target_os = "windows"))]
use std::io::Write;
#[cfg(not(target_os = "windows"))]
use toml;

// Windows-specific imports
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

// --- Constants ---
#[cfg(not(windows))]
const CONFIG_PATH: &str = "/etc/openscm/scmserver.config";

// --- Structs ---

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

// --- Default ---


impl Default for Config {
    fn default() -> Self {
        #[cfg(windows)]
        let base_config = PathBuf::from(r"C:\ProgramData\OpenSCM\Server");
        #[cfg(windows)]
        let base_data = PathBuf::from(r"C:\ProgramData\OpenSCM\Server");

        #[cfg(not(windows))]
        let base_config = PathBuf::from("/etc/openscm");
        #[cfg(not(windows))]
        let base_data = PathBuf::from("/var/lib/openscm");

        Self {
            server: ServerConfig {
                port: Some("8000".to_string()),
                loglevel: Some("info".to_string()),
            },
            database: DatabaseConfig {
                path: base_data.join("scm.db").to_string_lossy().into_owned(),
            },
            key: KeyPair {
                key_path: Some(base_config.join("keys").to_string_lossy().into_owned()),
                public_key: Some("scmserver.pub".to_string()),
                private_key: Some("scmserver.key".to_string()),
            },
        }
    }
}


// --- Key Generation ---

pub fn generate_keys_if_missing<P: AsRef<Path>>(
    public_key_path: P,
    private_key_path: P,
) -> Result<(), Box<dyn Error>> {
    let pub_path = public_key_path.as_ref();
    let priv_path = private_key_path.as_ref();

    if pub_path.exists() && priv_path.exists() {
        return Ok(());
    }

    if pub_path.exists() ^ priv_path.exists() {
        warn!(
            "Partial key pair detected! Only one key file exists. Regenerating both... pub={} priv={}",
            pub_path.exists(),
            priv_path.exists()
        );
    } else {
        warn!(
            "Server keys missing. Generating new Ed25519 pair at {:?}",
            priv_path.parent().unwrap_or(priv_path)
        );
    }

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = VerifyingKey::from(&signing_key);

    let priv_encoded = general_purpose::STANDARD.encode(signing_key.to_bytes());
    let pub_encoded = general_purpose::STANDARD.encode(verify_key.to_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true).mode(0o600);
        let mut priv_file = options.open(priv_path)?;
        priv_file.write_all(priv_encoded.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        fs::write(priv_path, &priv_encoded)?;
    }

    fs::write(pub_path, pub_encoded)?;
    info!("Server keys generated successfully.");
    Ok(())
}

// --- Validation ---

fn validate_and_setup_keys(config: &mut Config) -> Result<(), Box<dyn Error>> {
    // 1. Port Validation — hard error on invalid port
    if let Some(p) = &config.server.port {
        if p.parse::<u16>().is_err() {
            error!("Invalid port in config: '{}'. Please set a valid port (1-65535).", p);
            return Err(format!(
                "Invalid port in config: '{}'. Please set a valid port (1-65535).", p
            ).into());
        }
    }

    // 2. Setup Key Directory
    let key_dir = config.key.key_path.as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            #[cfg(windows)] { PathBuf::from(r"C:\ProgramData\OpenSCM\Server\keys") }
            #[cfg(not(windows))] { PathBuf::from("/etc/openscm/keys") }
        });

    if !key_dir.exists() {
        info!("Creating keys directory: {}", key_dir.display());
        fs::create_dir_all(&key_dir)?;
    }

    let pub_filename = config.key.public_key.as_deref().unwrap_or("scmserver.pub");
    let priv_filename = config.key.private_key.as_deref().unwrap_or("scmserver.key");

    generate_keys_if_missing(key_dir.join(pub_filename), key_dir.join(priv_filename))?;
    Ok(())
}

// --- Config Implementation ---

impl Config {
    /// The entry point for main.rs. It automatically finds the config.
    pub fn load() -> Result<Self, Box<dyn Error>> {
        #[cfg(target_os = "windows")]
        {
            info!("Loading configuration from Windows Registry...");
            Self::load_from_registry()
        }

        #[cfg(not(target_os = "windows"))]
        {
            let path = PathBuf::from(CONFIG_PATH);
            info!("Loading configuration from {:?}...", path);
            if !path.exists() {
                warn!("Config file not found. Bootstrapping defaults at {:?}", path);
                let mut default_cfg = Self::default();
                validate_and_setup_keys(&mut default_cfg)?;
                default_cfg.save()?;
                return Ok(default_cfg);
            }
            Self::load_from_toml(&path)
        }
    }

    #[cfg(target_os = "windows")]
    fn load_from_registry() -> Result<Self, Box<dyn Error>> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Server")?;

        // Read each value explicitly with defaults
        let port     = key.get_value("Port").unwrap_or_else(|_| "8000".to_string());
        let loglevel = key.get_value("LogLevel").unwrap_or_else(|_| "info".to_string());
        let db       = key.get_value("DB").unwrap_or_else(|_| r"C:\ProgramData\OpenSCM\Server\scm.db".to_string());
        let key_path = key.get_value("KeyPath").unwrap_or_else(|_| r"C:\ProgramData\OpenSCM\Server\keys".to_string());
        let pub_key  = key.get_value("PubKeyFile").unwrap_or_else(|_| "scmserver.pub".to_string());
        let priv_key = key.get_value("PrivKeyFile").unwrap_or_else(|_| "scmserver.key".to_string());

        // Check if any registry values were missing
        let needs_repair = [
            key.get_value::<String, _>("Port").is_err(),
            key.get_value::<String, _>("LogLevel").is_err(),
            key.get_value::<String, _>("DB").is_err(),
            key.get_value::<String, _>("KeyPath").is_err(),
            key.get_value::<String, _>("PubKeyFile").is_err(),
            key.get_value::<String, _>("PrivKeyFile").is_err(),
        ].iter().any(|&missing| missing);

        let mut config = Config {
            server: ServerConfig {
                port: Some(port),
                loglevel: Some(loglevel),
            },
            database: DatabaseConfig {
                path: db,
            },
            key: KeyPair {
                key_path: Some(key_path),
                public_key: Some(pub_key),
                private_key: Some(priv_key),
            },
        };

        if needs_repair {
            warn!("Registry settings were missing. Performing self-repair...");
            config.save()?;
        }

        validate_and_setup_keys(&mut config)?;
        Ok(config)
    }

    /// Persists current settings to the correct OS location
    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        #[cfg(target_os = "windows")]
        {
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let (key, _) = hklm.create_subkey("SOFTWARE\\OpenSCM\\Server")?;

            if let Some(p)  = &self.server.port      { key.set_value("Port", p)?; }
            if let Some(l)  = &self.server.loglevel   { key.set_value("LogLevel", l)?; }
            key.set_value("DB", &self.database.path)?;
            if let Some(kp) = &self.key.key_path      { key.set_value("KeyPath", kp)?; }
            if let Some(pk) = &self.key.public_key    { key.set_value("PubKeyFile", pk)?; }
            if let Some(sk) = &self.key.private_key   { key.set_value("PrivKeyFile", sk)?; }
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let path = PathBuf::from(CONFIG_PATH);
            self.save_to(path)
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn Error>> {
        let toml_string = toml::to_string_pretty(self)?;
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, toml_string)?;
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn load_from_toml(path: &Path) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&contents)?;
        validate_and_setup_keys(&mut config)?;
        Ok(config)
    }
}
