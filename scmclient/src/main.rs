mod models;
mod agent;
mod config;
mod compliance;

use tokio::time::{sleep, Duration};
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt, reload};
use tracing::{debug, info, warn, error};


use crate::config::{config_path,key_path};


fn check_required_directories() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Gather targets from your single-source-of-truth helpers
    let targets = [
        config_path(),
        key_path(),
    ];

    for target in targets {
        if let Some(parent) = std::path::Path::new(target).parent() {
            // Check if directory exists
            if !parent.exists() {
                info!("Required directory {:?} is missing. Attempting to create...", parent);
                
                // 2. Attempt to create. If it fails (e.g., Permission Denied), trigger the error logic.
                if let Err(e) = std::fs::create_dir_all(parent) {
                    error!(
                        "CRITICAL FAILURE: Could not create directory {:?}. Error: {}. \
                        This usually means the service lacks sufficient privileges or the \
                        installation is corrupt. Please reinstall the package or check permissions.", 
                        parent, e
                    );
                    return Err(format!("Missing required directory and failed to create: {:?}", parent).into());
                }
                info!("Successfully created directory: {:?}", parent);
            }

            // 3. Set secure permissions (Unix-specific)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let is_key_dir = target == key_path();
                let mode = if is_key_dir { 0o700 } else { 0o755 };

                if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode)) {
                    error!(
                        "CRITICAL FAILURE: Could not set permissions ({:o}) on {:?}. Error: {}. \
                        Ensure the OpenSCM service has ownership of its data directories.", 
                        mode, parent, e
                    );
                    return Err(format!("Permission hardening failed for: {:?}", parent).into());
                }
            }
        }
    }

    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // 1. Logging setup
    let env_filter = EnvFilter::new("info");
    let (reload_layer, reload_handle) = reload::Layer::new(env_filter);

    tracing_subscriber::registry()
        .with(reload_layer)
        .with(fmt::layer())
        .init();

    // 2. Version and CLI args
    let version = env!("CARGO_PKG_VERSION");
    let args: Vec<String> = std::env::args().collect();

    for arg in &args {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "-ver" | "--version" => {
                println!("OpenSCM Client version: {}", version);
                return Ok(());
            }
            _ => {}
        }
    }

	
    // 3. create required directories BEFORE logger init
    check_required_directories()?;

    // 4. Load config
    info!("Loading configuration...");
    let mut config = config::get_config().map_err(|e| {
        error!("Configuration error: {}", e);
        e
    })?;

    // 5. Handle URL override
    let mut config_changed = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--url" && i + 1 < args.len() {
            let new_url = args[i + 1].clone();
            info!("CLI Override: Setting Server URL to '{}'", new_url);
            config.server.url = new_url;
            config_changed = true;
            i += 2; // skip the value too
        } else {
            i += 1;
        }
    }

    if config_changed {
        config.save().map_err(|e| {
            error!("Failed to persist config: {}", e);
            e
        })?;
        info!("New configuration persisted.");
    }

    // 6. Startup info
    let server_url  = &config.server.url;
    let log_level   = config.client.loglevel.as_deref().unwrap_or("info");
    let heartbeat_secs = config.client.heartbeat
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);

    info!("================ OpenSCM Agent Configuration ================");
    info!("Server URL     : {}", server_url);
    info!("Client Version : {}", version);
    info!("Heartbeat      : {} seconds", heartbeat_secs);
    info!("Log Level      : {}", log_level);
    info!("=============================================================");

    // Apply log level from config
    let _ = reload_handle.reload(EnvFilter::new(log_level));

    // Track last applied log level to avoid redundant reloads
    let mut last_log_level = log_level.to_string();

    // 7. Main heartbeat loop
    loop {
        debug!("Starting heartbeat cycle");

        match agent::send_system_info(&mut config).await {
            Ok(_)  => debug!("Heartbeat completed successfully"),
            Err(e) => warn!("Heartbeat failed: {}", e),
        }

        // Recalculate heartbeat interval in case config changed
        let current_heartbeat = config.client.heartbeat
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);

        // Only reload log level if it actually changed
        if let Some(level) = &config.client.loglevel {
            if *level != last_log_level {
                let _ = reload_handle.reload(EnvFilter::new(level));
                info!("Log level changed to '{}'", level);
                last_log_level = level.clone();
            }
        }

        // Apply jitter (0-9 seconds) to prevent thundering herd
        let jitter = rand::random::<u64>() % 10;
        let sleep_time = current_heartbeat + jitter;

        debug!("Next heartbeat in {} seconds", sleep_time);
        sleep(Duration::from_secs(sleep_time)).await;
    }
}

fn print_usage() {
    println!(r#"
OpenSCM Client - Security Compliance Manager Agent

USAGE:
    scmclient [OPTIONS]

OPTIONS:
    -h, --help          Print this help message
    -ver, --version     Print version information
    --url <URL>         Set or override the Server URL (e.g., http://localhost:8000)

EXAMPLE:
    scmclient --url https://demo.openscm.io:8000
    "#);
}
