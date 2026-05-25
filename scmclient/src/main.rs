mod models;
mod agent;
mod config;
mod compliance;
mod runner;

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

    // 2a. `run` subcommand — local policy evaluation, no server interaction.
    //     Handled before config load / heartbeat loop because the runner is
    //     a one-shot tool and shouldn't block on missing config or network.
    if args.len() > 1 && args[1] == "run" {
        let mut policy_path: Option<String> = None;
        let mut format = runner::OutputFormat::Text;
        let mut strict = false;
        let mut failed_only = false;
        let mut cmd_enabled_override: Option<bool> = None;
        let mut ps_enabled_override:  Option<bool> = None;

        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--policy" if i + 1 < args.len() => { policy_path = Some(args[i + 1].clone()); i += 2; }
                "--format" if i + 1 < args.len() => {
                    format = match args[i + 1].to_lowercase().as_str() {
                        "json" => runner::OutputFormat::Json,
                        "text" => runner::OutputFormat::Text,
                        other  => {
                            eprintln!("Error: unknown --format '{}'. Use 'text' or 'json'.", other);
                            std::process::exit(2);
                        }
                    };
                    i += 2;
                }
                "--strict"       => { strict = true; i += 1; }
                "--failed-only"  => { failed_only = true; i += 1; }
                "--cmd-enabled"  => { cmd_enabled_override = Some(true); i += 1; }
                "--ps-enabled"   => { ps_enabled_override  = Some(true); i += 1; }
                other => {
                    eprintln!("Error: unknown argument '{}' for 'run' subcommand.", other);
                    std::process::exit(2);
                }
            }
        }

        let policy_path = match policy_path {
            Some(p) => p,
            None => {
                eprintln!("Error: 'run' requires --policy <path>.");
                std::process::exit(2);
            }
        };

        // Default the gating flags to false in local mode unless explicitly
        // overridden — the user is running an arbitrary policy file so
        // arbitrary command execution should remain opt-in.
        let cmd_enabled = cmd_enabled_override.unwrap_or(false);
        let ps_enabled  = ps_enabled_override.unwrap_or(false);

        let exit_code = runner::run(runner::RunOptions {
            policy_path, format, strict, failed_only, cmd_enabled, ps_enabled,
        });
        std::process::exit(exit_code as i32);
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

    if config.client.cmd_enabled.unwrap_or(false) {
        warn!("CMD element is ENABLED — this client will execute commands received from the server. Ensure you trust the server completely.");
    }

    // Apply log level from config
    let _ = reload_handle.reload(EnvFilter::new(log_level));

    // Track last applied log level to avoid redundant reloads
    let mut last_log_level = log_level.to_string();

    // Build the HTTP client once and reuse it for every heartbeat. reqwest's
    // connection pool only kicks in when the same Client instance is reused,
    // so building per-cycle was throwing away pooled connections and TLS
    // sessions every interval.
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| {
            error!("Failed to build HTTP client: {}", e);
            e
        })?;

    // 7. Main heartbeat loop
    loop {
        debug!("Starting heartbeat cycle");

        match agent::send_system_info(&mut config, &http_client).await {
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
    scmclient [OPTIONS]                            # Run as a managed agent (default)
    scmclient run --policy <FILE> [RUN OPTIONS]    # Local policy evaluation (no server)

OPTIONS:
    -h, --help          Print this help message
    -ver, --version     Print version information
    --url <URL>         Set or override the Server URL (e.g., http://localhost:8000)

RUN OPTIONS (for `scmclient run`):
    --policy <FILE>     Path to an OpenSCM policy JSON file (required)
    --format text|json  Output format (default: text)
    --strict            Exit with code 1 if any test fails
    --failed-only       Text mode: print only failing tests
    --cmd-enabled       Allow CMD elements to execute (off by default in local mode)
    --ps-enabled        Allow PowerShell elements to execute (off by default in local mode)

EXAMPLES:
    scmclient --url https://demo.openscm.io:8000
    scmclient run --policy cis-debian-13.json
    scmclient run --policy cis-debian-13.json --format json --strict
    scmclient run --policy custom.json --failed-only --cmd-enabled

EXIT CODES (for `scmclient run`):
    0   Success (or non-strict mode with failures)
    1   Strict mode and one or more tests failed
    2   Invalid arguments or policy file
    "#);
}
