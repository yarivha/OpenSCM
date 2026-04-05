mod models;
mod agent;
mod config;
mod compliance;

use tokio::time::{sleep, Duration};
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt, reload};
use tracing::{debug, info, warn, error};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // We call a separate run function so we can use '?' and Result
    if let Err(e) = run().await {
        eprintln!("Fatal Error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // 1. LOGGING SETUP (Initial)
    let env_filter = EnvFilter::new("info");
    let (reload_layer, reload_handle) = reload::Layer::new(env_filter);

    tracing_subscriber::registry()
        .with(reload_layer)
        .with(fmt::layer())
        .init();

    // 2. VERSION & CLI ARGS
    let version = env!("CARGO_PKG_VERSION");
    let args: Vec<String> = std::env::args().collect();

    // Handle early-exit flags
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

    // 3. LOAD CONFIG
    info!("Loading configuration...");
    let mut config = config::get_config().map_err(|e| {
        error!("Configuration error: {}", e);
        e
    })?;

    // 4. HANDLE URL OVERRIDE
    let mut config_changed = false;
    for i in 0..args.len() {
        if args[i] == "--url" && i + 1 < args.len() {
            let new_url = args[i + 1].clone();
            info!("CLI Override: Setting Server URL to {}", new_url);
            config.server.url = new_url;
            config_changed = true;
        }
    }

    if config_changed {
        config.save()?;
        info!("New configuration persisted to registry/file.");
    }

    // 5. STARTUP INFO
    let server_url = &config.server.url;
    let log_level = config.client.loglevel.as_deref().unwrap_or("info");
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

    // 6. MAIN HEARTBEAT LOOP
    loop {
        debug!("Starting heartbeat cycle");

        // Note: Passing &mut config so agent can update state (like IDs)
        match agent::send_system_info(&mut config).await {
            Ok(_) => debug!("Heartbeat completed successfully"),
            Err(e) => warn!("Heartbeat failed: {}", e),
        }

        // Re-calculate heartbeat and log level in case they changed during the cycle
        let current_heartbeat = config.client.heartbeat
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);

        if let Some(level) = &config.client.loglevel {
            let _ = reload_handle.reload(EnvFilter::new(level));
        }

        // Apply Jitter (0-9 seconds)
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
