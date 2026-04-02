mod models;
mod agent;
mod config;
mod compliance;

use tokio::time::{sleep, Duration};
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt, reload};
use tracing::{debug, info, warn, error};
use std::path::{Path, PathBuf};



#[tokio::main]
async fn main() {
    // === Logging setup ===
    let env_filter = EnvFilter::new("info");
    let (reload_layer, reload_handle) = reload::Layer::new(env_filter);

    tracing_subscriber::registry()
        .with(reload_layer)
        .with(fmt::layer())
        .init();

    info!("Starting SCM Agent...");
    info!("Loading config file");
    // === Load config ===
    let mut config = match config::get_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };


    // === Print startup configuration ===
    let server_host = config.server.host.as_deref().unwrap_or("localhost");
    let server_port = config.server.port.as_deref().unwrap_or("8000");
    let client_id = config.client.id.as_deref().unwrap_or("0");
    let heartbeat = config.client.heartbeat
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    let log_level = config.client.loglevel.as_deref().unwrap_or("info");

    info!("================ SCM Agent Configuration ================");
    info!("Server URL     : http://{}:{}", server_host, server_port);
    info!("Client Version : {}", env!("CARGO_PKG_VERSION"));
    info!("Client ID      : {}", client_id);
    info!("Heartbeat      : {} seconds", heartbeat);
    info!("Log Level      : {}", log_level);
    info!("=========================================================");

    if client_id == "0" {
        warn!("Client is not registered yet (ID=0)");
    }

    // === Apply log level from config ===
    if let Err(e) = reload_handle.reload(EnvFilter::new(log_level)) {
        error!("Failed to update log level: {}", e);
    } else {
        info!("Log level set to '{}'", log_level);
    }

    // === Main loop ===
    loop {
        debug!("Starting heartbeat cycle");

        match agent::send_system_info(&mut config).await {
            Ok(_) => debug!("Heartbeat completed successfully"),
            Err(e) => warn!("Heartbeat failed: {}", e),
        }

        // Optional jitter (avoid all agents hitting server together)
        let jitter = rand::random::<u64>() % 10;
        let sleep_time = heartbeat + jitter;

        debug!("Sleeping for {} seconds (including jitter)", sleep_time);
        sleep(Duration::from_secs(sleep_time)).await;
    }
}
