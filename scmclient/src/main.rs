mod models;
mod agent;
mod config;
mod compliance;

use tokio::time::{sleep, Duration};
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt, reload};
use tracing::{debug, info, warn, error};

#[tokio::main]
async fn main() {
    
    // Create required directories BEFORE logger init
    create_required_directories();

    if let Err(e) = run().await {
        error!("Fatal Error: {}", e);
        std::process::exit(1);
    }
}

//----------------------------------------
//  create_required_directories
//---------------------------------------
fn create_required_directories() {
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
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("Could not create directory {}: {}", dir, e);
        }
    }
}



async fn run() -> Result<(), Box<dyn std::error::Error>> {

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


    // 3. Load config
    info!("Loading configuration...");
    let mut config = config::get_config().map_err(|e| {
        error!("Configuration error: {}", e);
        e
    })?;

    // 4. Handle URL override
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

    // 5. Startup info
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

    // 6. Main heartbeat loop
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
