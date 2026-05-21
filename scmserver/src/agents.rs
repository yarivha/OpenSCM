// =============================================================================
// agents.rs — client-agent binary distribution and auto-upgrade support
//
// Agent binaries are embedded into the server binary at compile time via
// include_dir! in lib.rs (under `static/agents/`). At runtime they are served
// by the regular `/static/<file>` route — no separate download handler is
// needed, and there is no on-disk agents directory to manage. The trade-off
// is a bigger server binary in exchange for a single-file deployment.
//
// startup_scan
//   Called once after DB migrations on server startup. Iterates the embedded
//   `static/agents/` directory, computes SHA256 over each binary's in-memory
//   bytes, and upserts agent_packages. The agent version is the server's own
//   CARGO_PKG_VERSION — embedded agents are always built alongside the server
//   in the same release, so the two are guaranteed to match. If the directory
//   is empty (e.g. a dev build with no bundled agents) the scan is skipped.
// =============================================================================

use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tracing::{error, info};

use crate::STATIC_FILES_DIR;


// ─────────────────────────────────────────────────────────────────────────────
// Helper: derive_platform
// Converts the raw arch + os strings from the agent heartbeat into a normalised
// "{arch}-{os_type}" string (e.g. "x86_64-linux", "aarch64-linux",
// "x86_64-windows") that matches the filenames in the agents directory and the
// keys in the agent_packages table.
// ─────────────────────────────────────────────────────────────────────────────
pub fn derive_platform(arch: &str, os: &str) -> String {
    // os_info reports macOS as "Mac OS 14.4.1" (with a space) — collapse all
    // whitespace before substring matching so "mac os" and "macos" both hit.
    let os_norm: String = os
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let os_type = if os_norm.contains("windows") {
        "windows"
    } else if os_norm.contains("darwin")
        || os_norm.contains("macos")
        || os_norm.contains("osx")
        || os_norm.contains("apple")
    {
        "macos"
    } else if os_norm.contains("freebsd") {
        "freebsd"
    } else {
        "linux"
    };
    format!("{}-{}", arch, os_type)
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: platform_from_filename
// Extracts the platform string from a filename such as:
//   scmclient-x86_64-linux         →  "x86_64-linux"
//   scmclient-aarch64-linux        →  "aarch64-linux"
//   scmclient-x86_64-windows.exe   →  "x86_64-windows"
// Returns None if the name does not match the expected pattern.
// ─────────────────────────────────────────────────────────────────────────────
fn platform_from_filename(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".exe").unwrap_or(name);
    let platform = stem.strip_prefix("scmclient-")?;
    if platform.is_empty() {
        return None;
    }
    Some(platform.to_string())
}


// ─────────────────────────────────────────────────────────────────────────────
// startup_scan
// Walks the embedded `static/agents/` directory and upserts agent_packages
// for every recognised client binary found there. The version string is read
// from a `VERSION` file bundled alongside the binaries by the CI workflow.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn startup_scan(pool: &SqlitePool) {
    let agents_dir = match STATIC_FILES_DIR.get_dir("agents") {
        Some(d) => d,
        None => {
            // Dev builds typically don't bundle client binaries; the directory
            // is absent or empty and the upgrade feature is simply unavailable.
            info!("No bundled agents directory — upgrade packages unavailable.");
            return;
        }
    };

    let version = env!("CARGO_PKG_VERSION");

    let mut count: u32 = 0;

    for file in agents_dir.files() {
        // file.path() returns "agents/scmclient-x86_64-linux" — we want the
        // bare filename.
        let name = match file.path().file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        let platform = match platform_from_filename(name) {
            Some(p) => p,
            None => continue, // VERSION file and anything else
        };

        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(file.contents());
            format!("{:x}", hasher.finalize())
        };

        // Relative URL — served by the catch-all route which forwards to
        // STATIC_FILES_DIR.get_file("agents/<name>"). The client prepends the
        // server base URL before fetching.
        let url = format!("/agents/{}", name);

        match sqlx::query(
            "INSERT INTO agent_packages (platform, version, sha256, url, updated_at)
             VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(platform) DO UPDATE SET
               version    = excluded.version,
               sha256     = excluded.sha256,
               url        = excluded.url,
               updated_at = excluded.updated_at",
        )
        .bind(&platform)
        .bind(&version)
        .bind(&sha256)
        .bind(&url)
        .execute(pool)
        .await
        {
            Ok(_) => {
                info!(
                    "Agent package registered: {} v{} sha256={}…",
                    platform,
                    version,
                    &sha256[..12]
                );
                count += 1;
            }
            Err(e) => error!("Failed to upsert agent_packages for {}: {}", platform, e),
        }
    }

    if count > 0 {
        info!(
            "Agent scan complete: {} platform(s) registered at v{}.",
            count, version
        );
    }
}
