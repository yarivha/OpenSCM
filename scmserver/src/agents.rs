// =============================================================================
// agents.rs — client-agent binary distribution and auto-upgrade support
//
// startup_scan
//   Called once after DB migrations on server startup.  Scans the agents
//   directory for files matching `scmclient-{platform}[.exe]`, reads the
//   version from a `VERSION` sentinel file in the same directory, computes
//   SHA256 for each binary, and upserts agent_packages.  If the directory
//   or VERSION file is absent the scan is skipped silently — deployments
//   that don't ship agents simply have no upgrade packages available.
//
// serve_agent
//   Public HTTP handler — GET /agents/:filename streams the binary from the
//   agents directory without authentication.  Path traversal is prevented by
//   stripping all directory components before resolving the file path.  The
//   downloading client verifies the SHA256 independently.
// =============================================================================

use axum::{
    body::Body,
    extract::Path,
    http::{header, StatusCode},
    response::IntoResponse,
};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::path::Path as FsPath;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use tracing::{error, info, warn};

use crate::config::agents_path;


// ─────────────────────────────────────────────────────────────────────────────
// Helper: sha256_file
// Reads a file in 64 KiB chunks and returns its lowercase hex SHA256 digest.
// ─────────────────────────────────────────────────────────────────────────────
async fn sha256_file(path: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
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
// Scans the agents directory and upserts agent_packages for every recognised
// client binary found there.  The version string is read from a `VERSION`
// file that the CI build writes alongside the binaries.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn startup_scan(pool: &SqlitePool) {
    let dir = agents_path();

    // Read version from the VERSION sentinel written by the build script.
    let version_path = format!("{}/VERSION", dir);
    let version = match tokio::fs::read_to_string(&version_path).await {
        Ok(v) => v.trim().to_string(),
        Err(e) => {
            // Not an error — installations that don't ship client binaries
            // simply don't have an agents directory.
            info!(
                "No agents/VERSION file at '{}': {} — upgrade packages unavailable.",
                version_path, e
            );
            return;
        }
    };

    if version.is_empty() {
        warn!("agents/VERSION is empty — skipping agent scan.");
        return;
    }

    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(e) => {
            warn!(
                "Cannot read agents directory '{}': {} — upgrade packages unavailable.",
                dir, e
            );
            return;
        }
    };

    let mut count: u32 = 0;

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();

        let platform = match platform_from_filename(&name) {
            Some(p) => p,
            None => continue, // VERSION file and other non-binary files
        };

        let file_path = format!("{}/{}", dir, name);

        let sha256 = match sha256_file(&file_path).await {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to compute SHA256 for '{}': {}", file_path, e);
                continue;
            }
        };

        // URL is intentionally relative so it works behind any reverse proxy.
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


// ─────────────────────────────────────────────────────────────────────────────
// GET /agents/:filename  [public — no session auth required]
// Streams a client binary from the agents directory.  Only files whose names
// start with `scmclient-` are served; everything else returns 404.  Directory
// traversal is blocked by using only the bare filename component.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn serve_agent(Path(filename): Path<String>) -> impl IntoResponse {
    // Strip any directory components — no path traversal.
    let bare_name = FsPath::new(&filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if bare_name.is_empty() || !bare_name.starts_with("scmclient-") {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let file_path = format!("{}/{}", agents_path(), bare_name);

    match File::open(&file_path).await {
        Ok(file) => {
            let stream = ReaderStream::new(file);
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream"),
                    (
                        header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"{}\"", bare_name) as &str,
                    ),
                ],
                Body::from_stream(stream),
            )
                .into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Agent binary not found").into_response(),
    }
}
