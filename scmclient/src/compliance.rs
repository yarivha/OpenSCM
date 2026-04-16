use tracing::error;
use std::path::Path;
use std::fs;
use semver::Version;
use std::process::Command;
use std::net::{TcpStream, ToSocketAddrs};



fn parse_to_semver(v: &str) -> Option<Version> {
    let parts: Vec<_> = v.split('.').collect();
    let normalized = match parts.len() {
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => v.to_string(),
    };
    Version::parse(&normalized).ok()
}

#[cfg(unix)]
fn get_user_name_from_uid(uid: u32) -> Option<String> {
    let output = Command::new("id").args(["-un", &uid.to_string()]).output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else { None }
}

#[cfg(unix)]
fn check_user_exists(user: &str) -> bool {
    Command::new("id").arg(user).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(windows)]
fn check_user_exists(user: &str) -> bool {
    Command::new("net").args(["user", user]).stdout(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(unix)]
fn check_group_exists(group: &str) -> bool {
    Command::new("getent").args(["group", group]).status().map(|s| s.success()).unwrap_or(false)
}

#[cfg(windows)]
fn check_group_exists(group: &str) -> bool {
    Command::new("net").args(["localgroup", group]).status().map(|s| s.success()).unwrap_or(false)
}

fn check_port_open(port: &str) -> bool {
    let addr = format!("127.0.0.1:{}", port);
    TcpStream::connect_timeout(&addr.parse().unwrap(), std::time::Duration::from_millis(500)).is_ok()
}

#[cfg(unix)]
fn check_package_exists(package: &str) -> bool {
    // Check for Debian/Ubuntu or RHEL/CentOS
    let dpkg = Command::new("dpkg").args(["-s", package]).status().map(|s| s.success()).unwrap_or(false);
    let rpm = Command::new("rpm").args(["-q", package]).status().map(|s| s.success()).unwrap_or(false);
    dpkg || rpm
}

#[cfg(windows)]
fn check_package_exists(package: &str) -> bool {
    let output = Command::new("powershell").args(["-Command", &format!("Get-Package -Name {}", package)]).output().ok();
    output.map(|o| o.status.success()).unwrap_or(false)
}


fn calculate_sha1(path: &str) -> Result<String, std::io::Error> {
    use sha1::{Sha1, Digest};
    use std::fs::File;
    use std::io::{Read};

    let mut file = File::open(path)?;
    let mut hasher = Sha1::new();
    let mut buffer = [0; 4096]; // 4KB buffer for efficiency

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }

    // Convert the hash result to a hex string
    Ok(format!("{:x}", hasher.finalize()))
}



fn calculate_sha2(path: &str) -> Result<String, std::io::Error> {
    use sha2::{Sha256, Digest};
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 4096];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}


pub fn evaluate(
    element: &str,
    input: &str,
    selement: &str,
    condition: &str,
    sinput: &str,
) -> bool {
    let element_l = element.trim().to_lowercase();
    let selement_l = selement.trim().to_lowercase();
    let condition_l = condition.trim().to_lowercase();
    let sinput_trim = sinput.trim();

    match element_l.as_str() {
        // =========================================================
        // AGENT: Checks the local OpenSCM binary state
        // =========================================================
        "agent" => match selement_l.as_str() {
            "version" => {
                let actual_v = parse_to_semver(env!("CARGO_PKG_VERSION"));
                let target_v = parse_to_semver(sinput_trim);
                if let (Some(a), Some(t)) = (actual_v, target_v) {
                    match condition_l.as_str() {
                        "equal" | "equals" | "==" => a == t,
                        "not equal" | "!=" => a != t,
                        "more than" | ">" => a > t,
                        "less than" | "<" => a < t,
                        _ => false,
                    }
                } else { false }
            },
            "content" => match condition_l.as_str() {
                "equals" => env!("CARGO_PKG_VERSION") == sinput_trim,
                "contains" => env!("CARGO_PKG_VERSION").contains(sinput_trim),
                _ => false,
            },
            _ => false,
        },

        // =========================================================
        // ARCHITECTURE: x86_64, aarch64, etc.
        // =========================================================
        "architecture" => match selement_l.as_str() {
            "content" => {
                let actual = std::env::consts::ARCH;
                match condition_l.as_str() {
                    "contains" => actual.contains(sinput_trim),
                    "not contains" => !actual.contains(sinput_trim),
                    "equals" => actual == sinput_trim,
                    _ => false,
                }
            },
            _ => false,
        },

        // =========================================================
        // DIRECTORY: Path existence and metadata
        // =========================================================
        "directory" => match selement_l.as_str() {
            "exists" => Path::new(input).is_dir(),
            "not exists" => !Path::new(input).is_dir(),
            "content" => {
                // Checks if a specific filename (sinput) exists inside the directory (input)
                fs::read_dir(input).map(|entries| {
                    entries.filter_map(|e| e.ok()).any(|e| e.file_name() == sinput_trim)
                }).unwrap_or(false)
            },
            "owner" => {
                #[cfg(unix)] {
                    let metadata = fs::metadata(input).ok();
                    let uid = metadata.map(|m| std::os::unix::fs::MetadataExt::uid(&m));
                    if let Some(u) = uid {
                        let name = get_user_name_from_uid(u).unwrap_or_default();
                        name == sinput_trim || u.to_string() == sinput_trim
                    } else { false }
                }
                #[cfg(windows)] { false }
            },
            "permission" | "permissions" => {
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(input).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
                    let expected = u32::from_str_radix(sinput_trim, 8).unwrap_or(0);
                    match condition_l.as_str() {
                        "equal" | "equals" => mode == expected,
                        "more than" => mode >= expected,
                        "less than" => mode <= expected,
                        _ => false,
                    }
                }
                #[cfg(windows)] { false }
            },
            _ => false,
        },

        // =========================================================
        // DOMAIN: Local domain/workgroup info
        // =========================================================
        "domain" => match selement_l.as_str() {
            "content" => {
                // Placeholder: In a real agent, you'd pull this from sysinfo or netapi32
                let actual = "local"; 
                actual.contains(sinput_trim)
            },
            _ => false,
        },

        // =========================================================
        // FILE: The heavy lifter for security configuration
        // =========================================================
        "file" => match selement_l.as_str() {
            "exists" => Path::new(input).is_file(),
            "not exists" => !Path::new(input).is_file(),
            "content" => {
                fs::read_to_string(input).map(|c| {
                    match condition_l.as_str() {
                        "contains" => c.contains(sinput_trim),
                        "not contains" => !c.contains(sinput_trim),
                        "equals" => c.trim() == sinput_trim,
                        _ => false,
                    }
                }).unwrap_or(false)
            },
            "owner" => {
                #[cfg(unix)] {
                    let uid = fs::metadata(input).map(|m| std::os::unix::fs::MetadataExt::uid(&m)).ok();
                    if let Some(u) = uid {
                        get_user_name_from_uid(u).map(|n| n == sinput_trim).unwrap_or(u.to_string() == sinput_trim)
                    } else { false }
                }
                #[cfg(windows)] { false }
            },
            "permission" | "permissions" => {
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(input).map(|m| m.permissions().mode() & 0o777).unwrap_or(0);
                    let expected = u32::from_str_radix(sinput_trim, 8).unwrap_or(0);
                    match condition_l.as_str() {
                        "equal" | "equals" => mode == expected,
                        "more than" => mode >= expected,
                        "less than" => mode <= expected,
                        _ => false,
                    }
                }
                #[cfg(windows)] { false }
            },
            "sha1" => calculate_sha1(input).map(|h| h.to_lowercase() == sinput_trim.to_lowercase()).unwrap_or(false),
            "sha2" => calculate_sha2(input).map(|h| h.to_lowercase() == sinput_trim.to_lowercase()).unwrap_or(false),
            _ => false,
        },

        // =========================================================
        // GROUP: Local system groups
        // =========================================================
        "group" => match selement_l.as_str() {
            "exists" => check_group_exists(input),
            "not exists" => !check_group_exists(input),
            "content" => {
                // Logic to check if sinput (user) is a member of input (group)
                // This usually requires shell command 'id -Gn <user>' or similar
                false 
            },
            _ => false,
        },

        // =========================================================
        // HOSTNAME & IP
        // =========================================================
        "hostname" => match selement_l.as_str() {
            "content" => gethostname::gethostname().to_string_lossy().contains(sinput_trim),
            _ => false,
        },
        "ip" => match selement_l.as_str() {
            "exists" => local_ip_address::list_afinet_netifas().unwrap_or_default().iter().any(|(_, ip)| ip.to_string() == input),
            "content" => local_ip_address::list_afinet_netifas().unwrap_or_default().iter().any(|(_, ip)| ip.to_string().contains(sinput_trim)),
            _ => false,
        },

        // =========================================================
        // OS: Operating System details
        // =========================================================
        "os" => match selement_l.as_str() {
            "content" => os_info::get().os_type().to_string().to_lowercase().contains(sinput_trim),
            "version" => {
                let actual = parse_to_semver(&os_info::get().version().to_string());
                let target = parse_to_semver(sinput_trim);
                if let (Some(a), Some(t)) = (actual, target) {
                    match condition_l.as_str() {
                        "equal" | "equals" => a == t,
                        "more than" => a > t,
                        "less than" => a < t,
                        _ => false,
                    }
                } else { false }
            },
            _ => false,
        },

        // =========================================================
        // PACKAGE: Native package managers
        // =========================================================
        "package" => match selement_l.as_str() {
            "exists" => check_package_exists(input),
            "not exists" => !check_package_exists(input),
            "version" => {
                // Requires executing 'dpkg -s' or 'rpm -q' and parsing the version string
                false
            },
            _ => false,
        },

        // =========================================================
        // PORT & PROCESS
        // =========================================================
        "port" => match selement_l.as_str() {
            "exists" => check_port_open(input),
            "not exists" => !check_port_open(input),
            _ => false,
        },
        "process" => match selement_l.as_str() {
            "exists" => {
                // Typically uses the 'sysinfo' crate to iterate processes
                false 
            },
            "not exists" => true,
            _ => false,
        },

        // =========================================================
        // REGISTRY (Windows Only)
        // =========================================================
        "registry" => match selement_l.as_str() {
            "exists" => {
                #[cfg(windows)] {
                    let cmd = format!("Test-Path 'HKLM:\\{}'", input);
                    Command::new("powershell").args(["-Command", &cmd]).status().map(|s| s.success()).unwrap_or(false)
                }
                #[cfg(unix)] { false }
            },
            "content" => false, // Requires 'Get-ItemProperty' logic
            _ => false,
        },

        // =========================================================
        // USER
        // =========================================================
        "user" => match selement_l.as_str() {
            "exists" => check_user_exists(input),
            "not exists" => !check_user_exists(input),
            _ => false,
        },

        _ => {
            error!("Unknown element type: {}", element);
            false
        }
    }
}
