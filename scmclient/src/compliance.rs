use tracing::{debug, error, warn};
use std::path::Path;
use std::fs;
use semver::Version;
use sysinfo::System;
use std::process::Command;
use std::net::TcpStream;
use std::io::{BufRead, BufReader};


// ============================================================
// HELPERS
// ============================================================

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
    uzers::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().into_owned())
}

#[cfg(unix)]
fn get_group_name_from_gid(gid: u32) -> Option<String> {
    uzers::get_group_by_gid(gid).map(|g| g.name().to_string_lossy().into_owned())
}


fn check_user_exists(user: &str) -> bool {
    // 1. Use the dedicated Users struct (this is the 0.30+ way)
    // new_with_refreshed_list() does the initialization and the refresh in one go.
    let users = sysinfo::Users::new_with_refreshed_list();
    
    // 2. Iterate directly over the users
    // In 0.30+, get_name() is now just name()
    users.iter().any(|u| u.name() == user)
}



#[cfg(unix)]
fn check_group_exists(group: &str) -> bool {
    // Native Unix call to the groups database
    uzers::get_group_by_name(group).is_some()
}

#[cfg(windows)]
fn check_group_exists(group: &str) -> bool {
    // Windows groups are complex; sysinfo doesn't list them all yet.
    // For now, sticking to 'net localgroup' is acceptable, or 
    // using the 'windows' crate for a deep native call.
    Command::new("net")
        .args(["localgroup", group])
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}



#[cfg(unix)]
fn is_user_in_group(user: &str, group: &str) -> bool {
    let output = Command::new("id")
        .args(["-Gn", user])
        .output()
        .ok();
    output
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|g| g == group)
        })
        .unwrap_or(false)
}


/// Check if a TCP port is open on localhost.
/// Returns false gracefully on invalid port or connection failure.
fn check_port_open(port: &str) -> bool {
    let addr_str = format!("127.0.0.1:{}", port);
    let addr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => {
            warn!("Invalid port value: '{}'", port);
            return false;
        }
    };
    TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)).is_ok()
}


#[cfg(unix)]
fn check_package_exists(package: &str) -> bool {
    use std::process::Stdio;

    let dpkg = Command::new("dpkg-query")
        .args(["-W", "-f='${Status}'", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if dpkg {
        return true;
    }

    Command::new("rpm")
        .args(["-q", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn check_package_exists(package: &str) -> bool {
    Command::new("powershell")
        .args(["-Command", &format!("Get-Package -Name {}", package)])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}


#[cfg(unix)]
fn get_package_version(package: &str) -> Option<String> {
    // Try Debian/Ubuntu (dpkg)
    let output = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", package])
        .output()
        .ok();

    if let Some(o) = output {
        if o.status.success() {
            let ver = String::from_utf8_lossy(&o.stdout).trim().to_string();
            return Some(ver.split(':').last().unwrap_or(&ver).to_string());
        }
    }

    // Try RHEL/CentOS/Fedora (rpm)
    let output_rpm = Command::new("rpm")
        .args(["-q", "--queryformat", "%{VERSION}", package])
        .output()
        .ok();

    if let Some(o) = output_rpm {
        if o.status.success() {
            return Some(String::from_utf8_lossy(&o.stdout).trim().to_string());
        }
    }

    None
}

#[cfg(windows)]
fn get_package_version(package: &str) -> Option<String> {
    let cmd = format!("(Get-Package -Name {}).Version", package);
    let output = Command::new("powershell")
        .args(["-Command", &cmd])
        .output()
        .ok();

    output.and_then(|o| {
        if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else {
            None
        }
    })
}


#[cfg(unix)]
fn get_system_domain() -> Option<String> {
    // Native lookup via the resolver
    dns_lookup::get_hostname().ok().and_then(|h| {
        if h.contains('.') {
            h.splitn(2, '.').nth(1).map(|s| s.to_string())
        } else {
            None
        }
    })
}

#[cfg(windows)]
fn get_system_domain() -> Option<String> {
    // Native Windows API call (via dns-lookup crate)
    dns_lookup::get_hostname().ok().and_then(|h| {
        // On Windows, the domain is often found via the FQDN
        let fqdn = dns_lookup::getaddrinfo(Some(&h), None, None).ok()?.next()?.canonname?;
        fqdn.splitn(2, '.').nth(1).map(|s| s.to_string())
    })
}


fn check_file_content(path: &str, condition: &str, expected: &str) -> bool {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            error!("Could not open file {}: {}", path, e);
            return false;
        }
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        if let Ok(content) = line {
            if apply_string_condition(&content, condition, expected) {
                return true; // Found a match, stop reading!
            }
        }
    }
    false
}


fn calculate_sha1(path: &str) -> Result<String, std::io::Error> {
    use sha1::{Sha1, Digest};
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut hasher = Sha1::new();
    let mut buffer = [0; 4096];

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }

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


/// Apply a string condition check between actual and expected values.
fn apply_string_condition(actual: &str, condition: &str, expected: &str) -> bool {
    match condition.trim().to_lowercase().as_str() {
        "contains"                   => actual.to_lowercase().contains(&expected.to_lowercase()),
        "not contains"               => !actual.to_lowercase().contains(&expected.to_lowercase()),
        "equals" | "equal"           => actual.to_lowercase() == expected.to_lowercase(),
        "not equals" | "not equal"   => actual.to_lowercase() != expected.to_lowercase(),
        "regular expression" | "regex" => {
            match regex::RegexBuilder::new(expected)
                .multi_line(true)
                .size_limit(1_000_000)
                .build()
            {
                Ok(re) => re.is_match(actual),
                Err(e) => {
                    error!("Invalid regex pattern '{}': {}", expected, e);
                    false
                }
            }
        }
        _ => {
            error!("Unknown string condition: '{}'", condition);
            false
        }
    }
}


/// Apply a semver comparison between actual and target version strings.
fn apply_version_condition(actual_str: &str, condition: &str, target_str: &str) -> bool {
    let actual = parse_to_semver(actual_str);
    let target = parse_to_semver(target_str);

    if let (Some(a), Some(t)) = (actual, target) {
        match condition.trim().to_lowercase().as_str() {
            "equal" | "equals" | "==" => a == t,
            "not equal" | "not equals" | "!=" => a != t,
            "more than" | "greater than" | ">" => a > t,
            "less than" | "<" => a < t,
            _ => {
                error!("Unknown version condition: '{}'", condition);
                false
            }
        }
    } else {
        // Fallback to string comparison if semver parsing fails
        match condition.trim().to_lowercase().as_str() {
            "equal" | "equals" => actual_str == target_str,
            "contains"         => actual_str.contains(target_str),
            _ => false,
        }
    }
}


// ============================================================
// MAIN EVALUATE FUNCTION
// ============================================================

pub fn evaluate(
    element: &str,
    input: &str,
    selement: &str,
    condition: &str,
    sinput: &str,
) -> bool {
    let element_l   = element.trim().to_lowercase();
    let selement_l  = selement.trim().to_lowercase();
    let sinput_trim = sinput.trim();

    match element_l.as_str() {

        // =========================================================
        // AGENT
        // =========================================================
        "agent" => match selement_l.as_str() {
            "version" => apply_version_condition(env!("CARGO_PKG_VERSION"), condition, sinput_trim),
            "content" => apply_string_condition(env!("CARGO_PKG_VERSION"), condition, sinput_trim),
            _ => {
                error!("Unsupported agent selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // ARCHITECTURE
        // =========================================================
        "architecture" => match selement_l.as_str() {
            "content" => apply_string_condition(std::env::consts::ARCH, condition, sinput_trim),
            _ => {
                error!("Unsupported architecture selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // DIRECTORY
        // =========================================================
        "directory" => match selement_l.as_str() {
            "exists"     => Path::new(input).is_dir(),
            "not exists" => !Path::new(input).is_dir(),
            "content"    => {
                fs::read_dir(input)
                    .map(|entries| {
                        entries
                            .filter_map(|e| e.ok())
                            .any(|e| e.file_name() == sinput_trim)
                    })
                    .unwrap_or(false)
            }
            "owner" => {
                #[cfg(unix)]
                {
                    let metadata = fs::metadata(input).ok();
                    let uid = metadata.map(|m| std::os::unix::fs::MetadataExt::uid(&m));
                    if let Some(u) = uid {
                        let name = get_user_name_from_uid(u).unwrap_or_default();
                        name == sinput_trim || u.to_string() == sinput_trim
                    } else {
                        false
                    }
                }
                #[cfg(windows)] { false }
            }
            "group" => {
                #[cfg(unix)]
                {
                    let metadata = fs::metadata(input).ok();
                    let gid = metadata.map(|m| std::os::unix::fs::MetadataExt::gid(&m));
                    if let Some(g) = gid {
                        let name = get_group_name_from_gid(g).unwrap_or_default();
                        // Now supports "equals", "contains", "regex", etc.
                        apply_string_condition(&name, condition, sinput_trim) ||
                        apply_string_condition(&g.to_string(), condition, sinput_trim)
                    } else {
                        false
                    }
                }
                #[cfg(windows)] { false }
            }

            "permission" | "permissions" => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(input)
                        .map(|m| m.permissions().mode() & 0o777)
                        .unwrap_or(0);
                    let expected = u32::from_str_radix(sinput_trim, 8).unwrap_or(0);
                    match condition.trim().to_lowercase().as_str() {
                        "equal" | "equals" => mode == expected,
                        "more than"        => mode >= expected,
                        "less than"        => mode <= expected,
                        _ => false,
                    }
                }
                #[cfg(windows)] { false }
            }
            _ => {
                error!("Unsupported directory selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // DOMAIN
        // =========================================================
        "domain" => match selement_l.as_str() {
            "content" => {
                let actual = get_system_domain().unwrap_or_else(|| "local".to_string());
                apply_string_condition(&actual, condition, sinput_trim)
            }
            _ => {
                error!("Unsupported domain selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // FILE
        // =========================================================
        "file" => match selement_l.as_str() {
            "exists"     => Path::new(input).is_file(),
            "not exists" => !Path::new(input).is_file(),
            "content"    => check_file_content(input,condition, sinput_trim),
            "owner" => {
                #[cfg(unix)]
                {
                    let uid = fs::metadata(input)
                        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
                        .ok();
                    if let Some(u) = uid {
                        get_user_name_from_uid(u)
                            .map(|n| n == sinput_trim)
                            .unwrap_or(u.to_string() == sinput_trim)
                    } else {
                        false
                    }
                }
                #[cfg(windows)] { false }
            }
            "group" => {
                #[cfg(unix)]
                {
                    let gid = fs::metadata(input)
                        .map(|m| std::os::unix::fs::MetadataExt::gid(&m))
                        .ok();
                    if let Some(g) = gid {
                        let name = get_group_name_from_gid(g).unwrap_or_default();
                        // Apply the flexible string condition logic
                        apply_string_condition(&name, condition, sinput_trim) || 
                        apply_string_condition(&g.to_string(), condition, sinput_trim)
                    } else {
                        false
                    }
                }
                #[cfg(windows)] { false }
            }
            "permission" | "permissions" => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(input)
                        .map(|m| m.permissions().mode() & 0o777)
                        .unwrap_or(0);
                    let expected = u32::from_str_radix(sinput_trim, 8).unwrap_or(0);
                    match condition.trim().to_lowercase().as_str() {
                        "equal" | "equals" => mode == expected,
                        "more than"        => mode >= expected,
                        "less than"        => mode <= expected,
                        _ => false,
                    }
                }
                #[cfg(windows)] { false }
            }
            "sha1" => {
                match calculate_sha1(input) {
                    Ok(actual_hash) => {
                        let actual   = actual_hash.to_lowercase();
                        let expected = sinput_trim.to_lowercase();
                        debug!("SHA1 Check - File: {} | Actual: {} | Expected: {}", input, actual, expected);
                        apply_string_condition(&actual, condition, &expected)
                    }
                    Err(e) => {
                        error!("Failed to calculate SHA1 for '{}': {}", input, e);
                        false
                    }
                }
            }
            "sha2" | "sha256" => {
                match calculate_sha2(input) {
                    Ok(actual_hash) => {
                        let actual   = actual_hash.to_lowercase();
                        let expected = sinput_trim.to_lowercase();
                        debug!("SHA256 Check - File: {} | Actual: {} | Expected: {}", input, actual, expected);
                        apply_string_condition(&actual, condition, &expected)
                    }
                    Err(e) => {
                        error!("Failed to calculate SHA256 for '{}': {}", input, e);
                        false
                    }
                }
            }
            _ => {
                error!("Unsupported file selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // GROUP
        // =========================================================
        "group" => match selement_l.as_str() {
            "exists"     => check_group_exists(input),
            "not exists" => !check_group_exists(input),
            "content"    => {
                #[cfg(unix)]    { is_user_in_group(sinput_trim, input) }
                #[cfg(windows)] { false }
            }
            _ => {
                error!("Unsupported group selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // HOSTNAME
        // =========================================================
        "hostname" => match selement_l.as_str() {
            "content" => {
                let actual = gethostname::gethostname().to_string_lossy().to_string();
                apply_string_condition(&actual, condition, sinput_trim)
            }
            _ => {
                error!("Unsupported hostname selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // IP
        // =========================================================
        "ip" => match selement_l.as_str() {
            "exists" => {
                match local_ip_address::list_afinet_netifas() {
                    Ok(interfaces) => interfaces.iter().any(|(_, ip)| ip.to_string() == input),
                    Err(e) => {
                        warn!("Failed to list network interfaces: {}", e);
                        false
                    }
                }
            }
            "content" => {
                match local_ip_address::list_afinet_netifas() {
                    Ok(interfaces) => interfaces
                        .iter()
                        .any(|(_, ip)| apply_string_condition(&ip.to_string(), condition, sinput_trim)),
                    Err(e) => {
                        warn!("Failed to list network interfaces: {}", e);
                        false
                    }
                }
            }
            _ => {
                error!("Unsupported ip selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // OS
        // =========================================================
        "os" => match selement_l.as_str() {
            "content" => {
                let actual = os_info::get().os_type().to_string();
                apply_string_condition(&actual, condition, sinput_trim)
            }
            "version" => {
                let actual_str = os_info::get().version().to_string();
                apply_version_condition(&actual_str, condition, sinput_trim)
            }
            _ => {
                error!("Unsupported os selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // PACKAGE
        // =========================================================
        "package" => match selement_l.as_str() {
            "exists"     => check_package_exists(input),
            "not exists" => !check_package_exists(input),
            "version"    => {
                match get_package_version(input) {
                    Some(actual_ver) => apply_version_condition(&actual_ver, condition, sinput_trim),
                    None => {
                        debug!("Package '{}' not installed — version check fails.", input);
                        false
                    }
                }
            }
            _ => {
                error!("Unsupported package selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // PORT
        // =========================================================
        "port" => match selement_l.as_str() {
            "exists"     => check_port_open(input),
            "not exists" => !check_port_open(input),
            _ => {
                error!("Unsupported port selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // PROCESS
        // =========================================================
        "process" => {
            let mut sys = System::new();
            sys.refresh_processes();

            let is_running = sys
                .processes()
                .values()
                .any(|p| p.name().to_lowercase().contains(&input.to_lowercase()));

            match selement_l.as_str() {
                "exists"     => is_running,
                "not exists" => !is_running,
                _ => {
                    error!("Unsupported process selement: '{}'", selement);
                    false
                }
            }
        }

        // =========================================================
        // REGISTRY (Windows Only)
        // =========================================================
        "registry" => match selement_l.as_str() {
            "exists" => {
                #[cfg(windows)]
                {
                    let cmd = format!("Test-Path 'HKLM:\\{}'", input);
                    Command::new("powershell")
                        .args(["-Command", &cmd])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                }
                #[cfg(unix)] { false }
            }
            "not exists" => {
                #[cfg(windows)]
                {
                    let cmd = format!("Test-Path 'HKLM:\\{}'", input);
                    !Command::new("powershell")
                        .args(["-Command", &cmd])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(true)
                }
                #[cfg(unix)] { false }
            }
            "content" => {
                #[cfg(windows)]
                {
                    // input format: "SOFTWARE\\MyApp\\Settings|ValueName"
                    let parts: Vec<&str> = input.splitn(2, '|').collect();
                    if parts.len() != 2 {
                        error!(
                            "Registry content check requires 'path|ValueName' format, got: '{}'",
                            input
                        );
                        return false;
                    }
                    let reg_path   = parts[0];
                    let value_name = parts[1];
                    let cmd = format!(
                        "(Get-ItemProperty -Path 'HKLM:\\{}' -Name '{}').{}",
                        reg_path, value_name, value_name
                    );
                    let output = Command::new("powershell")
                        .args(["-Command", &cmd])
                        .output()
                        .ok();
                    output
                        .map(|o| {
                            let actual = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            apply_string_condition(&actual, condition, sinput_trim)
                        })
                        .unwrap_or(false)
                }
                #[cfg(unix)] { false }
            }
            _ => {
                error!("Unsupported registry selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // USER
        // =========================================================
        "user" => match selement_l.as_str() {
            "exists"     => check_user_exists(input),
            "not exists" => !check_user_exists(input),
            _ => {
                error!("Unsupported user selement: '{}'", selement);
                false
            }
        },

        // =========================================================
        // UNKNOWN
        // =========================================================
        _ => {
            error!("Unknown element type: '{}'", element);
            false
        }
    }
}
