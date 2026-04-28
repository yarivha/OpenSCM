use tracing::{debug, error, warn};
use std::path::Path;
use std::fs;
use semver::Version;
use sysinfo::System;
use std::process::Command;
use std::net::TcpStream;
use std::io::{BufRead, BufReader};


// ============================================================
// EVAL RESULT
// ============================================================

#[derive(Debug, PartialEq)]
pub enum EvalResult {
    Pass,
    Fail,
    Na,
}


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
    let users = sysinfo::Users::new_with_refreshed_list();
    users.iter().any(|u| u.name() == user)
}


#[cfg(unix)]
fn check_group_exists(group: &str) -> bool {
    uzers::get_group_by_name(group).is_some()
}

#[cfg(windows)]
fn check_group_exists(group: &str) -> bool {
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


#[cfg(target_os = "macos")]
fn check_package_exists(package: &str) -> bool {
    use std::process::Stdio;

    // Try Homebrew formula
    let brew_formula = Command::new("brew")
        .args(["list", "--formula", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if brew_formula { return true; }

    // Try Homebrew cask
    let brew_cask = Command::new("brew")
        .args(["list", "--cask", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if brew_cask { return true; }

    // Try native macOS pkgutil — scan the full package list for a match
    if let Ok(output) = Command::new("pkgutil").args(["--pkgs"]).output() {
        let list = String::from_utf8_lossy(&output.stdout);
        if list.lines().any(|line| line == package || line.contains(package)) {
            return true;
        }
    }

    false
}

#[cfg(all(unix, not(target_os = "macos")))]
fn check_package_exists(package: &str) -> bool {
    use std::process::Stdio;

    // Try dpkg (Debian/Ubuntu)
    let dpkg_output = Command::new("dpkg-query")
        .args(["-W", "-f=${Status}", package])
        .output();

    if let Ok(output) = dpkg_output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("install ok installed") {
            return true;
        }
    }

    // Try rpm (RHEL/Fedora/openSUSE)
    let rpm = Command::new("rpm")
        .args(["-q", package])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if rpm { return true; }

    // Try pacman (Arch Linux)
    Command::new("pacman")
        .args(["-Q", package])
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



#[cfg(target_os = "macos")]
fn get_package_version(package: &str) -> Option<String> {
    // Try Homebrew formula
    let output = Command::new("brew")
        .args(["list", "--formula", "--versions", package])
        .output()
        .ok();

    if let Some(o) = output {
        if o.status.success() {
            // "brew list --versions <pkg>" returns "package version" e.g. "nginx 1.25.3"
            let out = String::from_utf8_lossy(&o.stdout);
            if let Some(ver) = out.split_whitespace().nth(1) {
                return Some(ver.to_string());
            }
        }
    }

    // Try Homebrew cask
    let output_cask = Command::new("brew")
        .args(["list", "--cask", "--versions", package])
        .output()
        .ok();

    if let Some(o) = output_cask {
        if o.status.success() {
            let out = String::from_utf8_lossy(&o.stdout);
            if let Some(ver) = out.split_whitespace().nth(1) {
                return Some(ver.to_string());
            }
        }
    }

    // Try pkgutil — find matching package ID then fetch its version
    if let Ok(list_output) = Command::new("pkgutil").args(["--pkgs"]).output() {
        let list = String::from_utf8_lossy(&list_output.stdout);
        if let Some(pkg_id) = list.lines().find(|l| *l == package || l.contains(package)) {
            if let Ok(info) = Command::new("pkgutil").args(["--pkg-info", pkg_id]).output() {
                let info_str = String::from_utf8_lossy(&info.stdout);
                for line in info_str.lines() {
                    if let Some(ver) = line.strip_prefix("version: ") {
                        return Some(ver.trim().to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(all(unix, not(target_os = "macos")))]
fn get_package_version(package: &str) -> Option<String> {
    // Try dpkg (Debian/Ubuntu)
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

    // Try rpm (RHEL/Fedora/openSUSE)
    let output_rpm = Command::new("rpm")
        .args(["-q", "--queryformat", "%{VERSION}", package])
        .output()
        .ok();

    if let Some(o) = output_rpm {
        if o.status.success() {
            return Some(String::from_utf8_lossy(&o.stdout).trim().to_string());
        }
    }

    // Try pacman (Arch Linux)
    let output_pacman = Command::new("pacman")
        .args(["-Q", package])
        .output()
        .ok();

    if let Some(o) = output_pacman {
        if o.status.success() {
            // pacman -Q returns "package version" e.g. "nginx 1.24.0-1"
            let out = String::from_utf8_lossy(&o.stdout);
            if let Some(ver) = out.split_whitespace().nth(1) {
                return Some(ver.to_string());
            }
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
    dns_lookup::get_hostname().ok().and_then(|h| {
        let fqdn = dns_lookup::getaddrinfo(Some(&h), None, None)
            .ok()?
            .next()?
            .unwrap()
            .canonname?;
        fqdn.splitn(2, '.').nth(1).map(|s| s.to_string())
    })
}


fn check_file_content(path: &str, condition: &str, expected: &str) -> bool {
    // Guard: reject directories
    if Path::new(path).is_dir() {
        // Search all files in directory for the content
        let dir = match fs::read_dir(path) {
            Ok(d) => d,
            Err(e) => {
                error!("Could not read directory {}: {}", path, e);
                return false;
            }
        };
        for entry in dir.filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                if check_file_content(entry.path().to_str().unwrap_or(""), condition, expected) {
                    return true;
                }
            }
        }
        return false;
    }

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
                return true;
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
    cmd_enabled: bool,
) -> EvalResult {
    let element_l   = element.trim().to_lowercase();
    let selement_l  = selement.trim().to_lowercase();
    let sinput_trim = sinput.trim();

    match element_l.as_str() {

        // =========================================================
        // AGENT
        // =========================================================
        "agent" => match selement_l.as_str() {
            "version" => {
                if apply_version_condition(env!("CARGO_PKG_VERSION"), condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            "content" => {
                if apply_string_condition(env!("CARGO_PKG_VERSION"), condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported agent selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // ARCHITECTURE
        // =========================================================
        "architecture" => match selement_l.as_str() {
            "content" => {
                if apply_string_condition(std::env::consts::ARCH, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported architecture selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // DIRECTORY
        // =========================================================
        "directory" => match selement_l.as_str() {
            "exists"     => if Path::new(input).is_dir() { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !Path::new(input).is_dir() { EvalResult::Pass } else { EvalResult::Fail },
            "content"    => {
                let result = fs::read_dir(input)
                    .map(|entries| {
                        entries
                            .filter_map(|e| e.ok())
                            .any(|e| e.file_name() == sinput_trim)
                    })
                    .unwrap_or(false);
                if result { EvalResult::Pass } else { EvalResult::Fail }
            }
            "owner" => {
                #[cfg(unix)]
                {
                    let metadata = fs::metadata(input).ok();
                    let uid = metadata.map(|m| std::os::unix::fs::MetadataExt::uid(&m));
                    if let Some(u) = uid {
                        let name = get_user_name_from_uid(u).unwrap_or_default();
                        if name == sinput_trim || u.to_string() == sinput_trim {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(unix))]
                { EvalResult::Na }
            }
            "group" => {
                #[cfg(unix)]
                {
                    let metadata = fs::metadata(input).ok();
                    let gid = metadata.map(|m| std::os::unix::fs::MetadataExt::gid(&m));
                    if let Some(g) = gid {
                        let name = get_group_name_from_gid(g).unwrap_or_default();
                        if apply_string_condition(&name, condition, sinput_trim) ||
                           apply_string_condition(&g.to_string(), condition, sinput_trim) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(unix))]
                { EvalResult::Na }
            }
            "permission" | "permissions" => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(input)
                        .map(|m| m.permissions().mode() & 0o777)
                        .unwrap_or(0);
                    let expected = u32::from_str_radix(sinput_trim, 8).unwrap_or(0);
                    let result = match condition.trim().to_lowercase().as_str() {
                        "equal" | "equals" => mode == expected,
                        "more than"        => mode >= expected,
                        "less than"        => mode <= expected,
                        _ => false,
                    };
                    if result { EvalResult::Pass } else { EvalResult::Fail }
                }
                #[cfg(not(unix))]
                { EvalResult::Na }
            }
            _ => {
                error!("Unsupported directory selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // DOMAIN
        // =========================================================
        "domain" => match selement_l.as_str() {
            "content" => {
                let actual = get_system_domain().unwrap_or_else(|| "local".to_string());
                if apply_string_condition(&actual, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported domain selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // FILE
        // =========================================================
        "file" => match selement_l.as_str() {
            "exists"     => if Path::new(input).is_file() { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !Path::new(input).is_file() { EvalResult::Pass } else { EvalResult::Fail },
            "content"    => {
                if check_file_content(input, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            "owner" => {
                #[cfg(unix)]
                {
                    let uid = fs::metadata(input)
                        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
                        .ok();
                    if let Some(u) = uid {
                        let result = get_user_name_from_uid(u)
                            .map(|n| n == sinput_trim)
                            .unwrap_or(u.to_string() == sinput_trim);
                        if result { EvalResult::Pass } else { EvalResult::Fail }
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(unix))]
                { EvalResult::Na }
            }
            "group" => {
                #[cfg(unix)]
                {
                    let gid = fs::metadata(input)
                        .map(|m| std::os::unix::fs::MetadataExt::gid(&m))
                        .ok();
                    if let Some(g) = gid {
                        let name = get_group_name_from_gid(g).unwrap_or_default();
                        if apply_string_condition(&name, condition, sinput_trim) ||
                           apply_string_condition(&g.to_string(), condition, sinput_trim) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(unix))]
                { EvalResult::Na }
            }
            "permission" | "permissions" => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = fs::metadata(input)
                        .map(|m| m.permissions().mode() & 0o777)
                        .unwrap_or(0);
                    let expected = u32::from_str_radix(sinput_trim, 8).unwrap_or(0);
                    let result = match condition.trim().to_lowercase().as_str() {
                        "equal" | "equals" => mode == expected,
                        "more than"        => mode >= expected,
                        "less than"        => mode <= expected,
                        _ => false,
                    };
                    if result { EvalResult::Pass } else { EvalResult::Fail }
                }
                #[cfg(not(unix))]
                { EvalResult::Na }
            }
            "sha1" => {
                match calculate_sha1(input) {
                    Ok(actual_hash) => {
                        let actual   = actual_hash.to_lowercase();
                        let expected = sinput_trim.to_lowercase();
                        debug!("SHA1 Check - File: {} | Actual: {} | Expected: {}", input, actual, expected);
                        if apply_string_condition(&actual, condition, &expected) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    Err(e) => {
                        error!("Failed to calculate SHA1 for '{}': {}", input, e);
                        EvalResult::Fail
                    }
                }
            }
            "sha2" | "sha256" => {
                match calculate_sha2(input) {
                    Ok(actual_hash) => {
                        let actual   = actual_hash.to_lowercase();
                        let expected = sinput_trim.to_lowercase();
                        debug!("SHA256 Check - File: {} | Actual: {} | Expected: {}", input, actual, expected);
                        if apply_string_condition(&actual, condition, &expected) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    Err(e) => {
                        error!("Failed to calculate SHA256 for '{}': {}", input, e);
                        EvalResult::Fail
                    }
                }
            }
            _ => {
                error!("Unsupported file selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // GROUP
        // =========================================================
        "group" => match selement_l.as_str() {
            "exists"     => if check_group_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !check_group_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "content"    => {
                #[cfg(unix)]
                {
                    if is_user_in_group(sinput_trim, input) {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(unix))]
                { EvalResult::Na }
            }
            _ => {
                error!("Unsupported group selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // HOSTNAME
        // =========================================================
        "hostname" => match selement_l.as_str() {
            "content" => {
                let actual = gethostname::gethostname().to_string_lossy().to_string();
                if apply_string_condition(&actual, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported hostname selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // IP
        // =========================================================
        "ip" => match selement_l.as_str() {
            "exists" => {
                match local_ip_address::list_afinet_netifas() {
                    Ok(interfaces) => {
                        if interfaces.iter().any(|(_, ip)| ip.to_string() == input) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    Err(e) => {
                        warn!("Failed to list network interfaces: {}", e);
                        EvalResult::Fail
                    }
                }
            }
            "content" => {
                match local_ip_address::list_afinet_netifas() {
                    Ok(interfaces) => {
                        if interfaces.iter().any(|(_, ip)| apply_string_condition(&ip.to_string(), condition, sinput_trim)) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    Err(e) => {
                        warn!("Failed to list network interfaces: {}", e);
                        EvalResult::Fail
                    }
                }
            }
            _ => {
                error!("Unsupported ip selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // OS
        // =========================================================
        "os" => match selement_l.as_str() {
            "content" => {
                let actual = os_info::get().os_type().to_string();
                debug!("OS actual value: '{}'", actual);
                if apply_string_condition(&actual, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            "version" => {
                let actual_str = os_info::get().version().to_string();
                if apply_version_condition(&actual_str, condition, sinput_trim) {
                    EvalResult::Pass
                } else {
                    EvalResult::Fail
                }
            }
            _ => {
                error!("Unsupported os selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // PACKAGE
        // =========================================================
        "package" => match selement_l.as_str() {
            "exists"     => if check_package_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !check_package_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "version"    => {
                match get_package_version(input) {
                    Some(actual_ver) => {
                        if apply_version_condition(&actual_ver, condition, sinput_trim) {
                            EvalResult::Pass
                        } else {
                            EvalResult::Fail
                        }
                    }
                    None => {
                        debug!("Package '{}' not installed — version check fails.", input);
                        EvalResult::Fail
                    }
                }
            }
            _ => {
                error!("Unsupported package selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // PORT
        // =========================================================
        "port" => match selement_l.as_str() {
            "exists"     => if check_port_open(input) { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !check_port_open(input) { EvalResult::Pass } else { EvalResult::Fail },
            _ => {
                error!("Unsupported port selement: '{}'", selement);
                EvalResult::Na
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
                "exists"     => if is_running { EvalResult::Pass } else { EvalResult::Fail },
                "not exists" => if !is_running { EvalResult::Pass } else { EvalResult::Fail },
                _ => {
                    error!("Unsupported process selement: '{}'", selement);
                    EvalResult::Na
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
                    if Command::new("powershell")
                        .args(["-Command", &cmd])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                    {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(windows))]
                { EvalResult::Na }
            }
            "not exists" => {
                #[cfg(windows)]
                {
                    let cmd = format!("Test-Path 'HKLM:\\{}'", input);
                    if !Command::new("powershell")
                        .args(["-Command", &cmd])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(true)
                    {
                        EvalResult::Pass
                    } else {
                        EvalResult::Fail
                    }
                }
                #[cfg(not(windows))]
                { EvalResult::Na }
            }
            "content" => {
                #[cfg(windows)]
                {
                    let parts: Vec<&str> = input.splitn(2, '|').collect();
                    if parts.len() != 2 {
                        error!(
                            "Registry content check requires 'path|ValueName' format, got: '{}'",
                            input
                        );
                        return EvalResult::Fail;
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
                    match output {
                        Some(o) => {
                            let actual = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            if apply_string_condition(&actual, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        None => EvalResult::Fail,
                    }
                }
                #[cfg(not(windows))]
                { EvalResult::Na }
            }
            _ => {
                error!("Unsupported registry selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // USER
        // =========================================================
        "user" => match selement_l.as_str() {
            "exists"     => if check_user_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            "not exists" => if !check_user_exists(input) { EvalResult::Pass } else { EvalResult::Fail },
            _ => {
                error!("Unsupported user selement: '{}'", selement);
                EvalResult::Na
            }
        },

        // =========================================================
        // CMD
        // =========================================================
        "cmd" => {
            if !cmd_enabled {
                warn!(
                    "CMD element is disabled. Set 'cmd_enabled = true' in [client] config to enable it."
                );
                return EvalResult::Na;
            }
            match selement_l.as_str() {
                "output" => {
                    #[cfg(unix)]
                    let output = Command::new("sh").args(["-c", input]).output();
                    #[cfg(windows)]
                    let output = Command::new("cmd").args(["/C", input]).output();

                    match output {
                        Ok(o) => {
                            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
                            debug!("CMD '{}' stdout: '{}'", input, stdout);
                            if apply_string_condition(&stdout, condition, sinput_trim) {
                                EvalResult::Pass
                            } else {
                                EvalResult::Fail
                            }
                        }
                        Err(e) => {
                            error!("Failed to execute command '{}': {}", input, e);
                            EvalResult::Fail
                        }
                    }
                }
                _ => {
                    error!("Unsupported cmd selement: '{}'. Use 'output'.", selement);
                    EvalResult::Na
                }
            }
        }

        // =========================================================
        // UNKNOWN
        // =========================================================
        _ => {
            error!("Unknown element type: '{}'", element);
            EvalResult::Na
        }
    }
}
