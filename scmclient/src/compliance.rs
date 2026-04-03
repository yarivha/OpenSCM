use tracing::error;
use std::path::Path;
use std::fs;
use semver::Version;

// Normalize a version string into a semantic version.
// "0" -> "0.0.0", "1.2" -> "1.2.0", "1.2.3" stays "1.2.3".
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
    use std::process::Command;
    
    // Executes 'id -un <uid>' to get the username string from the system
    let output = Command::new("id")
        .args(["-un", &uid.to_string()])
        .output()
        .ok()?;

    if output.status.success() {
        // Trim whitespace/newlines and convert to String
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}


pub fn evaluate(
    element: &str,
    input: &str,
    selement: &str,
    condition: &str,
    sinput: &str,
) -> bool {
    // Normalize everything to trimmed lowercase
    let element_l = element.trim().to_lowercase();
    let selement_l = selement.trim().to_lowercase();
    let condition_l = condition.trim().to_lowercase();
    let sinput_trim = sinput.trim();

    match element_l.as_str() {

        "file" => match selement_l.as_str() {
            "exists" => Path::new(input).exists(),
            "not exists" => !Path::new(input).exists(),
            "content" => {
                match fs::read_to_string(input) {
                    Ok(content) => match condition_l.as_str() {
                        "contains" => content.contains(sinput),
                        "not contains" => !content.contains(sinput),
                    _ => {
                            error!("Unsupported content condition: {}", condition);
                            false
                        }
                    },
                    Err(_) => false,
                }
            },
            "permissions" => {
                match fs::metadata(input) {
                    Ok(metadata) => {
                        #[cfg(unix)]
                        {
                            // --- UNIX LOGIC (Linux, macOS, EasyNAS) ---
                            use std::os::unix::fs::PermissionsExt;
                            let mode = metadata.permissions().mode() & 0o777;

                            match u32::from_str_radix(sinput, 8) {
                                Ok(expected) => match condition_l.as_str() {
                                    "equal" => mode == expected,
                                    "more than" => mode >= expected,
                                    "less than" => mode <= expected,
                                    _ => {
                                        error!("Unsupported condition for Unix permissions: {}", condition);
                                        false
                                    }
                                },
                                Err(_) => {
                                    error!("Invalid octal string for Unix permissions: {}", sinput);
                                    false
                                }
                            }
                        }

                        #[cfg(windows)]
                        {
                            // --- WINDOWS LOGIC ---
                            use std::os::windows::fs::MetadataExt;
                            let attr = metadata.file_attributes();

                            // Windows attributes are usually checked via decimal bitmasks
                            // e.g., 1 = ReadOnly, 2 = Hidden, 4 = System, 16 = Directory
                            match sinput.parse::<u32>() {
                                Ok(expected) => match condition_l.as_str() {
                                    "equal" => attr == expected,
                                    "more than" => (attr & expected) == expected, // Contains ALL bits
                                    "less than" => (attr & expected) != 0,        // Contains ANY bits
                                    _ => {
                                        error!("Unsupported condition for Windows attributes: {}", condition);
                                        false
                                    }
                                },
                                Err(_) => {
                                    // Fallback: Check for "readonly" string if sinput isn't a number
                                    if sinput == "readonly" {
                                        metadata.permissions().readonly()
                                    } else {
                                        error!("Invalid attribute bitmask for Windows: {}", sinput);
                                        false
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Could not get metadata for permissions check on {}: {}", input, e);
                        false
                    }
                }
            },
            "owner" => {
                match fs::metadata(input) {
                    Ok(metadata) => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::MetadataExt;
                            let uid = metadata.uid();
                            let username = get_user_name_from_uid(uid).unwrap_or_default();
                            let uid_str = uid.to_string();

                            match condition_l.as_str() {
                                "equals" => {
                                    // Check against both username and UID string
                                    username == sinput || uid_str == sinput
                                },
                                "not equals" => {
                                    username != sinput && uid_str != sinput
                                },
                                "contains" => {
                                    // Check if the input string exists within the username
                                    username.contains(sinput)
                                },
                                "not contains" => {
                                    !username.contains(sinput)
                                },
                                _ => {
                                    error!("Unsupported owner condition: {}", condition);
                                    false
                                }
                            }
                        }

                        #[cfg(windows)]
                        {
                            // Windows logic would go here, likely using SID strings
                            error!("Windows owner string checks not yet implemented");
                            false
                        }
                    }
                    Err(_) => false,
                }
            }

            _ => {
                error!(
                    "Unsupported file check: element={}, input={}, selement={}, condition={}, sinput={}",
                    element, input, selement, condition, sinput
                );
                false
            }

        },

        "directory" => match selement_l.as_str() {
            "exists" => Path::new(input).is_dir(),
            "not exits" => !Path::new(input).is_dir(),
            _ => {
                error!(
                    "Unsupported directory check: element={}, input={}, selement={}, condition={}, sinput={}",
                    element, input, selement, condition, sinput
                );
                false
            }
        },

        "agent" => match selement_l.as_str() {
            "version" => {
                // parse current agent version
                let my_ver_str = env!("CARGO_PKG_VERSION");
                let my_ver_opt = parse_to_semver(my_ver_str);
                let target_ver_opt = parse_to_semver(sinput_trim);

                if let (Some(my_ver), Some(target_ver)) = (my_ver_opt, target_ver_opt) {
                    match condition_l.as_str() {
                        "equals" | "equal" | "==" => my_ver == target_ver,
                        "less than" | "<" => my_ver < target_ver,
                        "more than" | "greater than" | ">" => my_ver > target_ver,
                        _ => {
                            error!(
                                "Unsupported agent version condition: element={}, input={}, selement={}, condition={}, sinput={}",
                                element, input, selement, condition, sinput
                            );
                            false
                        }
                    }
                } else {
                    error!(
                        "Invalid version format: element={}, input={}, selement={}, condition={}, sinput={}",
                        element, input, selement, condition, sinput
                    );
                    false
                }
            }
            _ => {
                error!(
                    "Unsupported agent selement: element={}, input={}, selement={}, condition={}, sinput={}",
                    element, input, selement, condition, sinput
                );
                false
            }
        },

        _ => {
            error!(
                "Unsupported check: element={}, input={}, selement={}, condition={}, sinput={}",
                element, input, selement, condition, sinput
            );
            false
        }
    }
}

