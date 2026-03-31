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

