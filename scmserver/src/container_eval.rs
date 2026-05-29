// =============================================================================
// container_eval.rs — server-side evaluator for container-only test elements
//
// Container-only elements (IMAGE, NETWORK in 0.5.0) check metadata about a
// container's configuration rather than running anything inside it. All the
// metadata is already cached in the `containers` table from heartbeat ingest,
// so evaluation is pure DB-against-condition — no agent round-trip needed.
//
// Routing is driven by `elements.evaluator` (added in schema v26), not by
// hardcoded element-name lists: the policy-run dispatch filters with
// `evaluator = 'container'` and we don't need a Rust-side classifier here.
// =============================================================================

use sqlx::sqlite::SqliteRow;
use sqlx::Row;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EvalResult { Pass, Fail, Na }

impl EvalResult {
    pub fn as_str(self) -> &'static str {
        match self { Self::Pass => "PASS", Self::Fail => "FAIL", Self::Na => "NA" }
    }
}

/// One test condition with the parts that are expensive to recompute hoisted
/// out of the per-container hot loop: the lowercased needle and a compiled
/// Regex (when condition is REGEX). Built once per condition row, evaluated
/// against many container rows.
pub struct PreparedCondition {
    pub element:  String,    // already upper-cased
    pub selement: String,    // already upper-cased
    pub op:       String,    // already upper-cased: EQUALS / CONTAINS / REGEX / ...
    pub sinput:   String,    // raw sinput (preserved for EQUALS)
    pub needle_lower: String,
    pub regex:    Option<regex::Regex>,
}

impl PreparedCondition {
    pub fn new(element: &str, selement: &str, condition: &str, sinput: &str) -> Self {
        let op = condition.trim().to_uppercase();
        let sinput = sinput.trim().to_string();
        let regex = if op == "REGEX" { regex::Regex::new(&sinput).ok() } else { None };
        Self {
            element:      element.trim().to_uppercase(),
            selement:     selement.trim().to_uppercase(),
            op,
            needle_lower: sinput.to_lowercase(),
            sinput,
            regex,
        }
    }
}

/// Evaluate one prepared condition against one container row.
/// Only the columns relevant to the (element, selement) pair are read;
/// missing / NULL fields produce `Na`.
pub fn evaluate(container_row: &SqliteRow, c: &PreparedCondition) -> EvalResult {
    let target: Option<String> = match (c.element.as_str(), c.selement.as_str()) {
        ("IMAGE",   "NAME")   => image_field(container_row, ImagePart::Name),
        ("IMAGE",   "TAG")    => image_field(container_row, ImagePart::Tag),
        ("IMAGE",   "SOURCE") => image_field(container_row, ImagePart::Source),
        ("IMAGE",   "DIGEST") => container_row.try_get("image_digest").ok().flatten(),
        ("NETWORK", "MODE")   => container_row.try_get("network_mode").ok().flatten(),
        _ => return EvalResult::Na,
    };
    match target {
        Some(v) if apply_condition(&v, c) => EvalResult::Pass,
        Some(_) => EvalResult::Fail,
        None    => EvalResult::Na,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Image reference parsing
//   reference  := [SOURCE/]NAME[:TAG][@DIGEST]
//   SOURCE     := registry host  (default "docker.io" when no '/' before name)
//   NAME       := optional namespace + repo (e.g. "library/nginx")
//   TAG        := tag after ':'  (default "latest" when absent)
// First path component is SOURCE only if it contains '.' or ':' or is
// "localhost" — matches standard Docker reference parsing rules.
// ─────────────────────────────────────────────────────────────────────────────
enum ImagePart { Source, Name, Tag }

fn image_field(row: &SqliteRow, part: ImagePart) -> Option<String> {
    let image: Option<String> = row.try_get("image").ok().flatten();
    image.map(|s| image_part(&s, part))
}

fn image_part(reference: &str, part: ImagePart) -> String {
    let no_digest = reference.split('@').next().unwrap_or(reference);

    let (source, rest) = match no_digest.split_once('/') {
        Some((head, rest)) if head.contains('.') || head.contains(':') || head == "localhost" => {
            (head.to_string(), rest.to_string())
        }
        _ => ("docker.io".to_string(), no_digest.to_string()),
    };

    let (name, tag) = match rest.rsplit_once(':') {
        Some((n, t)) if !t.contains('/') => (n.to_string(), t.to_string()),
        _ => (rest, "latest".to_string()),
    };

    match part {
        ImagePart::Source => source,
        ImagePart::Name   => name,
        ImagePart::Tag    => tag,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply a prepared condition. Mirrors the agent-side helper in
// scmclient/src/compliance.rs so host and container results have identical
// matching semantics. The needle is pre-lowercased and (for REGEX) pre-
// compiled by PreparedCondition::new.
// ─────────────────────────────────────────────────────────────────────────────
fn apply_condition(haystack: &str, c: &PreparedCondition) -> bool {
    let h = haystack.trim();
    match c.op.as_str() {
        "EQUALS"        => h.eq_ignore_ascii_case(&c.sinput),
        "NOT EQUALS"    => !h.eq_ignore_ascii_case(&c.sinput),
        "CONTAINS"      => h.to_lowercase().contains(&c.needle_lower),
        "NOT CONTAINS"  => !h.to_lowercase().contains(&c.needle_lower),
        "REGEX"         => c.regex.as_ref().is_some_and(|re| re.is_match(h)),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Combine per-condition EvalResults into a test-level verdict using the
// test's `filter` field. Matches scmclient/src/agent.rs::process_compliance_tests.
// ─────────────────────────────────────────────────────────────────────────────
pub fn combine_results(results: &[EvalResult], filter: &str) -> EvalResult {
    if results.is_empty() { return EvalResult::Na; }
    match filter.trim().to_lowercase().as_str() {
        "any" => {
            if results.iter().any(|r| *r == EvalResult::Pass) { EvalResult::Pass }
            else if results.iter().all(|r| *r == EvalResult::Na) { EvalResult::Na }
            else { EvalResult::Fail }
        }
        _ => {
            if results.iter().any(|r| *r == EvalResult::Fail) { EvalResult::Fail }
            else if results.iter().all(|r| *r == EvalResult::Na) { EvalResult::Na }
            else { EvalResult::Pass }
        }
    }
}
