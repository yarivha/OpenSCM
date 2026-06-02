// =============================================================================
// auto_groups.rs — automatic group assignment: rule evaluator + reconciler
//
// Auto groups (system_groups.auto_managed = 1) have exactly one rule in
// auto_group_rules.  Membership is fully determined by the rule and is
// reconciled by apply_auto_groups() — called from the heartbeat handler when
// rule-relevant metadata changed, and from the auto-group rule editor when
// the admin saves a new / edited rule.
//
// Privacy stance: every input field is something already collected for an
// unrelated operational reason (heartbeat metadata, container inventory,
// telemetry).  No process or package inventory.  See
// docs/design/0.5.2-auto-groups.md for the full spec.
//
// Public surface:
//
//   • Condition / Rule                — strongly-typed wrappers around the
//                                       JSON stored in auto_group_rules.conditions
//   • SystemSnapshot                  — rule-input fields loaded fresh from the DB
//   • load_enabled_rules(...)         — pulls all enabled rules for a tenant
//   • load_system_snapshot(...)       — pulls one system's snapshot
//   • apply_auto_groups(...)          — reconciles auto-group membership for
//                                       a single system; sets compliance_dirty=1
//                                       if anything changed
//   • validate_conditions_json(...)   — parses + validates a conditions JSON
//                                       blob (called from the rule-save handler)
// =============================================================================

use std::collections::HashSet;
use serde::Deserialize;
use sqlx::{Row, SqlitePool, Sqlite, Transaction};
use tracing::warn;

// ─────────────────────────────────────────────────────────────────────────────
// Type — Operator
// All operators we accept in a rule condition.  Mapped from the JSON
// "operator" string by Operator::parse.  Each operator names a target value
// type (string / number / bool / cidr / semver); validate_conditions_json
// enforces that the supplied value parses for the operator's type and that
// the operator is valid for the field's type.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operator {
    // String
    Equals, NotEquals, Contains, NotContains, StartsWith, EndsWith, Regex,
    // Numeric  (also reused for semver compare on the `ver` field)
    Eq, Ne, Lt, Le, Gt, Ge,
    // Enum / set
    In, NotIn,
    // IP / CIDR
    InCidr,
}

impl Operator {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "equals"       => Some(Operator::Equals),
            "not_equals"   => Some(Operator::NotEquals),
            "contains"     => Some(Operator::Contains),
            "not_contains" => Some(Operator::NotContains),
            "starts_with"  => Some(Operator::StartsWith),
            "ends_with"    => Some(Operator::EndsWith),
            "regex"        => Some(Operator::Regex),
            "eq" => Some(Operator::Eq),
            "ne" => Some(Operator::Ne),
            "lt" => Some(Operator::Lt),
            "le" => Some(Operator::Le),
            "gt" => Some(Operator::Gt),
            "ge" => Some(Operator::Ge),
            "in"     => Some(Operator::In),
            "not_in" => Some(Operator::NotIn),
            "in_cidr" => Some(Operator::InCidr),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type — Field
// All fields a rule can target.  Keep in sync with the parameter catalog in
// docs/design/0.5.2-auto-groups.md §4.  Adding a new field means: (a) extend
// this enum, (b) extend SystemSnapshot, (c) extend extract_value, (d) extend
// the admin UI's field picker.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field {
    Hostname, Ip, Os, OsFamily, Arch, Platform, Ver, Status,
    MemTotalMb, DiskTotalGb, UptimeSecs,
    ContainersExists, HasRuntime, AnyContainerImage,
}

impl Field {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "hostname"            => Some(Field::Hostname),
            "ip"                  => Some(Field::Ip),
            "os"                  => Some(Field::Os),
            "os_family"           => Some(Field::OsFamily),
            "arch"                => Some(Field::Arch),
            "platform"            => Some(Field::Platform),
            "ver"                 => Some(Field::Ver),
            "status"              => Some(Field::Status),
            "mem_total_mb"        => Some(Field::MemTotalMb),
            "disk_total_gb"       => Some(Field::DiskTotalGb),
            "uptime_secs"         => Some(Field::UptimeSecs),
            "containers_exists"   => Some(Field::ContainersExists),
            "has_runtime"         => Some(Field::HasRuntime),
            "any_container_image" => Some(Field::AnyContainerImage),
            _ => None,
        }
    }

    /// Returns true if the operator is valid for this field's value type.
    fn accepts(&self, op: Operator) -> bool {
        use Field::*;
        use Operator::*;
        match self {
            // String-typed fields (including IP, which also gets InCidr).
            Hostname | Os | Platform | AnyContainerImage =>
                matches!(op, Equals | NotEquals | Contains | NotContains
                              | StartsWith | EndsWith | Regex),

            Ip => matches!(op, Equals | NotEquals | Contains | NotContains
                              | StartsWith | EndsWith | Regex | InCidr),

            // Enum-style strings — equality and membership only.
            OsFamily | Arch | Status =>
                matches!(op, Equals | NotEquals | In | NotIn),

            // has_runtime is evaluated against the set of runtimes present
            // on this host (docker / podman / …); membership-style only.
            HasRuntime => matches!(op, Equals | NotEquals | In | NotIn),

            // Numeric fields — comparison operators.
            MemTotalMb | DiskTotalGb | UptimeSecs =>
                matches!(op, Eq | Ne | Lt | Le | Gt | Ge),

            // Boolean field — only equality.
            ContainersExists => matches!(op, Equals | NotEquals),

            // Semver-string — both string ops and ordered semver compare.
            Ver => matches!(op,
                Equals | NotEquals | Contains | NotContains | StartsWith | EndsWith
                | Regex | Eq | Ne | Lt | Le | Gt | Ge),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Type — Condition
// One condition inside a rule: `field op value`.  All conditions in a rule
// AND together; OR is expressed by defining a second auto group with a
// second rule (see design doc §14, resolved Q1).
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize)]
pub struct CondJson {
    pub field:    String,
    pub operator: String,
    pub value:    serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct Condition {
    pub field: Field,
    pub op:    Operator,
    pub value: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────────
// Type — Rule
// One rule = one auto group.  conditions is non-empty (validator rejects
// empty rules — those would silently match every system).
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct Rule {
    pub id:         i64,
    pub group_id:   i64,
    pub conditions: Vec<Condition>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Type — SystemSnapshot
// All rule-input fields for a single system, loaded fresh from the DB on
// every apply_auto_groups call.  Cheap (one SELECT against systems + one
// against containers); avoids stale-data races with concurrent heartbeats.
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub system_id:         i64,
    pub hostname:          Option<String>,
    pub ip:                Option<String>,
    pub os:                Option<String>,
    pub os_family:         Option<String>,   // derived from os
    pub arch:              Option<String>,
    pub platform:          Option<String>,   // derived: "{arch}-{os_family}"
    pub ver:               Option<String>,
    pub status:            Option<String>,
    pub mem_total_mb:      Option<i64>,
    pub disk_total_gb:     Option<i64>,
    pub uptime_secs:       Option<i64>,
    pub containers_exists: bool,
    pub runtimes:          Vec<String>,      // distinct runtimes on this host
    pub container_images:  Vec<String>,      // distinct images on this host
}

impl SystemSnapshot {
    /// Compact summary of the rule-relevant fields, used by the heartbeat
    /// handler to decide whether anything changed between the old and new
    /// snapshot.  Returning a tuple keeps the comparison trivially derivable.
    pub fn rule_relevant_fingerprint(&self) -> (
        Option<&str>, Option<&str>, Option<&str>, Option<&str>, Option<&str>,
        Option<i64>, Option<i64>, bool, Vec<&str>, Vec<&str>,
    ) {
        (
            self.hostname.as_deref(),
            self.ip.as_deref(),
            self.os.as_deref(),
            self.arch.as_deref(),
            self.ver.as_deref(),
            self.mem_total_mb,
            self.disk_total_gb,
            self.containers_exists,
            self.runtimes.iter().map(String::as_str).collect(),
            self.container_images.iter().map(String::as_str).collect(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — derive_os_family
// Maps a free-form `systems.os` string ("Ubuntu 24.04", "Debian GNU/Linux",
// "Microsoft Windows Server 2022", "Darwin 23.5.0", "FreeBSD 14.0") to a
// stable enum-ish lowercase tag.  Substring sniffing on lowercase os.
// ─────────────────────────────────────────────────────────────────────────────
fn derive_os_family(os: Option<&str>) -> Option<String> {
    let s = os?.to_ascii_lowercase();
    let fam = if s.contains("windows")                              { "windows" }
              else if s.contains("darwin") || s.contains("macos")    { "macos" }
              else if s.contains("freebsd")                          { "freebsd" }
              else if s.contains("openbsd")                          { "openbsd" }
              else if s.contains("netbsd")                           { "netbsd" }
              else if s.contains("linux")  || s.contains("ubuntu")
                   || s.contains("debian") || s.contains("rhel")
                   || s.contains("centos") || s.contains("fedora")
                   || s.contains("alpine") || s.contains("suse")
                   || s.contains("arch")   || s.contains("rocky")
                   || s.contains("alma")                             { "linux" }
              else                                                   { "other" };
    Some(fam.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — derive_platform
// "{arch}-{os_family}", or None if either component is missing.  Mirrors
// derive_platform in client.rs but takes already-derived os_family.
// ─────────────────────────────────────────────────────────────────────────────
fn derive_platform(arch: Option<&str>, os_family: Option<&str>) -> Option<String> {
    Some(format!("{}-{}", arch?, os_family?))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — load_system_snapshot
// Builds a SystemSnapshot from `systems` + `containers` for one system.
// Tenant-scoped.  Returns Ok(None) if the system doesn't exist (e.g. was
// deleted between the heartbeat START and the eval call — safe no-op).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn load_system_snapshot(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    system_id: i64,
) -> Result<Option<SystemSnapshot>, sqlx::Error> {
    let Some(row) = sqlx::query(
        "SELECT id, name, ip, os, arch, ver, status,
                mem_total_mb, disk_total_gb, uptime_secs
         FROM systems
         WHERE id = ? AND tenant_id = ?"
    )
    .bind(system_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await? else { return Ok(None); };

    let os: Option<String> = row.try_get("os").ok().flatten();
    let arch: Option<String> = row.try_get("arch").ok().flatten();
    let os_family = derive_os_family(os.as_deref());
    let platform = derive_platform(arch.as_deref(), os_family.as_deref());

    // Distinct runtimes + images on this host.
    let container_rows = sqlx::query(
        "SELECT runtime, image FROM containers
         WHERE host_system_id = ? AND tenant_id = ?"
    )
    .bind(system_id)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut runtime_set: HashSet<String> = HashSet::new();
    let mut image_set:   HashSet<String> = HashSet::new();
    for c in &container_rows {
        if let Ok(Some(r)) = c.try_get::<Option<String>, _>("runtime") { runtime_set.insert(r); }
        if let Ok(Some(i)) = c.try_get::<Option<String>, _>("image")   { image_set.insert(i); }
    }
    let mut runtimes: Vec<String>         = runtime_set.into_iter().collect();
    let mut container_images: Vec<String> = image_set.into_iter().collect();
    runtimes.sort();
    container_images.sort();

    Ok(Some(SystemSnapshot {
        system_id:         row.try_get::<i64, _>("id").unwrap_or(system_id),
        hostname:          row.try_get("name").ok().flatten(),
        ip:                row.try_get("ip").ok().flatten(),
        os,
        os_family,
        arch,
        platform,
        ver:               row.try_get("ver").ok().flatten(),
        status:            row.try_get("status").ok().flatten(),
        mem_total_mb:      row.try_get("mem_total_mb").ok().flatten(),
        disk_total_gb:     row.try_get("disk_total_gb").ok().flatten(),
        uptime_secs:       row.try_get("uptime_secs").ok().flatten(),
        containers_exists: !container_rows.is_empty(),
        runtimes,
        container_images,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — load_enabled_rules
// Loads every enabled auto-group rule for a tenant, parsing each row's
// conditions JSON.  Rows whose JSON fails to validate are skipped with a
// WARN (admin will see them as not-matching anything until they re-save) —
// preferable to taking down the heartbeat path because one rule got
// corrupted.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn load_enabled_rules(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
) -> Result<Vec<Rule>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, group_id, conditions
         FROM auto_group_rules
         WHERE tenant_id = ? AND enabled = 1"
    )
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id:       i64    = r.try_get("id").unwrap_or(0);
        let group_id: i64    = r.try_get("group_id").unwrap_or(0);
        let raw:      String = r.try_get("conditions").unwrap_or_default();

        match parse_conditions(&raw) {
            Ok(conditions) if !conditions.is_empty() => {
                out.push(Rule { id, group_id, conditions });
            }
            Ok(_) => {
                warn!("auto_group_rules.id={} has empty conditions — skipped", id);
            }
            Err(e) => {
                warn!("auto_group_rules.id={} has invalid conditions JSON ({}) — skipped",
                      id, e);
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — parse_conditions
// Parses + validates a `conditions` JSON blob.  Errors carry a human-readable
// reason so the rule-editor handler can surface them inline.  An empty array
// is allowed at the parse layer; the validator (validate_conditions_json)
// rejects it because saving an empty rule would silently match all systems.
// ─────────────────────────────────────────────────────────────────────────────
pub fn parse_conditions(raw: &str) -> Result<Vec<Condition>, String> {
    let parsed: Vec<CondJson> = serde_json::from_str(raw)
        .map_err(|e| format!("invalid JSON: {}", e))?;

    let mut out = Vec::with_capacity(parsed.len());
    for (i, c) in parsed.into_iter().enumerate() {
        let field = Field::parse(&c.field)
            .ok_or_else(|| format!("condition #{}: unknown field '{}'", i + 1, c.field))?;
        let op = Operator::parse(&c.operator)
            .ok_or_else(|| format!("condition #{}: unknown operator '{}'", i + 1, c.operator))?;
        if !field.accepts(op) {
            return Err(format!(
                "condition #{}: operator '{}' not valid for field '{}'",
                i + 1, c.operator, c.field));
        }
        // Per-operator value-shape check.
        validate_value(&c.value, op)
            .map_err(|e| format!("condition #{}: {}", i + 1, e))?;
        out.push(Condition { field, op, value: c.value });
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — validate_conditions_json
// Stricter wrapper around parse_conditions for the rule-save handler:
// additionally requires at least one condition.  Use this on POST /auto_groups
// from the admin UI.
// ─────────────────────────────────────────────────────────────────────────────
pub fn validate_conditions_json(raw: &str) -> Result<Vec<Condition>, String> {
    let parsed = parse_conditions(raw)?;
    if parsed.is_empty() {
        return Err("rule must contain at least one condition".to_string());
    }
    Ok(parsed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — validate_value
// Shape-checks the JSON value against what each operator expects.  Doesn't
// check that the value is *meaningful* for the field (e.g. that an os_family
// equals-value is one of the known families) — admins can write arbitrary
// strings, they just won't match anything.
// ─────────────────────────────────────────────────────────────────────────────
fn validate_value(v: &serde_json::Value, op: Operator) -> Result<(), String> {
    use Operator::*;
    match op {
        Equals | NotEquals => {
            if !(v.is_string() || v.is_number() || v.is_boolean()) {
                return Err("value must be string, number, or boolean".into());
            }
        }
        Contains | NotContains | StartsWith | EndsWith => {
            v.as_str().ok_or("value must be a string")?;
        }
        Regex => {
            let s = v.as_str().ok_or("value must be a string")?;
            regex::Regex::new(s).map_err(|e| format!("invalid regex: {}", e))?;
        }
        Eq | Ne | Lt | Le | Gt | Ge => {
            // Either a number (numeric fields) or a string (semver compare on ver).
            if !(v.is_number() || v.is_string()) {
                return Err("value must be a number or version string".into());
            }
        }
        In | NotIn => {
            let arr = v.as_array().ok_or("value must be an array")?;
            if arr.is_empty() {
                return Err("array must not be empty".into());
            }
            for x in arr {
                if !(x.is_string() || x.is_number() || x.is_boolean()) {
                    return Err("array elements must be string/number/boolean".into());
                }
            }
        }
        InCidr => {
            let s = v.as_str().ok_or("value must be a CIDR string")?;
            s.parse::<ipnet::IpNet>().map_err(|e| format!("invalid CIDR: {}", e))?;
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — apply_auto_groups
// Reconciles auto-group membership for one system.  Returns true if any row
// in systems_in_groups was inserted or deleted (the heartbeat caller can use
// this to decide whether to also mark compliance_dirty — which is set inside
// this function as well, but the bool is useful for audit logging).
//
// Only touches auto-managed groups.  Manual group memberships are completely
// untouched, satisfying the "manual is immune to rule churn" invariant.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn apply_auto_groups(
    tx: &mut Transaction<'_, Sqlite>,
    tenant_id: &str,
    system_id: i64,
) -> Result<bool, sqlx::Error> {
    // 1. Load snapshot + rules.  If the system row vanished, do nothing.
    let Some(snapshot) = load_system_snapshot(tx, tenant_id, system_id).await? else {
        return Ok(false);
    };
    let rules = load_enabled_rules(tx, tenant_id).await?;

    // 2. Evaluate rules → target group set.
    let target_groups: HashSet<i64> = rules.iter()
        .filter(|r| eval_rule(r, &snapshot))
        .map(|r| r.group_id)
        .collect();

    // 3. Current auto-group membership (auto_managed=1 only).
    let current_rows = sqlx::query(
        "SELECT sig.group_id
         FROM systems_in_groups sig
         JOIN system_groups sg ON sg.id = sig.group_id
         WHERE sig.system_id = ? AND sig.tenant_id = ? AND sg.auto_managed = 1"
    )
    .bind(system_id)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;

    let current_auto: HashSet<i64> = current_rows.iter()
        .filter_map(|r| r.try_get::<i64, _>("group_id").ok())
        .collect();

    // 4. Diff.
    let to_add: Vec<i64>    = target_groups.difference(&current_auto).copied().collect();
    let to_remove: Vec<i64> = current_auto.difference(&target_groups).copied().collect();

    if to_add.is_empty() && to_remove.is_empty() {
        return Ok(false);
    }

    // 5. Apply additions.
    for gid in &to_add {
        sqlx::query(
            "INSERT OR IGNORE INTO systems_in_groups (tenant_id, system_id, group_id)
             VALUES (?, ?, ?)"
        )
        .bind(tenant_id)
        .bind(system_id)
        .bind(gid)
        .execute(&mut **tx)
        .await?;
    }

    // 6. Apply removals (only from auto groups — the JOIN above already
    // filtered, so any gid in current_auto is by definition auto).
    for gid in &to_remove {
        sqlx::query(
            "DELETE FROM systems_in_groups
             WHERE tenant_id = ? AND system_id = ? AND group_id = ?"
        )
        .bind(tenant_id)
        .bind(system_id)
        .bind(gid)
        .execute(&mut **tx)
        .await?;
    }

    // 7. Mark the system's compliance as needing a recalc on the next tick.
    sqlx::query(
        "UPDATE systems SET compliance_dirty = 1
         WHERE id = ? AND tenant_id = ?"
    )
    .bind(system_id)
    .bind(tenant_id)
    .execute(&mut **tx)
    .await?;

    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public — apply_auto_groups_for_tenant
// Full sweep — re-evaluate every system in the tenant.  Used by the rule
// editor on create / edit / disable.  Returns the count of systems whose
// membership changed (for the audit trail).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn apply_auto_groups_for_tenant(
    pool: &SqlitePool,
    tenant_id: &str,
) -> Result<usize, sqlx::Error> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM systems WHERE tenant_id = ?"
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;

    let mut changed = 0usize;
    for sid in ids {
        let mut tx = pool.begin().await?;
        match apply_auto_groups(&mut tx, tenant_id, sid).await {
            Ok(true)  => { tx.commit().await?; changed += 1; }
            Ok(false) => { tx.commit().await?; }
            Err(e)    => { warn!("apply_auto_groups failed for system {}: {}", sid, e);
                           let _ = tx.rollback().await; }
        }
    }
    Ok(changed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — eval_rule
// Rule matches iff every condition matches (AND semantics).
// ─────────────────────────────────────────────────────────────────────────────
fn eval_rule(rule: &Rule, sys: &SystemSnapshot) -> bool {
    rule.conditions.iter().all(|c| eval_condition(c, sys))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — eval_condition
// Dispatch on operator + value type.  Returns false on any mismatch (the
// rule simply doesn't match — never an error path).  Regex compile failures
// at eval time return false; the validator should have caught them on save.
// ─────────────────────────────────────────────────────────────────────────────
fn eval_condition(c: &Condition, sys: &SystemSnapshot) -> bool {
    use Operator::*;
    match c.field {
        // ── Multi-value fields ──────────────────────────────────────────────
        Field::HasRuntime => {
            // Match if ANY runtime on this host matches the condition.
            sys.runtimes.iter().any(|r| match_string(r, c.op, &c.value))
        }
        Field::AnyContainerImage => {
            sys.container_images.iter().any(|img| match_string(img, c.op, &c.value))
        }

        // ── Boolean ────────────────────────────────────────────────────────
        Field::ContainersExists => {
            let want = c.value.as_bool().unwrap_or(false);
            let got  = sys.containers_exists;
            matches!((c.op, want == got), (Equals, true) | (NotEquals, false))
        }

        // ── Numeric ────────────────────────────────────────────────────────
        Field::MemTotalMb   => num_cmp(sys.mem_total_mb,   c.op, &c.value),
        Field::DiskTotalGb  => num_cmp(sys.disk_total_gb,  c.op, &c.value),
        Field::UptimeSecs   => num_cmp(sys.uptime_secs,    c.op, &c.value),

        // ── IP (string ops + InCidr) ───────────────────────────────────────
        Field::Ip => {
            let Some(ip_str) = sys.ip.as_deref() else { return false; };
            if c.op == InCidr {
                let Some(cidr_str) = c.value.as_str() else { return false; };
                let (Ok(cidr), Ok(ip)) = (
                    cidr_str.parse::<ipnet::IpNet>(),
                    ip_str.parse::<std::net::IpAddr>(),
                ) else { return false; };
                return cidr.contains(&ip);
            }
            match_string(ip_str, c.op, &c.value)
        }

        // ── Semver / mixed (ver) ───────────────────────────────────────────
        Field::Ver => {
            let Some(v) = sys.ver.as_deref() else { return false; };
            match c.op {
                Eq | Ne | Lt | Le | Gt | Ge => semver_cmp(v, c.op, &c.value),
                _                            => match_string(v, c.op, &c.value),
            }
        }

        // ── Plain string fields ────────────────────────────────────────────
        Field::Hostname => match_opt_string(sys.hostname.as_deref(), c.op, &c.value),
        Field::Os       => match_opt_string(sys.os.as_deref(),       c.op, &c.value),
        Field::OsFamily => match_opt_string(sys.os_family.as_deref(),c.op, &c.value),
        Field::Arch     => match_opt_string(sys.arch.as_deref(),     c.op, &c.value),
        Field::Platform => match_opt_string(sys.platform.as_deref(), c.op, &c.value),
        Field::Status   => match_opt_string(sys.status.as_deref(),   c.op, &c.value),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — match_opt_string / match_string
// Field-value can be None (column NULL); treat that as "no match" for every
// string operator (including not_equals — a missing value is not "not equal
// to X", it's simply absent).  Errs on the side of admins having to write
// rules that handle the explicit case.
// ─────────────────────────────────────────────────────────────────────────────
fn match_opt_string(field: Option<&str>, op: Operator, value: &serde_json::Value) -> bool {
    match field {
        Some(s) => match_string(s, op, value),
        None    => false,
    }
}

fn match_string(field: &str, op: Operator, value: &serde_json::Value) -> bool {
    use Operator::*;
    match op {
        Equals     => value.as_str().is_some_and(|v| field == v),
        NotEquals  => value.as_str().is_some_and(|v| field != v),
        Contains   => value.as_str().is_some_and(|v| field.contains(v)),
        NotContains=> value.as_str().is_some_and(|v| !field.contains(v)),
        StartsWith => value.as_str().is_some_and(|v| field.starts_with(v)),
        EndsWith   => value.as_str().is_some_and(|v| field.ends_with(v)),
        Regex => {
            let Some(pat) = value.as_str() else { return false; };
            regex::Regex::new(pat).map(|r| r.is_match(field)).unwrap_or(false)
        }
        In => value.as_array().is_some_and(|arr|
            arr.iter().any(|x| x.as_str() == Some(field))),
        NotIn => value.as_array().is_some_and(|arr|
            !arr.iter().any(|x| x.as_str() == Some(field))),
        _ => false, // numeric / cidr ops not valid here
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — num_cmp
// Returns false if the field is NULL.  Value side accepts JSON number or
// JSON string (string parsed as i64).
// ─────────────────────────────────────────────────────────────────────────────
fn num_cmp(field: Option<i64>, op: Operator, value: &serde_json::Value) -> bool {
    use Operator::*;
    let Some(a) = field else { return false; };
    let Some(b) = value.as_i64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<i64>().ok()))
        else { return false; };
    match op {
        Eq => a == b, Ne => a != b,
        Lt => a <  b, Le => a <= b,
        Gt => a >  b, Ge => a >= b,
        _  => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — semver_cmp
// Compares the system's version string against the rule value using
// semver::Version.  Both sides must parse; otherwise no match.
// ─────────────────────────────────────────────────────────────────────────────
fn semver_cmp(field: &str, op: Operator, value: &serde_json::Value) -> bool {
    use Operator::*;
    let Some(v_str) = value.as_str() else { return false; };
    let (Ok(a), Ok(b)) = (
        semver::Version::parse(field),
        semver::Version::parse(v_str),
    ) else { return false; };
    match op {
        Eq => a == b, Ne => a != b,
        Lt => a <  b, Le => a <= b,
        Gt => a >  b, Ge => a >= b,
        _  => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snap() -> SystemSnapshot {
        SystemSnapshot {
            system_id: 1,
            hostname: Some("web-prod-01".into()),
            ip:       Some("10.10.5.7".into()),
            os:       Some("Ubuntu 24.04".into()),
            os_family: Some("linux".into()),
            arch:     Some("x86_64".into()),
            platform: Some("x86_64-linux".into()),
            ver:      Some("0.5.1".into()),
            status:   Some("active".into()),
            mem_total_mb:  Some(32_000),
            disk_total_gb: Some(500),
            uptime_secs:   Some(120_000),
            containers_exists: true,
            runtimes:         vec!["docker".into()],
            container_images: vec!["nginx:1.25".into(), "redis:7".into()],
        }
    }

    fn cond(field: &str, op: &str, value: serde_json::Value) -> Condition {
        let raw = json!([{"field": field, "operator": op, "value": value}]).to_string();
        parse_conditions(&raw).unwrap().into_iter().next().unwrap()
    }

    #[test]
    fn string_equals_and_regex() {
        let s = snap();
        assert!(eval_condition(&cond("hostname", "starts_with", json!("web-")), &s));
        assert!(eval_condition(&cond("hostname", "regex", json!(r"^web-prod-\d+$")), &s));
        assert!(!eval_condition(&cond("hostname", "equals", json!("db-01")), &s));
    }

    #[test]
    fn cidr_match() {
        let s = snap();
        assert!(eval_condition(&cond("ip", "in_cidr", json!("10.10.0.0/16")), &s));
        assert!(!eval_condition(&cond("ip", "in_cidr", json!("192.168.0.0/16")), &s));
    }

    #[test]
    fn numeric_and_semver() {
        let s = snap();
        assert!(eval_condition(&cond("mem_total_mb", "ge", json!(16000)), &s));
        assert!(!eval_condition(&cond("mem_total_mb", "lt", json!(16000)), &s));
        assert!(eval_condition(&cond("ver", "ge", json!("0.5.0")), &s));
        assert!(eval_condition(&cond("ver", "lt", json!("1.0.0")), &s));
    }

    #[test]
    fn boolean_and_runtime() {
        let s = snap();
        assert!(eval_condition(&cond("containers_exists", "equals", json!(true)), &s));
        assert!(eval_condition(&cond("has_runtime", "equals", json!("docker")), &s));
        assert!(!eval_condition(&cond("has_runtime", "equals", json!("podman")), &s));
        assert!(eval_condition(&cond("any_container_image", "contains", json!("nginx")), &s));
    }

    #[test]
    fn os_family_enum() {
        let s = snap();
        assert!(eval_condition(&cond("os_family", "in",
            json!(["linux", "freebsd"])), &s));
        assert!(!eval_condition(&cond("os_family", "equals", json!("windows")), &s));
    }

    #[test]
    fn null_field_never_matches() {
        let mut s = snap();
        s.mem_total_mb = None;
        assert!(!eval_condition(&cond("mem_total_mb", "ge", json!(1)), &s));
    }

    #[test]
    fn validator_rejects_empty_rule() {
        assert!(validate_conditions_json("[]").is_err());
    }

    #[test]
    fn validator_rejects_bad_operator_for_field() {
        assert!(parse_conditions(
            &json!([{"field":"mem_total_mb","operator":"contains","value":"x"}]).to_string()
        ).is_err());
    }

    #[test]
    fn validator_rejects_bad_regex() {
        assert!(parse_conditions(
            &json!([{"field":"hostname","operator":"regex","value":"["}]).to_string()
        ).is_err());
    }

    #[test]
    fn validator_rejects_bad_cidr() {
        assert!(parse_conditions(
            &json!([{"field":"ip","operator":"in_cidr","value":"not-a-cidr"}]).to_string()
        ).is_err());
    }
}
