// =============================================================================
// db_compat.rs — SQLite-only SQL helpers
//
// Previously contained multi-backend (SQLite/MySQL/PostgreSQL) dispatch logic.
// Simplified to SQLite-only for v0.3.1. All functions that previously branched
// on get_db_backend() now return the SQLite variant unconditionally.
//
// adapt_sql() is kept as an identity function so all call sites continue to
// compile without modification. last_insert_id_sql(), schema_info_exists_sql(),
// table_exists_sql(), and column_exists() are kept for the same reason.
// =============================================================================

use sqlx::SqlitePool;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: adapt_sql
// Identity function — returns sql unchanged. Kept so callers need no changes.
// ─────────────────────────────────────────────────────────────────────────────
pub fn adapt_sql(sql: &str) -> String {
    sql.to_string()
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: schema_info_exists_sql
// Returns a COUNT(*) SQL statement that evaluates to 1 when the schema_info
// table exists (and has at least one row), 0 otherwise.
// ─────────────────────────────────────────────────────────────────────────────
pub fn schema_info_exists_sql() -> &'static str {
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_info'"
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: table_exists_sql
// Returns a COUNT(*) SQL that is 1 when `table` exists in the current schema.
// Used for optional-table checks (e.g. plan_limits on SaaS).
// ─────────────────────────────────────────────────────────────────────────────
pub fn table_exists_sql(table: &str) -> String {
    format!(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{table}'"
    )
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: column_exists
// Returns true if `column` is present in `table`.
// Uses pragma_table_info which is a virtual table readable via plain SQL.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> bool {
    let sql = format!(
        "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name = '{}'",
        table, column
    );
    let count: i64 = sqlx::query_scalar(&sql)
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    count > 0
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: last_insert_id_sql
// Returns the SQL expression that retrieves the auto-generated ID from the most
// recent INSERT on the current connection.
// ─────────────────────────────────────────────────────────────────────────────
pub fn last_insert_id_sql() -> &'static str {
    "SELECT last_insert_rowid()"
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: format_datetime_col
// Returns a SQL expression that formats a datetime column as an ISO-8601 string
// ("YYYY-MM-DDTHH:MM:SSZ"), or '' when the value is NULL.
// ─────────────────────────────────────────────────────────────────────────────
pub fn format_datetime_col(col: &str) -> String {
    format!("COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', {col}), '')")
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: unix_diff_col
// Returns a SQL expression that computes (now − col) in whole seconds.
// Used in offline-detection CASE statements.
// ─────────────────────────────────────────────────────────────────────────────
pub fn unix_diff_col(col: &str) -> String {
    format!(
        "(CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', {col}) AS INTEGER))"
    )
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: date_group_col
// Returns a SQL expression that truncates/formats `col` for a given grouping
// granularity, used by the dashboard compliance-history trend queries.
//
// granularity: "yearly" | "weekly" | "monthly" | "hourly" (default = daily)
// ─────────────────────────────────────────────────────────────────────────────
pub fn date_group_col(col: &str, granularity: &str) -> String {
    match granularity {
        "yearly"  => format!("strftime('%Y', {col})"),
        "weekly"  => format!("strftime('%Y-W%W', {col})"),
        "monthly" => format!("strftime('%m-%Y', {col})"),
        "hourly"  => format!("strftime('%m-%d %H:00', {col})"),
        _         => format!("strftime('%Y-%m-%d', {col})"),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: group_concat_col
// Returns a SQL expression for aggregating strings with a comma separator.
// ─────────────────────────────────────────────────────────────────────────────
pub fn group_concat_col(col: &str) -> String {
    format!("GROUP_CONCAT({col})")
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: rename_table_sql
// Returns the SQL statement that renames a table.
// ─────────────────────────────────────────────────────────────────────────────
pub fn rename_table_sql(old: &str, new: &str) -> String {
    format!("ALTER TABLE {old} RENAME TO {new}")
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: admin_role_trigger_sql
// Returns the SQL that creates a DB-level trigger protecting the bootstrap
// admin's role from being changed.
// ─────────────────────────────────────────────────────────────────────────────
pub fn admin_role_trigger_sql() -> Option<&'static str> {
    Some(
        "CREATE TRIGGER IF NOT EXISTS protect_bootstrap_admin_role
         BEFORE UPDATE OF role ON users
         WHEN OLD.id = 1 AND OLD.tenant_id = 'default'
         BEGIN
             SELECT RAISE(ABORT, 'The bootstrap admin role cannot be changed');
         END",
    )
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: upsert_results_sql
// Returns the full INSERT … ON CONFLICT DO UPDATE statement for inserting or
// replacing a compliance test result in the results table.
// ─────────────────────────────────────────────────────────────────────────────
pub fn upsert_results_sql() -> &'static str {
    r#"INSERT INTO results (tenant_id, system_id, test_id, result, last_updated)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(tenant_id, system_id, test_id)
       DO UPDATE SET result = excluded.result, last_updated = excluded.last_updated"#
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: upsert_schedule_sql
// Returns the full INSERT … ON CONFLICT DO UPDATE statement for inserting or
// updating a policy schedule row.
// `stype` must be a string literal embedded into the SQL ("scan" or "report").
// ─────────────────────────────────────────────────────────────────────────────
pub fn upsert_schedule_sql(stype: &str) -> String {
    format!(
        r#"INSERT INTO policy_schedules
               (tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run)
           VALUES (?, ?, '{stype}', ?, ?, ?, ?)
           ON CONFLICT(policy_id, schedule_type) DO UPDATE SET
               enabled          = excluded.enabled,
               frequency        = excluded.frequency,
               cron_expression  = excluded.cron_expression,
               next_run         = CASE
                                    WHEN excluded.next_run != '' THEN excluded.next_run
                                    ELSE next_run
                                  END"#
    )
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: upsert_setting_sql
// Returns the INSERT … ON CONFLICT DO UPDATE statement for inserting or
// updating a single settings row (tenant_id, key, value).
// ─────────────────────────────────────────────────────────────────────────────
pub fn upsert_setting_sql() -> &'static str {
    r#"INSERT INTO settings (tenant_id, skey, value)
       VALUES (?, ?, ?)
       ON CONFLICT (tenant_id, skey) DO UPDATE SET value = excluded.value"#
}
