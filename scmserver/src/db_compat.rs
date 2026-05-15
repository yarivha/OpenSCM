// =============================================================================
// db_compat.rs — DB-backend-agnostic helpers for multi-backend AnyPool support
//
// All SQL that differs between SQLite, MySQL, and PostgreSQL (e.g. schema
// introspection, auto-increment syntax, upserts, date functions) lives here so
// the rest of the codebase stays clean.
//
// Callers call set_db_backend() once at startup; every helper below then
// returns the correct SQL for the active backend.
// =============================================================================

use sqlx::AnyPool;
use crate::{DbBackend, get_db_backend};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: adapt_sql
// Rewrites a SQL string for the active backend by substituting SQLite-specific
// syntax with the appropriate MySQL or PostgreSQL equivalent.
//
// Handles:
//  • INTEGER PRIMARY KEY AUTOINCREMENT  →  INT NOT NULL AUTO_INCREMENT PRIMARY KEY  (MySQL)
//                                       →  BIGSERIAL PRIMARY KEY                    (PostgreSQL)
//  • INSERT OR IGNORE INTO              →  INSERT IGNORE INTO                       (MySQL)
//                                       →  INSERT INTO … ON CONFLICT DO NOTHING     (PostgreSQL)
//  • DEFAULT (datetime('now'))          →  DEFAULT CURRENT_TIMESTAMP                (both)
//
// SQLite input is returned unchanged.
// ─────────────────────────────────────────────────────────────────────────────
pub fn adapt_sql(sql: &str) -> String {
    match get_db_backend() {
        DbBackend::Sqlite => sql.to_string(),

        DbBackend::Mysql => {
            let s = sql
                .replace(
                    "INTEGER PRIMARY KEY AUTOINCREMENT",
                    "INT NOT NULL AUTO_INCREMENT PRIMARY KEY",
                )
                .replace("INSERT OR IGNORE INTO", "INSERT IGNORE INTO")
                .replace("DEFAULT (datetime('now'))", "DEFAULT CURRENT_TIMESTAMP")
                // MySQL: `key` is a reserved word. Quote it wherever it appears
                // as the systems.key column identifier in DDL and DML.
                .replace(" key TEXT,",  " `key` TEXT,")   // CREATE TABLE col def
                .replace(" key = ",     " `key` = ")      // WHERE key = ?
                .replace("SELECT key,", "SELECT `key`,")  // SELECT list
                .replace(", key,",      ", `key`,")        // INSERT / column lists
                .replace(", key)",      ", `key`)");       // end of column list
            s
        }

        DbBackend::Postgres => {
            let mut s = sql
                .replace(
                    "INTEGER PRIMARY KEY AUTOINCREMENT",
                    "BIGSERIAL PRIMARY KEY",
                )
                .replace("DEFAULT (datetime('now'))", "DEFAULT CURRENT_TIMESTAMP")
                // PostgreSQL has no DATETIME type — use TIMESTAMP instead.
                .replace(" DATETIME ", " TIMESTAMP ")
                .replace(" DATETIME\n", " TIMESTAMP\n")
                .replace(" DATETIME,", " TIMESTAMP,");
            // Transform single-statement INSERT OR IGNORE:
            // "INSERT OR IGNORE INTO t (c) VALUES (?)"
            //   → "INSERT INTO t (c) VALUES (?) ON CONFLICT DO NOTHING"
            if s.contains("INSERT OR IGNORE INTO") {
                s = s.replace("INSERT OR IGNORE INTO", "INSERT INTO");
                s = format!("{} ON CONFLICT DO NOTHING", s.trim_end());
            }
            s
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: schema_info_exists_sql
// Returns a COUNT(*) SQL statement that evaluates to 1 when the schema_info
// table exists (and has at least one row), 0 otherwise.
// ─────────────────────────────────────────────────────────────────────────────
pub fn schema_info_exists_sql() -> &'static str {
    match get_db_backend() {
        DbBackend::Sqlite => {
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_info'"
        }
        DbBackend::Mysql => {
            "SELECT COUNT(*) FROM information_schema.TABLES \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'schema_info'"
        }
        DbBackend::Postgres => {
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = 'schema_info'"
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: table_exists_sql
// Returns a COUNT(*) SQL that is 1 when `table` exists in the current schema.
// Used for optional-table checks (e.g. plan_limits on SaaS).
// ─────────────────────────────────────────────────────────────────────────────
pub fn table_exists_sql(table: &str) -> String {
    match get_db_backend() {
        DbBackend::Sqlite => format!(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{table}'"
        ),
        DbBackend::Mysql => format!(
            "SELECT COUNT(*) FROM information_schema.TABLES \
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{table}'"
        ),
        DbBackend::Postgres => format!(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = '{table}'"
        ),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: column_exists
// Returns true if `column` is present in `table` for the active DB backend.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn column_exists(pool: &AnyPool, table: &str, column: &str) -> bool {
    match get_db_backend() {
        DbBackend::Sqlite => {
            // pragma_table_info(<table>) is a virtual table readable via plain SQL.
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
        DbBackend::Mysql => {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.COLUMNS \
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?",
            )
            .bind(table)
            .bind(column)
            .fetch_one(pool)
            .await
            .unwrap_or(0);
            count > 0
        }
        DbBackend::Postgres => {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = ? AND column_name = ?",
            )
            .bind(table)
            .bind(column)
            .fetch_one(pool)
            .await
            .unwrap_or(0);
            count > 0
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: last_insert_id_sql
// Returns the SQL expression that retrieves the auto-generated ID from the most
// recent INSERT on the current connection.
// ─────────────────────────────────────────────────────────────────────────────
pub fn last_insert_id_sql() -> &'static str {
    match get_db_backend() {
        DbBackend::Sqlite   => "SELECT last_insert_rowid()",
        DbBackend::Mysql    => "SELECT LAST_INSERT_ID()",
        DbBackend::Postgres => "SELECT lastval()",
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: format_datetime_col
// Returns a SQL expression that formats a datetime column as an ISO-8601 string
// ("YYYY-MM-DDTHH:MM:SSZ"), or '' when the value is NULL.
// Example: format_datetime_col("s.created_date") →
//   SQLite:   COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', s.created_date), '')
//   MySQL:    COALESCE(DATE_FORMAT(s.created_date, '%Y-%m-%dT%H:%i:%SZ'), '')
//   Postgres: COALESCE(TO_CHAR(s.created_date::TIMESTAMP,
//                       'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '')
// ─────────────────────────────────────────────────────────────────────────────
pub fn format_datetime_col(col: &str) -> String {
    match get_db_backend() {
        DbBackend::Sqlite => {
            format!("COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', {col}), '')")
        }
        DbBackend::Mysql => {
            // MySQL: %H=hour, %i=minute (not %M which is month name), %S=second
            format!("COALESCE(DATE_FORMAT({col}, '%Y-%m-%dT%H:%i:%SZ'), '')")
        }
        DbBackend::Postgres => {
            format!(
                "COALESCE(TO_CHAR({col}::TIMESTAMP, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), '')"
            )
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: unix_diff_col
// Returns a SQL expression that computes (now − col) in whole seconds, for
// use in offline-detection CASE statements.
// Example: unix_diff_col("s.last_seen") →
//   SQLite:  (CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', s.last_seen) AS INTEGER))
//   MySQL:   (UNIX_TIMESTAMP() - UNIX_TIMESTAMP(s.last_seen))
//   Postgres:(EXTRACT(EPOCH FROM NOW())::BIGINT - EXTRACT(EPOCH FROM s.last_seen::TIMESTAMP)::BIGINT)
// ─────────────────────────────────────────────────────────────────────────────
pub fn unix_diff_col(col: &str) -> String {
    match get_db_backend() {
        DbBackend::Sqlite => format!(
            "(CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', {col}) AS INTEGER))"
        ),
        DbBackend::Mysql => format!("(UNIX_TIMESTAMP() - UNIX_TIMESTAMP({col}))"),
        DbBackend::Postgres => format!(
            "(EXTRACT(EPOCH FROM NOW())::BIGINT \
              - EXTRACT(EPOCH FROM {col}::TIMESTAMP)::BIGINT)"
        ),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: date_group_col
// Returns a SQL expression that truncates/formats `col` for a given grouping
// granularity, used by the dashboard compliance-history trend queries.
//
// granularity: "yearly" | "weekly" | "monthly" | "hourly" (default = daily)
// ─────────────────────────────────────────────────────────────────────────────
pub fn date_group_col(col: &str, granularity: &str) -> String {
    match get_db_backend() {
        DbBackend::Sqlite => match granularity {
            "yearly"  => format!("strftime('%Y', {col})"),
            "weekly"  => format!("strftime('%Y-W%W', {col})"),
            "monthly" => format!("strftime('%m-%Y', {col})"),
            "hourly"  => format!("strftime('%m-%d %H:00', {col})"),
            _         => format!("strftime('%Y-%m-%d', {col})"),
        },
        DbBackend::Mysql => match granularity {
            "yearly"  => format!("DATE_FORMAT({col}, '%Y')"),
            "weekly"  => format!("DATE_FORMAT({col}, '%Y-W%u')"),
            "monthly" => format!("DATE_FORMAT({col}, '%m-%Y')"),
            "hourly"  => format!("DATE_FORMAT({col}, '%m-%d %H:00')"),
            _         => format!("DATE_FORMAT({col}, '%Y-%m-%d')"),
        },
        DbBackend::Postgres => match granularity {
            "yearly"  => format!("TO_CHAR({col}::TIMESTAMP, 'YYYY')"),
            "weekly"  => format!("TO_CHAR({col}::TIMESTAMP, 'IYYY-\"W\"IW')"),
            "monthly" => format!("TO_CHAR({col}::TIMESTAMP, 'MM-YYYY')"),
            "hourly"  => format!("TO_CHAR({col}::TIMESTAMP, 'MM-DD HH24:\"00\"')"),
            _         => format!("TO_CHAR({col}::TIMESTAMP, 'YYYY-MM-DD')"),
        },
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: group_concat_col
// Returns a SQL expression for aggregating strings with a comma separator.
// SQLite and MySQL share GROUP_CONCAT; PostgreSQL uses STRING_AGG.
// ─────────────────────────────────────────────────────────────────────────────
pub fn group_concat_col(col: &str) -> String {
    match get_db_backend() {
        DbBackend::Sqlite | DbBackend::Mysql => format!("GROUP_CONCAT({col})"),
        DbBackend::Postgres => format!("STRING_AGG({col}, ',')"),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: rename_table_sql
// Returns the SQL statement that renames a table.
// SQLite and PostgreSQL: ALTER TABLE old RENAME TO new
// MySQL: RENAME TABLE old TO new  (ALTER TABLE … RENAME TO is not supported)
// ─────────────────────────────────────────────────────────────────────────────
pub fn rename_table_sql(old: &str, new: &str) -> String {
    match get_db_backend() {
        DbBackend::Sqlite | DbBackend::Postgres => {
            format!("ALTER TABLE {old} RENAME TO {new}")
        }
        DbBackend::Mysql => {
            format!("RENAME TABLE {old} TO {new}")
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: admin_role_trigger_sql
// Returns the SQL that creates a DB-level trigger protecting the bootstrap
// admin's role from being changed. Returns None on backends where the SQLite
// RAISE(ABORT, ...) syntax is not supported — application-level enforcement
// still applies on those backends.
// ─────────────────────────────────────────────────────────────────────────────
pub fn admin_role_trigger_sql() -> Option<&'static str> {
    match get_db_backend() {
        DbBackend::Sqlite => Some(
            "CREATE TRIGGER IF NOT EXISTS protect_bootstrap_admin_role
             BEFORE UPDATE OF role ON users
             WHEN OLD.id = 1 AND OLD.tenant_id = 'default'
             BEGIN
                 SELECT RAISE(ABORT, 'The bootstrap admin role cannot be changed');
             END",
        ),
        // MySQL trigger syntax requires SIGNAL SQLSTATE and a FOR EACH ROW clause.
        // PostgreSQL requires a PL/pgSQL function + separate trigger statement.
        // Application-level enforcement (UI lock + server guard) covers both.
        DbBackend::Mysql | DbBackend::Postgres => None,
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: upsert_results_sql
// Returns the full INSERT … ON CONFLICT / ON DUPLICATE KEY UPDATE statement
// for inserting or replacing a compliance test result in the results table.
// ─────────────────────────────────────────────────────────────────────────────
pub fn upsert_results_sql() -> &'static str {
    match get_db_backend() {
        // SQLite and PostgreSQL share the ON CONFLICT … DO UPDATE syntax.
        DbBackend::Sqlite | DbBackend::Postgres => {
            r#"INSERT INTO results (tenant_id, system_id, test_id, result, last_updated)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(tenant_id, system_id, test_id)
               DO UPDATE SET result = excluded.result, last_updated = excluded.last_updated"#
        }
        DbBackend::Mysql => {
            r#"INSERT INTO results (tenant_id, system_id, test_id, result, last_updated)
               VALUES (?, ?, ?, ?, ?)
               ON DUPLICATE KEY UPDATE result = VALUES(result), last_updated = VALUES(last_updated)"#
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: upsert_schedule_sql
// Returns the full INSERT … ON CONFLICT / ON DUPLICATE KEY UPDATE statement
// for inserting or updating a policy schedule row.
// `stype` must be a string literal embedded into the SQL ("scan" or "report").
// ─────────────────────────────────────────────────────────────────────────────
pub fn upsert_schedule_sql(stype: &str) -> String {
    match get_db_backend() {
        DbBackend::Sqlite | DbBackend::Postgres => format!(
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
        ),
        DbBackend::Mysql => format!(
            r#"INSERT INTO policy_schedules
                   (tenant_id, policy_id, schedule_type, enabled, frequency, cron_expression, next_run)
               VALUES (?, ?, '{stype}', ?, ?, ?, ?)
               ON DUPLICATE KEY UPDATE
                   enabled          = VALUES(enabled),
                   frequency        = VALUES(frequency),
                   cron_expression  = VALUES(cron_expression),
                   next_run         = CASE
                                        WHEN VALUES(next_run) != '' THEN VALUES(next_run)
                                        ELSE next_run
                                      END"#
        ),
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Helper: upsert_setting_sql
// Returns the INSERT … ON CONFLICT / ON DUPLICATE KEY UPDATE statement for
// inserting or updating a single settings row (tenant_id, key, value).
// ─────────────────────────────────────────────────────────────────────────────
pub fn upsert_setting_sql() -> &'static str {
    match get_db_backend() {
        DbBackend::Sqlite | DbBackend::Postgres => {
            r#"INSERT INTO settings (tenant_id, skey, value)
               VALUES (?, ?, ?)
               ON CONFLICT (tenant_id, skey) DO UPDATE SET value = excluded.value"#
        }
        DbBackend::Mysql => {
            r#"INSERT INTO settings (tenant_id, skey, value)
               VALUES (?, ?, ?)
               ON DUPLICATE KEY UPDATE value = VALUES(value)"#
        }
    }
}
