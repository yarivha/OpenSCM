// =============================================================================
// db_compat.rs — DB-backend-agnostic helpers for multi-backend AnyPool support
//
// All SQL that differs between SQLite, MySQL, and PostgreSQL (e.g. schema
// introspection) lives here so the rest of the codebase stays clean.
// Callers set the active backend once at startup via set_db_backend(); these
// helpers then return the correct SQL or execute the correct query.
// =============================================================================

use sqlx::AnyPool;
use crate::get_db_backend;
use crate::DbBackend;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: schema_info_exists_sql
// Returns a COUNT(*) SQL statement that evaluates to 1 when the schema_info
// table exists (and has at least one row), 0 otherwise.
// The statement is parameterless and safe to pass to query_scalar.
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
// Helper: column_exists
// Returns true if `column` is present in `table` for the active DB backend.
// Uses a COUNT(*) approach for MySQL/Postgres (parameterised); for SQLite uses
// the pragma_table_info() virtual table so it works through AnyPool.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn column_exists(pool: &AnyPool, table: &str, column: &str) -> bool {
    match get_db_backend() {
        DbBackend::Sqlite => {
            // pragma_table_info(<table>) is a virtual table readable via plain SQL.
            // Interpolating table name is safe here — callers always pass
            // hard-coded string literals, never user input.
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
                 WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
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
