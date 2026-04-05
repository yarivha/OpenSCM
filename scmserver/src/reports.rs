use axum::response::Html;
use axum::http::{StatusCode, header};
use axum::extract::{RawForm, Extension, Query, Path};
use http_body_util::Full;
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use tracing::error;

use crate::auth::AuthSession;
use crate::handlers::render_template;



//////////////////// Reports /////////////////////////
// reports
pub async fn reports(auth: AuthSession, pool: Extension<SqlitePool>, tera: Extension<Arc<Tera>>)
    -> Result<Html<String>, StatusCode> {
    let context = Context::new();
    render_template(&tera,Some(&pool), "reports.html", context, Some(auth)).await
}




