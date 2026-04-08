use axum::response::{Html, Redirect};
use axum::http::StatusCode;
use axum::extract::{RawForm, Extension, Query, Path};
use tera::{Tera, Context};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::sync::Arc;
use urlencoding;
use tracing::error;
use bcrypt::{hash, DEFAULT_COST};

use crate::models::ErrorQuery;
use crate::models::User;
use crate::auth::AuthSession;
use crate::handlers::render_template;
use crate::handlers::parse_form_data;



//////////////////// Settings /////////////////////////
 

