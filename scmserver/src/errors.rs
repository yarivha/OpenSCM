// src/errors.rs
use thiserror::Error;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response, Json};
use serde_json::json;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal server error: {0}")]
    InternalServerError(String),
    #[error("Template rendering error: {0}")]
    TemplateError(#[from] tera::Error), // Add this if you haven't
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AppError::DatabaseError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("Database error: {}", e)}),
            ),
            AppError::IoError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("IO error: {}", e)}),
            ),
            AppError::ValidationError(e) => (StatusCode::BAD_REQUEST, json!({"error": e})),
            AppError::NotFound => (StatusCode::NOT_FOUND, json!({"error": "Not found"})),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, json!({"error": "Unauthorized"})),
            AppError::InternalServerError(e) | AppError::TemplateError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("Internal server error: {}", e)}),
            ),
        };

        (status, Json(body)).into_response()
    }
}
