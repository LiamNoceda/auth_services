use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize,};
use jsonwebtoken::{encode, EncodingKey, Header};
use chrono::{Duration, Utc, DateTime};
use sqlx::PgPool;
use validator::Validate;

pub struct AppConfig {
    pub db: PgPool,
}

#[derive(Deserialize, Validate)]
pub struct AuthRequest {
    #[validate(length(min = 2, max = 55, message = "Username must be between 2 and 55 characters"))]
    pub username: String,

    #[validate(length(min = 8, max = 255, message = "The Password must be between 8 and 255 characters"))]
    pub password: String,
}

// Struct for auth response
#[derive(Serialize)]
pub struct AuthResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct ApiResponse {
    pub error: String,
}

pub enum AppError {
    ValidationError(String),
    UserAlreadyExists,
    InvalidCredentials,
    InvalidRefreshToken,
    DatabaseError(sqlx::Error),
    TokenError(jsonwebtoken::errors::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::UserAlreadyExists => (StatusCode::CONFLICT, "Username is already taken".to_string()),
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid username or password".to_string()),
            Self::DatabaseError(err) => {
                tracing::error!("Database error occurred: {:?}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        (status, Json(ApiResponse { error: error_message })).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        Self::DatabaseError(err)
    }
}
