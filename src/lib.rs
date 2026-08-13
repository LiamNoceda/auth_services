use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize,};
use base64::{prelude::BASE64_STANDARD, Engine};
use jsonwebtoken::{encode, EncodingKey, Header};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use validator::Validate;

// Data Base configuration struct
pub struct AppConfig {
    pub db: PgPool,
    pub jwt_secret: String,
}

// Struct for register request
#[derive(Deserialize, Validate)]
pub struct AuthRequest {
    #[validate(length(min = 2, max = 55, message = "Username must be between 2 and 55 characters"))]
    pub username: String,

    #[validate(length(min = 8, max = 130, message = "The Password must be between 8 and 130 characters"))]
    pub password: String,
}

// Struct for auth response
#[derive(Serialize)]
pub struct AuthResponse {
    pub message: String,
    pub token: String,
}

#[derive(Serialize)]
pub struct ApiResponse {
    pub error: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
}

impl Claims {
    pub fn new(username: String) -> Self {
        let issued_at = Utc::now();
        let expiration = issued_at
            .checked_add_signed(Duration::days(130))
            .expect("Valid timestamp")
            .timestamp();
        
        Self {
            sub: username,
            iat: issued_at.timestamp(),
            exp: expiration,
        }
    }

    pub fn sign(&self, secret_base64: &str) -> Result<String, AppError> {
        let raw_secret = BASE64_STANDARD
            .decode(secret_base64.trim())
            .map_err(|err| {
                tracing::error!("Failed to decode JWT_SECRET from Base64: {:?}", err);
                AppError::DatabaseError(sqlx::Error::WorkerCrashed)
            })?;

        let key = EncodingKey::from_secret(&raw_secret);

        encode(&Header::default(), self, &key)
            .map_err(|err| {
                tracing::error!("JWT signing failed: {:?}", err);
                AppError::DatabaseError(sqlx::Error::WorkerCrashed)
            })
    }
}

pub enum AppError {
    ValidationError(String),
    UserAlreadyExists,
    InvalidCredentials,
    DatabaseError(sqlx::Error),
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
