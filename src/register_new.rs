use axum::{
    response::{IntoResponse, Response},
    extract::State,
    http::StatusCode,
    Json,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize,};
use sqlx::PgPool;
use std::sync::Arc;
use validator::Validate;

// Data Base configuration struct
pub struct AppConfig {
    pub db: PgPool,
}

// Struct for register request
#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 2, max = 55, message = "Username must be between 2 and 55 characters"))]
    pub username: String,

    #[validate(length(min = 8, max = 130, message = "The Password must be between 8 and 130 characters"))]
    pub password: String,
}

// Struct for auth response
#[derive(Serialize)]
pub struct AuthResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub enum AppError {
    ValidationError(String),
    UserAlreadyExists,
    DatabaseError(sqlx::Error),
    InternalServerError,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_messge) = match self {
            AppError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::UserAlreadyExists => (StatusCode::CONFLICT, "Username is already taken".to_string()),
            AppError::DatabaseError(e) => {
                eprintln!("Database error occurred: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database server error".to_string())
            }
            AppError::InternalServerError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        (status, Json(ErrorResponse { error: error_messge })).into_response()
    }
}

pub async fn register_handler(State(ctx): State<Arc<AppConfig>>, Json(payload): Json<RegisterRequest>,) -> Result<impl IntoResponse, AppError> {
    payload
    .validate()
    .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let password_to_hash = payload.password;
    let hashed_password = tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| AppError::InternalServerError)
    })
    .await
    .map_err(|_| AppError::InternalServerError)??;

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
        &payload.username,
        &hashed_password
    )
    .execute(&ctx.db)
    .await
    .map_err(|e| {
        if let Some(db_error) = e.as_database_error() {
            if db_error.code() == Some(std::borrow::Cow::Borrowed("23505")) {
                return AppError::UserAlreadyExists;
            }
        }
        AppError::DatabaseError(e)
    })?;

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse { 
            message: "User registered successfully".to_string() 
        }),
    ))
}
