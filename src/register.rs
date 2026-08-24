use axum::{
    response::IntoResponse,
    extract::State,
    http::StatusCode,
    Json,
};
use argon2::{Argon2, PasswordHasher};
use std::sync::Arc;
use validator::Validate;

use auth_spatial::{AppConfig, AuthRequest, AuthResponse, AppError};

pub async fn register_handler(State(ctx): State<Arc<AppConfig>>, Json(payload): Json<AuthRequest>,) -> Result<impl IntoResponse, AppError> {
    payload
    .validate()
    .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let password_to_hash = payload.password;
    let hashed_password = tokio::task::spawn_blocking(move || {
        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| {
                tracing::error!("Password hashing failed: {:?}", e);
                sqlx::Error::WorkerCrashed
            })
    })
    .await
    .map_err(|_| AppError::DatabaseError(sqlx::Error::WorkerCrashed))?
    .map_err(AppError::DatabaseError)?;

    let row = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
        &payload.username,
        &hashed_password
    )
    .fetch_one(&ctx.db)
    .await
    .map_err(|e| {
        if let Some(db_error) = e.as_database_error() {
            if db_error.code() == Some(std::borrow::Cow::Borrowed("23505")) {
                return AppError::UserAlreadyExists;
            }
        }
        AppError::DatabaseError(e)
    })?;

    let tokens = ctx.token_spatial.issue_token_pair(&ctx.db, row.id).await?;

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse { 
            message: "User registered successfully".to_string(),
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        }),
    ))
}
