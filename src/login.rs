use axum::{
    response::IntoResponse,
    extract::State,
    http::StatusCode,
    Json,
};
use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use std::sync::Arc;
use validator::Validate;

use auth_spatial::{AppConfig, AuthRequest, AuthResponse, AppError, Claims};

pub async fn login_handler(State(ctx): State<Arc<AppConfig>>, Json(payload): Json<AuthRequest>,) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let user = sqlx::query!(
        "Select password_hash from users where username = $1",
        &payload.username
    )
    .fetch_optional(&ctx.db)
    .await
    .map_err(AppError::DatabaseError)?
    .ok_or(AppError::InvalidCredentials)?;

    let password_to_verify = payload.password;
    let stored_hash = user.password_hash;

    tokio::task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&stored_hash)
            .map_err(|_| AppError::InvalidCredentials)?;

        Argon2::default()
            .verify_password(password_to_verify.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::InvalidCredentials)
    })
    .await
    .map_err(|_| AppError::DatabaseError(sqlx::Error::WorkerCrashed))??;

    let token = Claims::new(payload.username.clone())
        .sign(&ctx.jwt_secret)?;

    Ok((
        StatusCode::OK,
            Json(AuthResponse {
                message: "Logged in successfully".to_string(),
                token,
        }),
    ))
}
