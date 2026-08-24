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

use auth_spatial::{AppConfig, AuthRequest, AuthResponse, AppError};

const DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXJhbmRvbXNhbHQ$Q2hhbmdlTWVCZWZvcmVQcm9kdWN0aW9u";

pub async fn login_handler(State(ctx): State<Arc<AppConfig>>, Json(payload): Json<AuthRequest>,) -> Result<impl IntoResponse, AppError> {
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let user = sqlx::query!(
        "Select id, password_hash FROM users WHERE username = $1",
        &payload.username
    )
    .fetch_optional(&ctx.db)
    .await?;

    let (user_id, stored_hash) = match &user {
        Some(u) => (Some(u.id), u.password_hash.clone()),
        None => (None, DUMMY_HASH.to_string()),
    };

    let password_to_verify = payload.password;
    let verify_ok = tokio::task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&stored_hash)
            .map_err(|_| ())?;
        Argon2::default()
            .verify_password(password_to_verify.as_bytes(), &parsed_hash)
            .is_ok()
    })
    .await
    .map_err(|_| AppError::DatabaseError(sqlx::Error::WorkerCrashed))?
    .unwrap_or(false);

    if !verify_ok || user_id.is_none() {
        return Err(AppError::InvalidCredentials);
    }
    let user_id = user_id.unwrap();

    let tokens = ctx.token_spatial.issue_token_pair(&ctx.db, user_id).await?;

    Ok((
        StatusCode::OK,
        Json(AuthResponse {
            message: "Logged in successfully".to_string(),
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        }),
    ))
}
