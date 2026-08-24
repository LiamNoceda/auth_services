use axum::{
    response::IntoResponse,
    extract::State,
    Json,
};
use std::sync::Arc;
use serde::Deserialize;

use auth_spatial::{AppConfig, AuthResponse, AppError};

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh_handler(State(ctx): State<Arc<AppConfig>>, Json(payload): Json<RefreshRequest>) -> Result<impl IntoResponse, AppError> {
    let tokens = ctx
    .token_spatial
    .rotate_refresh_token(&ctx.db, &payload.refresh_token)
    .await?;

    Ok(Json(AuthResponse {
        message: "Tokens refreshed successfully".to_string(),
        access_token: tokens.access_token,
        refresh_token: tokens. refresh_token,
    }))
}