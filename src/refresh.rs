use axum::{
    response::IntoResponse,
    extract::State,
    Json,
};
use std::sync::Arc;
use serde::Deserialize;

use auth_spatial::{AppConfig, AuthRequest, AppError};

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh_handler(State(ctx): State<Arc<AppConfig>>, Json(payload): Json<RefreshRequest>) -> Result<IntoResponse, AppError> {
    let claims = ctx.token_spatial.verify_token(&payload.refresh_token)?;

    let tokens = ctx.token_spatial.create_token_pair(claims.sub)?;

    Ok(Json(AuthResponse {
        message: "Tokens refreshed successfully".to_string(),
        access_token: tokens.access_token,
        refresh_token: tokens. refresh_token,
    }))
}