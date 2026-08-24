use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize,};
use jsonwebtoken::{encode, EncodingKey, Header};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use validator::Validate;
use rand::RngCore;
use sha2::{Digest, Sha256};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

pub struct AppConfig {
    pub db: PgPool,
    pub token_spatial: TokenSpatial,
}

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
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct ApiResponse {
    pub error: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: i64,
    pub exp: usize,
}

#[derive(Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

const ACCESS_TOKEN_MINUTES: i64 = 15;
const REFRESH_TOKEN_DAYS:i64 = 30;

pub struct TokenSpatial {
    pub jwt: Vec<u8>,
}

impl TokenSpatial {
    pub fn new(secret: String) -> Self {
        Self { jwt: secret.into_bytes(), }
    }

    pub fn create_access_token(&self, user_id: i64) -> Result<TokenPair, jsonwebtoken::errors::Error> {
        let exp = (Utc::now() + Duration::minutes(ACCESS_TOKEN_MINUTES)).timestamp() as usize;
        let claims = Claims { sub: user_id, exp };
        let encoding_key = EncodingKey::from_secret(&self.jwt);
        encode(&Header::default(), &claims, &encoding_key)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        use jsonwebtoken::{decode, DecodingKey, Validation};
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&self.jwt),
            &Validation::default(),
        )?;
        Ok(token_data.claims)
    }

    pub fn generate_opaque_token() -> String {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn hash_token(token: &str) -> Vec<u8> {
        Sha256::digest(token.as_bytes()).to_vec()
    }

    pub async fn issue_token_pair(&self, pool: &PgPool, user_id: i64) -> Result<TokenPair, AppError> {
        let access_token = self.create_access_token(user_id)?;
        let refresh_token = self.generate_opaque_token();
        let token_hash = self.hash_token(&refresh_token);
        let expires_at = Utc::now() + Duration::days(REFRESH_TOKEN_DAYS);

        sqlx::query!(
            "INSERT INTO refresh_token (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
            user_id,
            token_hash,
            expires_at,
        )
        .execute(pool)
        .await?;

        Ok(TokenPair { access_token, refresh_token })
    }

    pub async fn rotate_refresh_token(&self, pool: &PgPool, presented_token: &str) -> Result<TokenPair, AppError> {
        let hash_token = Self::hash_token(presented_token);

        let row = sqlx::query!(
            r#"
            SELECT id, user_id, expires_at, revoked_at
            FROM refresh_tokens
            WHERE token_hash = $1
            "#,
            token_hash,
        )
        .fetch_optional(pool)
        .await?
        .ok_or(AppError::InvalidRefreshToken)?;

        if row.revoked_at.is_some() {
            sqlx::query!(
                "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND rewoked_at is NULL",
                row.user_id,
            )
            .execute(pool)
            .await?;
            return Err(AppError::InvalidRefreshToken);
        }

        if row.expires_at < Utc::now() {
            return Err(AppError::InvalidRefreshToken);
        }

        let new_pair = self.issue_token_pair(pool, row.user_id).await?;
        let new_hash = self.hash_token(&new_pair.refresh_token);

        let new_row_id = sqlx::query_scalar!(
            "SELECT id FROM refresh_tokens WHERE token_hash = $1",
            new_hash
        )
        .fetch_one(pool)
        .await?;

        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $1 WHERE id = $2",
            new_row_id,
            row.id,
        )
        .execute(pool)
        .await?;

        Ok(new_pair)
    }
}

pub enum AppError {
    ValidationError(String),
    UserAlreadyExists,
    InvalidCredentials,
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
            Self::TokenError(err) => {
                tracing::error!("JWT error occurred: {:?}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed".to_string())
            }
        };

        (status, Json(ApiResponse { error: error_message })).into_response()
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        Self::TokenError(err)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        Self::DatabaseError(err)
    }
}
