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

// Data Base configuration struct
pub struct AppConfig {
    pub db: PgPool,
    pub token_spatial: TokenSpatial,
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

pub struct TokenSpatial {
    pub jwt: Vec<u8>,
}

impl TokenSpatial {
    pub fn new(secret: String) -> Self {
        Self { jwt: secret.into_bytes(), }
    }

    pub fn create_token_pair(&self, user_id: i64) -> Result<TokenPair, jsonwebtoken::errors::Error> {
        let access_exp = (Utc::now() + Duration::minutes(15)).timestamp() as usize;
        let refresh_exp = (Utc::now() + Duration::days(180)).timestamp() as usize;

        let access_claim = Claims { sub: user_id, exp: access_exp };
        let refresh_claim = Claims { sub: user_id, exp: refresh_exp };

        let encoding_key = EncodingKey::from_secret(&self.jwt);

        let access_token = encode(&Header::default(), &access_claim, &encoding_key)?;
        let refresh_token = encode(&Header::default(), &refresh_claim, &encoding_key)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
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
