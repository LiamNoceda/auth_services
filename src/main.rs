use axum::{routing::post, Router,};
use axum::http::{header::{CONTENT_TYPE, AUTHORIZATION}, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

mod register;
mod login;
mod refresh;

use register::register_handler;
use login::login_handler;
use refresh::refresh_handler;
use auth_spatial::{AppConfig, TokenSpatial};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let server_url = std::env::var("SERVER_URL")
        .unwrap_or_else(|_| "0.0.0.0:8081".to_string());
    let allowed_origin = std::env::var("ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:5173".to_string());
    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set");

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&db_url)
        .await
        .expect("Failed to connect to Postgres");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed run database migrations");

    let origins = match allowed_origin.parse() {
        Ok(parsed_url) => AllowOrigin::exact(parsed_url),
        Err(_) => {
            tracing::error!("CRITICAL: Invalid ALLOWED_ORIGIN format: '{}'. Falling back to safe mock origin", allowed_origin);
            AllowOrigin::exact("http://localhost:5173".parse().unwrap())
        }
    };

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .allow_credentials(allowed_origin != "*");

    let token_spatial = TokenSpatial::new(jwt_secret);
    let shared_state = Arc::new(AppConfig { db: pool, token_spatial, });

    let app = Router::new()
        .route("/api/auth/register", post(register_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/auth/refresh", post(refresh_handler))
        .layer(cors)
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind(server_url).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
