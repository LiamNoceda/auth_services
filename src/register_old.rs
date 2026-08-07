use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use bcrypt::{hash, DEFAULT_COST};
use sqlx::PgPool;

#[derive(Deserialize)]
struct RegisterUnit {
    name: String,
    username: String,
    fullname: String,
    phone: u32,
    password: String //будем принимать только сам пароль, бек его хеширует и отправит в sql таблицу hash_password
}

const DATABASE_URL: &str = "URL-Data-Base";

async fn auth_mdlwr(request: Request<Body>, next: Next,) -> Result<(Response, StatusCode), (StatusCode, &'static str)> {
    
}

#[tokio::main]
async main() {
    let db_pool = PgPool::connect(DATABASE_URL)
        .await
        .expect("К сожалению, не удалось подключиться к базе данных");

    let app = Router::new()
        .route("/auth/register", post(hadler_register))
        .with_state(db_pool)
        .route_layer(middleware ::from_fn(auth_mdlwr));

    let listener = tokio::net::TcpListener::bind(127.0.0.1:8001)
        .await
        .unwrap();
    println!("Пространство регистрации запушен на http://127.0.0.1:8001");
    axum::serve(listener, app)
        .await
        .unwrap();
}
