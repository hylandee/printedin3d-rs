use axum::{
    Json, Router,
    http::StatusCode,
    routing::{delete, get, post, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use thiserror::Error;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        .route("/order", get(get_order))
        .route("/order", delete(cancel_order))
        .route("/order", put(upsert_order))
        .route("/order", post(create_order));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await;
}
async fn create_order(Json(payload): Json<CreateOrder>) -> (StatusCode, Json<Order>) {
    // insert your application logic here
    let order = Order {
        id: 1337,
        username: payload.username,
    };

    // this will be converted into a JSON response
    // with a status code of `201 Created`
    (StatusCode::CREATED, Json(user))
}

// the input to our `create_user` handler
#[derive(Deserialize)]
struct CreateUser {
    username: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: String, // random token
    pub user_id: i64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user_id: i64,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub username: String,
}

impl From<User> for AuthenticatedUser {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new() -> Self {
        use rand::{Rng, distributions::Alphanumeric};

        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        SessionId(token)
    }
}

pub struct PlainPassword(pub String);
pub struct PasswordHash(pub String);

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("user already exists")]
    UserAlreadyExists,

    #[error("session expired")]
    SessionExpired,

    #[error("unauthorized")]
    Unauthorized,

    #[error("internal error")]
    Internal,
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

pub struct NewSession {
    pub id: SessionId,
    pub user_id: i64,
    pub expires_at: DateTime<Utc>,
}
