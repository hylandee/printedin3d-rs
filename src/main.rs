use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use thiserror::Error;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db = SqlitePool::connect("sqlite:auth.db?mode=rwc")
        .await
        .expect("db connect failed");

    // Initialize database schema
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )",
    )
    .execute(&db)
    .await
    .expect("failed to create users table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
    )
    .execute(&db)
    .await
    .expect("failed to create sessions table");

    let state = AppState { db };

    let app = auth_routes()
        .layer(CookieManagerLayer::new())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}

//
// ROUTES
//

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/change-password", post(change_password))
        .route("/update-username", post(update_username))
        .route("/profile", get(get_profile))
        .route("/account", axum::routing::delete(delete_account))
}

//
// MODELS
//

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub expires_at: DateTime<Utc>,
}

//
// API TYPES
//

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

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUsernameRequest {
    pub new_username: String,
}

#[derive(Debug, Serialize)]
pub struct ProfileResponse {
    pub id: i64,
    pub username: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

//
// DOMAIN
//

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

//
// SESSION ID
//

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new() -> Self {
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let token: String = (0..64)
            .map(|_| {
                let idx = (rand::random::<u32>() as usize) % chars.len();
                chars.chars().nth(idx).unwrap()
            })
            .collect();

        SessionId(token)
    }
}

//
// ERRORS
//

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

    #[error("invalid username: {0}")]
    InvalidUsername(String),

    #[error("invalid password: {0}")]
    InvalidPassword(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::InvalidCredentials | AuthError::Unauthorized => StatusCode::UNAUTHORIZED,
            AuthError::UserAlreadyExists => StatusCode::CONFLICT,
            AuthError::SessionExpired => StatusCode::UNAUTHORIZED,
            AuthError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::InvalidUsername(_) | AuthError::InvalidPassword(_) => StatusCode::BAD_REQUEST,
        };
        (status, self.to_string()).into_response()
    }
}

//
// VALIDATION
//

fn validate_username(username: &str) -> Result<(), AuthError> {
    if username.len() < 3 {
        return Err(AuthError::InvalidUsername("username must be at least 3 characters".to_string()));
    }
    if username.len() > 50 {
        return Err(AuthError::InvalidUsername("username must be at most 50 characters".to_string()));
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(AuthError::InvalidUsername("username can only contain letters, numbers, underscores, and hyphens".to_string()));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.len() < 8 {
        return Err(AuthError::InvalidPassword("password must be at least 8 characters".to_string()));
    }
    if password.len() > 128 {
        return Err(AuthError::InvalidPassword("password must be at most 128 characters".to_string()));
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(AuthError::InvalidPassword("password must contain at least one uppercase letter".to_string()));
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(AuthError::InvalidPassword("password must contain at least one lowercase letter".to_string()));
    }
    if !password.chars().any(|c| !c.is_alphabetic()) {
        return Err(AuthError::InvalidPassword("password must contain at least one non-alphabetic character".to_string()));
    }
    Ok(())
}

//
// STATE
//

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

//
// HANDLERS
//

async fn authenticate_user(state: &AppState, cookies: &Cookies) -> Result<User, AuthError> {
    let session_cookie = cookies.get("session_id").ok_or(AuthError::Unauthorized)?;

    let session = sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = ?")
        .bind(session_cookie.value())
        .fetch_optional(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?
        .ok_or(AuthError::Unauthorized)?;

    if session.expires_at < Utc::now() {
        return Err(AuthError::SessionExpired);
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;

    Ok(user)
}

pub async fn signup(
    State(state): State<AppState>,
    Json(payload): Json<SignupRequest>,
) -> Result<StatusCode, AuthError> {
    validate_username(&payload.username)?;
    validate_password(&payload.password)?;
    create_user(&state, payload).await?;
    Ok(StatusCode::CREATED)
}

pub async fn login(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AuthError> {
    validate_username(&payload.username)?;
    validate_password(&payload.password)?;
    let user = verify_user(&state, payload).await?;

    let session = create_session(&state, user.id).await?;

    set_session_cookie(&cookies, &session.id);

    Ok(Json(AuthResponse {
        user_id: user.id,
        username: user.username,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<StatusCode, AuthError> {
    if let Some(cookie) = cookies.get("session_id") {
        delete_session(&state, cookie.value()).await?;
        clear_session_cookie(&cookies);
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn me(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<AuthResponse>, AuthError> {
    let session_cookie = cookies.get("session_id").ok_or(AuthError::Unauthorized)?;

    let session = sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE id = ?")
        .bind(session_cookie.value())
        .fetch_optional(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?
        .ok_or(AuthError::Unauthorized)?;

    if session.expires_at < Utc::now() {
        return Err(AuthError::SessionExpired);
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;

    Ok(Json(AuthResponse {
        user_id: user.id,
        username: user.username,
    }))
}

pub async fn change_password(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<StatusCode, AuthError> {
    let user = authenticate_user(&state, &cookies).await?;
    
    // Verify current password
    let current_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(user.id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    if !verify_password(&payload.current_password, &current_user.password_hash)? {
        return Err(AuthError::InvalidCredentials);
    }
    
    // Validate and hash new password
    validate_password(&payload.new_password)?;
    let new_hash = hash_password(&payload.new_password)?;
    
    // Update password
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(&new_hash)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    // Delete all sessions for security
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    clear_session_cookie(&cookies);
    
    Ok(StatusCode::OK)
}

pub async fn update_username(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(payload): Json<UpdateUsernameRequest>,
) -> Result<StatusCode, AuthError> {
    let user = authenticate_user(&state, &cookies).await?;
    
    validate_username(&payload.new_username)?;
    
    // Check if username is already taken
    let existing = sqlx::query("SELECT id FROM users WHERE username = ? AND id != ?")
        .bind(&payload.new_username)
        .bind(user.id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    if existing.is_some() {
        return Err(AuthError::UserAlreadyExists);
    }
    
    // Update username
    sqlx::query("UPDATE users SET username = ? WHERE id = ?")
        .bind(&payload.new_username)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    Ok(StatusCode::OK)
}

pub async fn get_profile(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<ProfileResponse>, AuthError> {
    let user = authenticate_user(&state, &cookies).await?;
    
    Ok(Json(ProfileResponse {
        id: user.id,
        username: user.username,
        created_at: user.created_at.to_rfc3339(),
    }))
}

pub async fn delete_account(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(payload): Json<DeleteAccountRequest>,
) -> Result<StatusCode, AuthError> {
    let user = authenticate_user(&state, &cookies).await?;
    
    // Verify password before deletion
    let current_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(user.id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    if !verify_password(&payload.password, &current_user.password_hash)? {
        return Err(AuthError::InvalidCredentials);
    }
    
    // Delete all sessions first
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    // Delete user
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    clear_session_cookie(&cookies);
    
    Ok(StatusCode::NO_CONTENT)
}

//
// COOKIE HELPERS
//

fn set_session_cookie(cookies: &Cookies, session_id: &str) {
    let cookie = Cookie::build(("session_id", session_id.to_string()))
        .http_only(true)
        .secure(false) // set true in production
        .same_site(tower_cookies::cookie::SameSite::Lax)
        .path("/")
        .build();

    cookies.add(cookie);
}

fn clear_session_cookie(cookies: &Cookies) {
    let cookie = Cookie::build(("session_id", ""))
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build();

    cookies.add(cookie);
}

//
// SERVICE LAYER
//

pub async fn create_user(state: &AppState, payload: SignupRequest) -> Result<(), AuthError> {
    let password_hash = hash_password(&payload.password)?;
    let created_at = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
    )
    .bind(&payload.username)
    .bind(&password_hash)
    .bind(&created_at)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            if let sqlx::Error::Database(db_err) = &err {
                if db_err.message().contains("UNIQUE constraint failed") {
                    return Err(AuthError::UserAlreadyExists);
                }
            }
            Err(AuthError::Internal)
        }
    }
}

pub async fn verify_user(state: &AppState, payload: LoginRequest) -> Result<User, AuthError> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?
        .ok_or(AuthError::InvalidCredentials)?;

    if verify_password(&payload.password, &user.password_hash)? {
        Ok(user)
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

pub async fn create_session(state: &AppState, user_id: i64) -> Result<Session, AuthError> {
    let expires_at = Utc::now() + Duration::days(7);

    for _ in 0..3 {
        let session_id = SessionId::new().0;

        let result = sqlx::query(
            "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
        )
        .bind(&session_id)
        .bind(user_id)
        .bind(expires_at.to_rfc3339())
        .execute(&state.db)
        .await;

        match result {
            Ok(_) => {
                return Ok(Session {
                    id: session_id,
                    user_id,
                    expires_at,
                });
            }
            Err(err) => {
                if let sqlx::Error::Database(db_err) = &err {
                    if db_err.message().contains("UNIQUE constraint failed") {
                        continue;
                    }
                }
                return Err(AuthError::Internal);
            }
        }
    }

    Err(AuthError::Internal)
}

pub async fn delete_session(state: &AppState, session_id: &str) -> Result<(), AuthError> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(session_id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;

    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, AuthError> {
    // Generate a random salt (16+ chars is sufficient)
    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let salt: String = (0..16)
        .map(|_| {
            let idx = (rand::random::<u32>() as usize) % chars.len();
            chars.chars().nth(idx).unwrap()
        })
        .collect();

    let salt = SaltString::encode_b64(salt.as_bytes()).map_err(|_| AuthError::Internal)?;

    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthError::Internal)?
        .to_string();

    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|_| AuthError::Internal)?;

    let argon2 = Argon2::default();

    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password_valid() {
        // Valid password: has upper, lower, non-alpha, and proper length
        assert!(validate_password("Password123!").is_ok());
        assert!(validate_password("MySecurePass@2024").is_ok());
        assert!(validate_password("Test_123").is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(validate_password("Short1!").is_err());
        assert!(validate_password("").is_err());
        assert!(validate_password("1234567").is_err());
    }

    #[test]
    fn test_validate_password_too_long() {
        let long_password = "A".repeat(129) + "1!";
        assert!(validate_password(&long_password).is_err());
    }

    #[test]
    fn test_validate_password_no_uppercase() {
        assert!(validate_password("password123!").is_err());
        assert!(validate_password("lowercaseonly123!").is_err());
    }

    #[test]
    fn test_validate_password_no_lowercase() {
        assert!(validate_password("PASSWORD123!").is_err());
        assert!(validate_password("UPPERCASEONLY123!").is_err());
    }

    #[test]
    fn test_validate_password_no_non_alpha() {
        assert!(validate_password("PasswordOnly").is_err());
        assert!(validate_password("NoSpecialChars").is_err());
    }

    #[test]
    fn test_validate_password_edge_cases() {
        // Exactly 8 characters
        assert!(validate_password("Pass123!").is_ok());
        // Exactly 128 characters
        let exactly_128 = "A".repeat(125) + "a1!";
        assert!(validate_password(&exactly_128).is_ok());
        // Unicode characters
        assert!(validate_password("Pässword123!").is_ok());
    }

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("testuser").is_ok());
        assert!(validate_username("test_user").is_ok());
        assert!(validate_username("test-user").is_ok());
        assert!(validate_username("TestUser123").is_ok());
    }

    #[test]
    fn test_validate_username_too_short() {
        assert!(validate_username("ab").is_err());
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long_username = "a".repeat(51);
        assert!(validate_username(&long_username).is_err());
    }

    #[test]
    fn test_validate_username_invalid_chars() {
        assert!(validate_username("test@user").is_err());
        assert!(validate_username("test user").is_err());
        assert!(validate_username("test.user").is_err());
        assert!(validate_username("test/user").is_err());
    }

    #[test]
    fn test_password_complexity_edge_cases() {
        // Password with only numbers and special chars (no letters)
        assert!(validate_password("12345678!").is_err());
        // Password with only uppercase and special chars (no lowercase)
        assert!(validate_password("PASSWORD!").is_err());
        // Password with only lowercase and special chars (no uppercase)
        assert!(validate_password("password!").is_err());
        // Valid password with all requirements
        assert!(validate_password("ValidPass123!").is_ok());
    }

    #[test]
    fn test_username_edge_cases() {
        // Username with numbers and underscores
        assert!(validate_username("user_123").is_ok());
        // Username with hyphens
        assert!(validate_username("test-user").is_ok());
        // Username at minimum length
        assert!(validate_username("abc").is_ok());
        // Username at maximum length
        let max_username = "a".repeat(50);
        assert!(validate_username(&max_username).is_ok());
    }
}
