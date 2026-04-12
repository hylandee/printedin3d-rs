use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteJournalMode};
use sqlx::SqlitePool;
use thiserror::Error;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tower_http::cors::CorsLayer;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
pub enum UserRole {
    Customer,
    Operator,
    Admin,
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::Customer
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let connect_opts = SqliteConnectOptions::new()
        .filename("auth.db")
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5));

    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_opts)
        .await
        .expect("db connect failed");

    // Initialize database schema
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Customer',
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

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS filaments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            surcharge REAL NOT NULL DEFAULT 0.0,
            image_url TEXT
        )",
    )
    .execute(&db)
    .await
    .expect("failed to create filaments table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            base_price REAL NOT NULL,
            image_url TEXT,
            created_at TEXT NOT NULL
        )",
    )
    .execute(&db)
    .await
    .expect("failed to create products table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending_payment',
            total_amount REAL NOT NULL,
            queue_position INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
    )
    .execute(&db)
    .await
    .expect("failed to create orders table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            filament_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (filament_id) REFERENCES filaments(id)
        )",
    )
    .execute(&db)
    .await
    .expect("failed to create order_items table");

    // Insert default filaments (material + color combinations)
    sqlx::query(
        "INSERT OR IGNORE INTO filaments (name, surcharge, image_url) VALUES 
         ('White PLA Basic', 0.0, 'https://example.com/images/filaments/white-pla-basic.jpg'),
         ('Black PLA Basic', 0.0, 'https://example.com/images/filaments/black-pla-basic.jpg'),
         ('Gray PLA Basic', 0.0, 'https://example.com/images/filaments/gray-pla-basic.jpg'),
         ('Blue PLA Basic', 0.0, 'https://example.com/images/filaments/blue-pla-basic.jpg'),
         ('Red PLA Basic', 0.0, 'https://example.com/images/filaments/red-pla-basic.jpg'),
         ('Green PLA Basic', 0.0, 'https://example.com/images/filaments/green-pla-basic.jpg'),
         ('Yellow PLA Basic', 0.0, 'https://example.com/images/filaments/yellow-pla-basic.jpg'),
         ('White PLA Matte', 0.0, 'https://example.com/images/filaments/white-pla-matte.jpg'),
         ('Black PLA Matte', 0.0, 'https://example.com/images/filaments/black-pla-matte.jpg'),
         ('Gray PLA Matte', 0.0, 'https://example.com/images/filaments/gray-pla-matte.jpg'),
         ('Blue PLA Matte', 0.0, 'https://example.com/images/filaments/blue-pla-matte.jpg'),
         ('Red PLA Matte', 0.0, 'https://example.com/images/filaments/red-pla-matte.jpg'),
         ('Green PLA Matte', 0.0, 'https://example.com/images/filaments/green-pla-matte.jpg'),
         ('Yellow PLA Matte', 0.0, 'https://example.com/images/filaments/yellow-pla-matte.jpg'),
         ('White PLA Silk', 3.0, 'https://example.com/images/filaments/white-pla-silk.jpg'),
         ('Black PLA Silk', 3.0, 'https://example.com/images/filaments/black-pla-silk.jpg'),
         ('Gray PLA Silk', 3.0, 'https://example.com/images/filaments/gray-pla-silk.jpg'),
         ('Blue PLA Silk', 3.0, 'https://example.com/images/filaments/blue-pla-silk.jpg'),
         ('Red PLA Silk', 3.0, 'https://example.com/images/filaments/red-pla-silk.jpg'),
         ('Green PLA Silk', 3.0, 'https://example.com/images/filaments/green-pla-silk.jpg'),
         ('Yellow PLA Silk', 3.0, 'https://example.com/images/filaments/yellow-pla-silk.jpg'),
         ('Orange PLA Silk', 3.0, 'https://example.com/images/filaments/orange-pla-silk.jpg'),
         ('Purple PLA Silk', 3.0, 'https://example.com/images/filaments/purple-pla-silk.jpg'),
         ('Pink PLA Silk', 3.0, 'https://example.com/images/filaments/pink-pla-silk.jpg'),
         ('Brown PLA Silk', 3.0, 'https://example.com/images/filaments/brown-pla-silk.jpg'),
         ('Beige PLA Silk', 3.0, 'https://example.com/images/filaments/beige-pla-silk.jpg'),
         ('Marble PLA Silk', 3.0, 'https://example.com/images/filaments/marble-pla-silk.jpg'),
         ('White PLA Glow', 3.0, 'https://example.com/images/filaments/white-pla-glow.jpg'),
         ('Black PLA Glow', 3.0, 'https://example.com/images/filaments/black-pla-glow.jpg'),
         ('Gray PLA Glow', 3.0, 'https://example.com/images/filaments/gray-pla-glow.jpg'),
         ('Blue PLA Glow', 3.0, 'https://example.com/images/filaments/blue-pla-glow.jpg'),
         ('Red PLA Glow', 3.0, 'https://example.com/images/filaments/red-pla-glow.jpg'),
         ('Green PLA Glow', 3.0, 'https://example.com/images/filaments/green-pla-glow.jpg'),
         ('Yellow PLA Glow', 3.0, 'https://example.com/images/filaments/yellow-pla-glow.jpg'),
         ('Orange PLA Glow', 3.0, 'https://example.com/images/filaments/orange-pla-glow.jpg'),
         ('Purple PLA Glow', 3.0, 'https://example.com/images/filaments/purple-pla-glow.jpg'),
         ('Pink PLA Glow', 3.0, 'https://example.com/images/filaments/pink-pla-glow.jpg'),
         ('Brown PLA Glow', 3.0, 'https://example.com/images/filaments/brown-pla-glow.jpg'),
         ('Beige PLA Glow', 3.0, 'https://example.com/images/filaments/beige-pla-glow.jpg'),
         ('Marble PLA Glow', 3.0, 'https://example.com/images/filaments/marble-pla-glow.jpg')"
    )
    .execute(&db)
    .await
    .expect("failed to insert default filaments");

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
        .route("/api/signup", post(signup))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/change-password", post(change_password))
        .route("/api/update-username", post(update_username))
        .route("/api/profile", get(get_profile))
        .route("/api/account", axum::routing::delete(delete_account))
        // Product routes
        .route("/api/products", get(get_products))
        .route("/api/products", post(create_product))
        .route("/api/products/{id}/image", put(update_product_image))
        // Filament routes
        .route("/api/filaments", get(get_filaments))
        .route("/api/filaments", post(create_filament))
        .route("/api/filaments/{id}/image", put(update_filament_image))
        // Order routes
        .route("/api/orders", get(get_orders))
        .route("/api/orders", post(create_order))
        .route("/api/orders/{id}/status", put(update_order_status))
        // Queue route
        .route("/api/queue", get(get_queue))
        .route("/api/orders/{id}/queue/move-up", put(move_order_up))
        .route("/api/orders/{id}/queue/move-down", put(move_order_down))
        // User management (Admin only)
        .route("/api/users", get(get_users))
        .route("/api/users/{id}/role", put(update_user_role))
}

//
// MODELS
//

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Filament {
    pub id: i64,
    pub name: String,
    pub surcharge: f64,
    pub image_url: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Product {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub base_price: f64,
    pub image_url: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Order {
    pub id: i64,
    pub user_id: i64,
    pub status: String,
    pub total_amount: f64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct OrderItem {
    pub id: i64,
    pub order_id: i64,
    pub product_id: i64,
    pub filament_id: i64,
    pub quantity: i32,
    pub unit_price: f64,
}

//
// API TYPES
//

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: UserRole,
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
    pub role: UserRole,
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
    pub role: UserRole,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateProductRequest {
    pub name: String,
    pub description: Option<String>,
    pub base_price: f64,
    pub image_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateFilamentRequest {
    pub name: String,
    pub surcharge: f64,
    pub image_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProductImageRequest {
    pub image_url: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrderStatusRequest {
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFilamentImageRequest {
    pub image_url: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRoleRequest {
    pub role: UserRole,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrderItemRequest {
    pub product_id: i64,
    pub filament_id: i64,
    pub quantity: i32,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrderRequest {
    pub items: Vec<CreateOrderItemRequest>,
}

#[derive(Debug, Serialize)]
pub struct OrderWithItems {
    pub id: i64,
    pub user_id: i64,
    pub status: String,
    pub total_amount: f64,
    pub created_at: String,
    pub updated_at: String,
    pub items: Vec<OrderItemWithProduct>,
}

#[derive(Debug, Serialize)]
pub struct OrderItemWithProduct {
    pub id: i64,
    pub product_id: i64,
    pub product_name: String,
    pub filament_name: String,
    pub quantity: i32,
    pub unit_price: f64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct UserSummary {
    pub id: i64,
    pub username: String,
    pub role: UserRole,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct QueueItem {
    pub position: i32,
    pub total_items: i32,
    pub is_current_user: bool,
}

//
// DOMAIN
//

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub username: String,
    pub role: UserRole,
}

impl From<User> for AuthenticatedUser {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            role: user.role,
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

impl UserRole {
    fn level(&self) -> i32 {
        match self {
            UserRole::Customer => 1,
            UserRole::Operator => 2,
            UserRole::Admin => 3,
        }
    }
    
    fn has_minimum_role(&self, required: &UserRole) -> bool {
        self.level() >= required.level()
    }
}

async fn require_minimum_role(
    state: &AppState,
    cookies: &Cookies,
    required_role: UserRole,
) -> Result<AuthenticatedUser, AuthError> {
    let user = authenticate_user(state, cookies).await?;
    
    if user.role.has_minimum_role(&required_role) {
        Ok(user.into())
    } else {
        Err(AuthError::Unauthorized)
    }
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
        role: user.role,
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
        role: user.role,
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
        role: user.role,
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
// PRODUCT HANDLERS
//

pub async fn get_products(
    State(state): State<AppState>,
) -> Result<Json<Vec<Product>>, AuthError> {
    let products = sqlx::query_as::<_, Product>("SELECT * FROM products ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;

    Ok(Json(products))
}

pub async fn create_product(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(payload): Json<CreateProductRequest>,
) -> Result<Json<Product>, AuthError> {
    // Only operators and admins can create products
    require_minimum_role(&state, &cookies, UserRole::Operator).await?;

    let created_at = Utc::now().to_rfc3339();

    let product = sqlx::query_as::<_, Product>(
        "INSERT INTO products (name, description, base_price, image_url, created_at) VALUES (?, ?, ?, ?, ?) RETURNING *",
    )
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(payload.base_price)
    .bind(&payload.image_url)
    .bind(&created_at)
    .fetch_one(&state.db)
    .await
    .map_err(|_| AuthError::Internal)?;

    Ok(Json(product))
}

pub async fn update_product_image(
    State(state): State<AppState>,
    Path(product_id): Path<i64>,
    cookies: Cookies,
    Json(payload): Json<UpdateProductImageRequest>,
) -> Result<StatusCode, AuthError> {
    // Only admins can update product images
    require_minimum_role(&state, &cookies, UserRole::Admin).await?;
    
    sqlx::query("UPDATE products SET image_url = ? WHERE id = ?")
        .bind(&payload.image_url)
        .bind(product_id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    Ok(StatusCode::OK)
}

//
// FILAMENT HANDLERS
//

pub async fn get_filaments(
    State(state): State<AppState>,
) -> Result<Json<Vec<Filament>>, AuthError> {
    let filaments = sqlx::query_as::<_, Filament>("SELECT * FROM filaments ORDER BY name")
        .fetch_all(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;

    Ok(Json(filaments))
}

pub async fn create_filament(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(payload): Json<CreateFilamentRequest>,
) -> Result<Json<Filament>, AuthError> {
    // Only operators and admins can create filaments
    require_minimum_role(&state, &cookies, UserRole::Operator).await?;

    let filament = sqlx::query_as::<_, Filament>(
        "INSERT INTO filaments (name, surcharge, image_url) VALUES (?, ?, ?) RETURNING *",
    )
    .bind(&payload.name)
    .bind(payload.surcharge)
    .bind(&payload.image_url)
    .fetch_one(&state.db)
    .await
    .map_err(|_| AuthError::Internal)?;

    Ok(Json(filament))
}

pub async fn update_filament_image(
    State(state): State<AppState>,
    Path(filament_id): Path<i64>,
    cookies: Cookies,
    Json(payload): Json<UpdateFilamentImageRequest>,
) -> Result<StatusCode, AuthError> {
    // Only admins can update filament images
    require_minimum_role(&state, &cookies, UserRole::Admin).await?;
    
    sqlx::query("UPDATE filaments SET image_url = ? WHERE id = ?")
        .bind(&payload.image_url)
        .bind(filament_id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    Ok(StatusCode::OK)
}

//
// ORDER HANDLERS
//

pub async fn get_orders(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<Vec<OrderWithItems>>, AuthError> {
    let user = authenticate_user(&state, &cookies).await?;
    
    let orders = if matches!(user.role, UserRole::Admin) {
        // Admins can see all orders
        sqlx::query_as::<_, Order>("SELECT * FROM orders ORDER BY created_at DESC")
            .fetch_all(&state.db)
            .await
    } else {
        // Customers can only see their own orders
        sqlx::query_as::<_, Order>("SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC")
            .bind(user.id)
            .fetch_all(&state.db)
            .await
    }
    .map_err(|_| AuthError::Internal)?;

    let mut orders_with_items = Vec::new();
    
    for order in orders {
        let items = sqlx::query_as::<_, (i64, i64, String, String, i32, f64)>(
            "SELECT oi.id, oi.product_id, p.name, f.name, oi.quantity, oi.unit_price FROM order_items oi JOIN products p ON oi.product_id = p.id JOIN filaments f ON oi.filament_id = f.id WHERE oi.order_id = ?"
        )
        .bind(order.id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?
        .into_iter()
        .map(|(id, product_id, product_name, filament_name, quantity, unit_price)| OrderItemWithProduct {
            id,
            product_id,
            product_name,
            filament_name,
            quantity,
            unit_price,
        })
        .collect();

        orders_with_items.push(OrderWithItems {
            id: order.id,
            user_id: order.user_id,
            status: order.status,
            total_amount: order.total_amount,
            created_at: order.created_at,
            updated_at: order.updated_at,
            items,
        });
    }

    Ok(Json(orders_with_items))
}

pub async fn create_order(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(payload): Json<CreateOrderRequest>,
) -> Result<Json<OrderWithItems>, AuthError> {
    let user = authenticate_user(&state, &cookies).await?;
    
    // Start transaction
    let mut tx = state.db.begin().await.map_err(|_| AuthError::Internal)?;
    
    let created_at = Utc::now();
    let updated_at = created_at;
    
    // Calculate total amount and validate items
    let mut total_amount = 0.0;
    let mut order_items_data = Vec::new();
    
    for item in &payload.items {
        // Get product base price
        let product = sqlx::query_as::<_, Product>("SELECT * FROM products WHERE id = ?")
            .bind(item.product_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| AuthError::Internal)?;
        
        // Get filament surcharge
        let filament = sqlx::query_as::<_, Filament>("SELECT * FROM filaments WHERE id = ?")
            .bind(item.filament_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| AuthError::Internal)?;
        
        let unit_price = product.base_price + filament.surcharge;
        let item_total = unit_price * item.quantity as f64;
        total_amount += item_total;
        
        order_items_data.push((product, filament, item.quantity, unit_price));
    }
    
    // Create order
    let order = sqlx::query_as::<_, Order>(
        "INSERT INTO orders (user_id, status, total_amount, created_at, updated_at) VALUES (?, 'pending_payment', ?, ?, ?) RETURNING *",
    )
    .bind(user.id)
    .bind(total_amount)
    .bind(created_at.to_rfc3339())
    .bind(updated_at.to_rfc3339())
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| AuthError::Internal)?;
    
    // Create order items
    let mut order_items_with_product = Vec::new();
    for (product, filament, quantity, unit_price) in order_items_data {
        let order_item = sqlx::query_as::<_, OrderItem>(
            "INSERT INTO order_items (order_id, product_id, filament_id, quantity, unit_price) VALUES (?, ?, ?, ?, ?) RETURNING *",
        )
        .bind(order.id)
        .bind(product.id)
        .bind(filament.id)
        .bind(quantity)
        .bind(unit_price)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| AuthError::Internal)?;
        
        order_items_with_product.push(OrderItemWithProduct {
            id: order_item.id,
            product_id: product.id,
            product_name: product.name,
            filament_name: filament.name,
            quantity,
            unit_price,
        });
    }
    
    tx.commit().await.map_err(|_| AuthError::Internal)?;
    
    Ok(Json(OrderWithItems {
        id: order.id,
        user_id: order.user_id,
        status: order.status,
        total_amount: order.total_amount,
        created_at: order.created_at,
        updated_at: order.updated_at,
        items: order_items_with_product,
    }))
}

pub async fn update_order_status(
    State(state): State<AppState>,
    Path(order_id): Path<i64>,
    cookies: Cookies,
    Json(payload): Json<UpdateOrderStatusRequest>,
) -> Result<StatusCode, AuthError> {
    // Operators and admins can update order status
    require_minimum_role(&state, &cookies, UserRole::Operator).await?;
    
    let updated_at = Utc::now().to_rfc3339();
    
    // Start transaction for atomic updates
    let mut tx = state.db.begin().await.map_err(|_| AuthError::Internal)?;
    
    // Update order status
    sqlx::query("UPDATE orders SET status = ?, updated_at = ? WHERE id = ?")
        .bind(&payload.status)
        .bind(&updated_at)
        .bind(order_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    // If status changed to 'in_queue', assign queue position
    if payload.status == "in_queue" {
        // Find the next available queue position
        let max_position: Option<(Option<i64>,)> = sqlx::query_as(
            "SELECT MAX(queue_position) FROM orders WHERE status = 'in_queue'"
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AuthError::Internal)?;
        
        let next_position = match max_position {
            Some((Some(max_pos),)) => max_pos + 1,
            _ => 1,
        };
        
        sqlx::query("UPDATE orders SET queue_position = ? WHERE id = ?")
            .bind(next_position)
            .bind(order_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| AuthError::Internal)?;
    }
    
    tx.commit().await.map_err(|_| AuthError::Internal)?;
    
    Ok(StatusCode::OK)
}

//
// QUEUE HANDLER
//

pub async fn get_queue(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<Vec<QueueItem>>, AuthError> {
    let current_user = authenticate_user(&state, &cookies).await?;
    
    // Get all orders in queue (paid but not yet completed)
    let queue_orders = sqlx::query_as::<_, (i64, i64)>(
        "SELECT id, user_id FROM orders WHERE status = 'in_queue' ORDER BY queue_position ASC"
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| AuthError::Internal)?;
    
    let mut queue_items = Vec::new();
    let mut position = 1;
    
    for (order_id, user_id) in queue_orders {
        // Count total items in this order
        let total_items: (i64,) = sqlx::query_as(
            "SELECT SUM(quantity) FROM order_items WHERE order_id = ?"
        )
        .bind(order_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
        
        queue_items.push(QueueItem {
            position,
            total_items: total_items.0 as i32,
            is_current_user: user_id == current_user.id,
        });
        
        position += 1;
    }
    
    Ok(Json(queue_items))
}

pub async fn move_order_up(
    State(state): State<AppState>,
    Path(order_id): Path<i64>,
    cookies: Cookies,
) -> Result<StatusCode, AuthError> {
    // Only operators and admins can manipulate the queue
    require_minimum_role(&state, &cookies, UserRole::Operator).await?;

    let mut tx = state.db.begin().await.map_err(|_| AuthError::Internal)?;

    // Get current order's queue position
    let current_order: Option<(i64,)> = sqlx::query_as(
        "SELECT queue_position FROM orders WHERE id = ? AND status = 'in_queue'"
    )
    .bind(order_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AuthError::Internal)?;

    let current_position = match current_order {
        Some((pos,)) => pos,
        None => return Err(AuthError::Unauthorized),
    };

    // Find the order immediately above this one
    let above_order: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM orders WHERE status = 'in_queue' AND queue_position < ? ORDER BY queue_position DESC LIMIT 1"
    )
    .bind(current_position)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AuthError::Internal)?;

    if let Some((above_order_id,)) = above_order {
        // Swap positions
        sqlx::query("UPDATE orders SET queue_position = ? WHERE id = ?")
            .bind(current_position)
            .bind(above_order_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| AuthError::Internal)?;

        sqlx::query("UPDATE orders SET queue_position = ? WHERE id = ?")
            .bind(current_position - 1)
            .bind(order_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| AuthError::Internal)?;
    }

    tx.commit().await.map_err(|_| AuthError::Internal)?;
    Ok(StatusCode::OK)
}

pub async fn move_order_down(
    State(state): State<AppState>,
    Path(order_id): Path<i64>,
    cookies: Cookies,
) -> Result<StatusCode, AuthError> {
    // Only operators and admins can manipulate the queue
    require_minimum_role(&state, &cookies, UserRole::Operator).await?;

    let mut tx = state.db.begin().await.map_err(|_| AuthError::Internal)?;

    // Get current order's queue position
    let current_order: Option<(i64,)> = sqlx::query_as(
        "SELECT queue_position FROM orders WHERE id = ? AND status = 'in_queue'"
    )
    .bind(order_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AuthError::Internal)?;

    let current_position = match current_order {
        Some((pos,)) => pos,
        None => return Err(AuthError::Unauthorized),
    };

    // Find the order immediately below this one
    let below_order: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM orders WHERE status = 'in_queue' AND queue_position > ? ORDER BY queue_position ASC LIMIT 1"
    )
    .bind(current_position)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AuthError::Internal)?;

    if let Some((below_order_id,)) = below_order {
        // Swap positions
        sqlx::query("UPDATE orders SET queue_position = ? WHERE id = ?")
            .bind(current_position)
            .bind(below_order_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| AuthError::Internal)?;

        sqlx::query("UPDATE orders SET queue_position = ? WHERE id = ?")
            .bind(current_position + 1)
            .bind(order_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| AuthError::Internal)?;
    }

    tx.commit().await.map_err(|_| AuthError::Internal)?;
    Ok(StatusCode::OK)
}

//
// USER MANAGEMENT HANDLERS
//

pub async fn get_users(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<Vec<UserSummary>>, AuthError> {
    // Only admins can view all users
    require_minimum_role(&state, &cookies, UserRole::Admin).await?;
    
    let users = sqlx::query_as::<_, UserSummary>("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    Ok(Json(users))
}

pub async fn update_user_role(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
    cookies: Cookies,
    Json(payload): Json<UpdateUserRoleRequest>,
) -> Result<StatusCode, AuthError> {
    // Only admins can change user roles
    require_minimum_role(&state, &cookies, UserRole::Admin).await?;
    
    // Prevent admin from demoting themselves
    let current_user = authenticate_user(&state, &cookies).await?;
    if current_user.id == user_id && matches!(payload.role, UserRole::Customer | UserRole::Operator) {
        return Err(AuthError::Unauthorized);
    }
    
    sqlx::query("UPDATE users SET role = ? WHERE id = ?")
        .bind(&payload.role)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| AuthError::Internal)?;
    
    Ok(StatusCode::OK)
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
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(&payload.username)
    .bind(&password_hash)
    .bind(&payload.role)
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
