// Enhanced Cargo.toml dependencies:
// [dependencies]
// tokio = { version = "1.0", features = ["full"] }
// warp = "0.3"
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// bcrypt = "0.15"
// uuid = { version = "1.0", features = ["v4"] }
// jsonwebtoken = "9.0"
// chrono = { version = "0.4", features = ["serde"] }
// sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "postgres", "chrono", "uuid"] }
// lettre = "0.11"
// rand = "0.8"
// tokio-cron-scheduler = "0.10"

use std::sync::Arc;
use warp::{Filter, Reply};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{DateTime, Utc, Duration};
use sqlx::{PgPool, Row};
use lettre::{Message, SmtpTransport, Transport, message::header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use tokio_cron_scheduler::{JobScheduler, Job};

// Enhanced User model
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub email_verification_token: Option<String>,
    pub password_reset_token: Option<String>,
    pub password_reset_expires: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Request/Response models
#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub token: Option<String>,
    pub user: Option<UserInfo>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
}

// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user id
    pub username: String,
    pub email: String,
    pub exp: usize,
}

// Configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_server: String,
    pub from_email: String,
    pub base_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://username:password@localhost/auth_db".to_string()),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "your-secret-key-here".to_string()),
            smtp_username: std::env::var("SMTP_USERNAME")
                .unwrap_or_else(|_| "your-email@gmail.com".to_string()),
            smtp_password: std::env::var("SMTP_PASSWORD")
                .unwrap_or_else(|_| "your-app-password".to_string()),
            smtp_server: std::env::var("SMTP_SERVER")
                .unwrap_or_else(|_| "smtp.gmail.com".to_string()),
            from_email: std::env::var("FROM_EMAIL")
                .unwrap_or_else(|_| "noreply@yourapp.com".to_string()),
            base_url: std::env::var("BASE_URL")
                .unwrap_or_else(|_| "http://localhost:3000_string()),
        }
    }
}

pub struct AuthService {
    db: PgPool,
    config: Config,
    mailer: SmtpTransport,
}

impl AuthService {
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        // Database connection
        let db = PgPool::connect(&config.database_url).await?;
        
        // Run migrations
        sqlx::migrate!("./migrations").run(&db).await?;

        // SMTP transport
        let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());
        let mailer = SmtpTransport::relay(&config.smtp_server)?
            .credentials(creds)
            .build();

        Ok(Self { db, config, mailer })
    }

    // Generate random token
    fn generate_token_string(&self) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    // Send email
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        let email = Message::builder()
            .from(self.config.from_email.parse()?)
            .to(to.parse()?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body.to_string())?;

        self.mailer.send(&email)?;
        Ok(())
    }

    pub async fn signup(&self, req: SignupRequest) -> Result<AuthResponse, Box<dyn std::error::Error>> {
        // Validate input
        if req.username.len() < 3 {
            return Ok(AuthResponse {
                success: false,
                message: "Username must be at least 3 characters long".to_string(),
                token: None,
                user: None,
            });
        }

        if req.password.len() < 6 {
            return Ok(AuthResponse {
                success: false,
                message: "Password must be at least 6 characters long".to_string(),
                token: None,
                user: None,
            });
        }

        if !req.email.contains('@') {
            return Ok(AuthResponse {
                success: false,
                message: "Invalid email format".to_string(),
                token: None,
                user: None,
            });
        }

        // Check if user already exists
        let existing_user = sqlx::query("SELECT id FROM users WHERE email = $1 OR username = $2")
            .bind(&req.email)
            .bind(&req.username)
            .fetch_optional(&self.db)
            .await?;

        if existing_user.is_some() {
            return Ok(AuthResponse {
                success: false,
                message: "User with this email or username already exists".to_string(),
                token: None,
                user: None,
            });
        }

        // Hash password
        let password_hash = hash(req.password, DEFAULT_COST)?;
        let verification_token = self.generate_token_string();
        let user_id = Uuid::new_v4();

        // Insert user
        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, email_verification_token, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#
        )
        .bind(&user_id)
        .bind(&req.username)
        .bind(&req.email)
        .bind(&password_hash)
        .bind(&verification_token)
        .bind(Utc::now())
        .bind(Utc::now())
        .execute(&self.db)
        .await?;

        // Send verification email
        let verification_url = format!("{}/verify-email?token={}", self.config.base_url, verification_token);
        let email_body = format!(
            r#"
            <h2>Welcome to Our App!</h2>
            <p>Please click the link below to verify your email address:</p>
            <a href="{}">Verify Email</a>
            <p>If you didn't create an account, please ignore this email.</p>
            "#,
            verification_url
        );

        if let Err(e) = self.send_email(&req.email, "Verify Your Email", &email_body).await {
            eprintln!("Failed to send verification email: {}", e);
        }

        Ok(AuthResponse {
            success: true,
            message: "User created successfully. Please check your email to verify your account.".to_string(),
            token: None,
            user: Some(UserInfo {
                id: user_id,
                username: req.username,
                email: req.email,
                email_verified: false,
            }),
        })
    }

    pub async fn verify_email(&self, req: VerifyEmailRequest) -> Result<ApiResponse, Box<dyn std::error::Error>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE email_verification_token = $1"
        )
        .bind(&req.token)
        .fetch_optional(&self.db)
        .await?;

        match user {
            Some(_) => {
                sqlx::query(
                    "UPDATE users SET email_verified = true, email_verification_token = NULL, updated_at = $1 WHERE email_verification_token = $2"
                )
                .bind(Utc::now())
                .bind(&req.token)
                .execute(&self.db)
                .await?;

                Ok(ApiResponse {
                    success: true,
                    message: "Email verified successfully".to_string(),
                })
            }
            None => Ok(ApiResponse {
                success: false,
                message: "Invalid verification token".to_string(),
            }),
        }
    }

    pub async fn login(&self, req: LoginRequest) -> Result<AuthResponse, Box<dyn std::error::Error>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(&req.email)
            .fetch_optional(&self.db)
            .await?;

        match user {
            Some(user) => {
                if !verify(&req.password, &user.password_hash)? {
                    return Ok(AuthResponse {
                        success: false,
                        message: "Invalid email or password".to_string(),
                        token: None,
                        user: None,
                    });
                }

                if !user.email_verified {
                    return Ok(AuthResponse {
                        success: false,
                        message: "Please verify your email before logging in".to_string(),
                        token: None,
                        user: None,
                    });
                }

                let token = self.generate_jwt_token(&user)?;

                Ok(AuthResponse {
                    success: true,
                    message: "Login successful".to_string(),
                    token: Some(token),
                    user: Some(UserInfo {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        email_verified: user.email_verified,
                    }),
                })
            }
            None => Ok(AuthResponse {
                success: false,
                message: "Invalid email or password".to_string(),
                token: None,
                user: None,
            }),
        }
    }

    pub async fn forgot_password(&self, req: ForgotPasswordRequest) -> Result<ApiResponse, Box<dyn std::error::Error>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(&req.email)
            .fetch_optional(&self.db)
            .await?;

        match user {
            Some(_) => {
                let reset_token = self.generate_token_string();
                let expires_at = Utc::now() + Duration::hours(1); // Token expires in 1 hour

                sqlx::query(
                    "UPDATE users SET password_reset_token = $1, password_reset_expires = $2, updated_at = $3 WHERE email = $4"
                )
                .bind(&reset_token)
                .bind(expires_at)
                .bind(Utc::now())
                .bind(&req.email)
                .execute(&self.db)
                .await?;

                // Send password reset email
                let reset_url = format!("{}/reset-password?token={}", self.config.base_url, reset_token);
                let email_body = format!(
                    r#"
                    <h2>Password Reset Request</h2>
                    <p>Click the link below to reset your password:</p>
                    <a href="{}">Reset Password</a>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request a password reset, please ignore this email.</p>
                    "#,
                    reset_url
                );

                if let Err(e) = self.send_email(&req.email, "Reset Your Password", &email_body).await {
                    eprintln!("Failed to send password reset email: {}", e);
                }

                Ok(ApiResponse {
                    success: true,
                    message: "Password reset link sent to your email".to_string(),
                })
            }
            None => {
                // Don't reveal whether email exists or not
                Ok(ApiResponse {
                    success: true,
                    message: "If an account with that email exists, a password reset link has been sent".to_string(),
                })
            }
        }
    }

    pub async fn reset_password(&self, req: ResetPasswordRequest) -> Result<ApiResponse, Box<dyn std::error::Error>> {
        if req.new_password.len() < 6 {
            return Ok(ApiResponse {
                success: false,
                message: "Password must be at least 6 characters long".to_string(),
            });
        }

        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires > $2"
        )
        .bind(&req.token)
        .bind(Utc::now())
        .fetch_optional(&self.db)
        .await?;

        match user {
            Some(_) => {
                let new_password_hash = hash(req.new_password, DEFAULT_COST)?;

                sqlx::query(
                    "UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL, updated_at = $2 WHERE password_reset_token = $3"
                )
                .bind(&new_password_hash)
                .bind(Utc::now())
                .bind(&req.token)
                .execute(&self.db)
                .await?;

                Ok(ApiResponse {
                    success: true,
                    message: "Password reset successfully".to_string(),
                })
            }
            None => Ok(ApiResponse {
                success: false,
                message: "Invalid or expired reset token".to_string(),
            }),
        }
    }

    fn generate_jwt_token(&self, user: &User) -> Result<String, jsonwebtoken::errors::Error> {
        let expiration = Utc::now()
            .checked_add_signed(Duration::hours(24))
            .expect("valid timestamp")
            .timestamp();

        let claims = Claims {
            sub: user.id.to_string(),
            username: user.username.clone(),
            email: user.email.clone(),
            exp: expiration as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_ref()),
        )
    }

    pub async fn verify_token(&self, token: &str) -> Result<Claims, String> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_ref()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|e| format!("Invalid token: {}", e))
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserInfo>, Box<dyn std::error::Error>> {
        let user_uuid = Uuid::parse_str(user_id)?;
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(user_uuid)
            .fetch_optional(&self.db)
            .await?;

        Ok(user.map(|u| UserInfo {
            id: u.id,
            username: u.username,
            email: u.email,
            email_verified: u.email_verified,
        }))
    }

    // Cleanup expired tokens (run periodically)
    pub async fn cleanup_expired_tokens(&self) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(
            "UPDATE users SET password_reset_token = NULL, password_reset_expires = NULL WHERE password_reset_expires < $1"
        )
        .bind(Utc::now())
        .execute(&self.db)
        .await?;

        Ok(())
    }
}

// API handlers
pub async fn signup_handler(
    req: SignupRequest,
    auth_service: Arc<AuthService>,
) -> Result<impl Reply, warp::Rejection> {
    match auth_service.signup(req).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            let error_response = AuthResponse {
                success: false,
                message: e.to_string(),
                token: None,
                user: None,
            };
            Ok(warp::reply::json(&error_response))
        }
    }
}

pub async fn login_handler(
    req: LoginRequest,
    auth_service: Arc<AuthService>,
) -> Result<impl Reply, warp::Rejection> {
    match auth_service.login(req).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            let error_response = AuthResponse {
                success: false,
                message: e.to_string(),
                token: None,
                user: None,
            };
            Ok(warp::reply::json(&error_response))
        }
    }
}

pub async fn verify_email_handler(
    req: VerifyEmailRequest,
    auth_service: Arc<AuthService>,
) -> Result<impl Reply, warp::Rejection> {
    match auth_service.verify_email(req).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            let error_response = ApiResponse {
                success: false,
                message: e.to_string(),
            };
            Ok(warp::reply::json(&error_response))
        }
    }
}

pub async fn forgot_password_handler(
    req: ForgotPasswordRequest,
    auth_service: Arc<AuthService>,
) -> Result<impl Reply, warp::Rejection> {
    match auth_service.forgot_password(req).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            let error_response = ApiResponse {
                success: false,
                message: e.to_string(),
            };
            Ok(warp::reply::json(&error_response))
        }
    }
}

pub async fn reset_password_handler(
    req: ResetPasswordRequest,
    auth_service: Arc<AuthService>,
) -> Result<impl Reply, warp::Rejection> {
    match auth_service.reset_password(req).await {
        Ok(response) => Ok(warp::reply::json(&response)),
        Err(e) => {
            let error_response = ApiResponse {
                success: false,
                message: e.to_string(),
            };
            Ok(warp::reply::json(&error_response))
        }
    }
}

pub async fn profile_handler(
    claims: Claims,
    auth_service: Arc<AuthService>,
) -> Result<impl Reply, warp::Rejection> {
    match auth_service.get_user_by_id(&claims.sub).await {
        Ok(Some(user)) => Ok(warp::reply::json(&user)),
        Ok(None) => {
            let error = serde_json::json!({
                "success": false,
                "message": "User not found"
            });
            Ok(warp::reply::json(&error))
        }
        Err(e) => {
            let error = serde_json::json!({
                "success": false,
                "message": e.to_string()
            });
            Ok(warp::reply::json(&error))
        }
    }
}

// Authentication middleware
pub fn with_auth(
    auth_service: Arc<AuthService>,
) -> impl Filter<Extract = (Claims,), Error = warp::Rejection> + Clone {
    warp::header::<String>("authorization")
        .and_then(move |auth_header: String| {
            let auth_service = auth_service.clone();
            async move {
                if let Some(token) = auth_header.strip_prefix("Bearer ") {
                    match auth_service.verify_token(token).await {
                        Ok(claims) => Ok(claims),
                        Err(_) => Err(warp::reject::custom(AuthError::InvalidToken)),
                    }
                } else {
                    Err(warp::reject::custom(AuthError::MissingToken))
                }
            }
        })
}

// Custom error types
#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    MissingToken,
}

impl warp::reject::Reject for AuthError {}

// Database migrations (create migrations/001_initial.sql)
const INITIAL_MIGRATION: &str = r#"
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_verification_token ON users(email_verification_token);
CREATE INDEX idx_users_reset_token ON users(password_reset_token);
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let auth_service = Arc::new(AuthService::new(config).await?);

    // Setup cleanup scheduler
    let scheduler = JobScheduler::new().await?;
    let cleanup_service = auth_service.clone();
    scheduler.add(
        Job::new_async("0 0 * * * *", move |_uuid, _l| {
            let service = cleanup_service.clone();
            Box::pin(async move {
                if let Err(e) = service.cleanup_expired_tokens().await {
                    eprintln!("Cleanup error: {}", e);
                }
            })
        })?
    ).await?;
    scheduler.start().await?;

    // Routes
    let signup = warp::path("signup")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(signup_handler);

    let login = warp::path("login")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(login_handler);

    let verify_email = warp::path("verify-email")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(verify_email_handler);

    let forgot_password = warp::path("forgot-password")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(forgot_password_handler);

    let reset_password = warp::path("reset-password")
        .and(warp::post())
        .and(warp::body::json())
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(reset_password_handler);

    let profile = warp::path("profile")
        .and(warp::get())
        .and(with_auth(auth_service.clone()))
        .and(warp::any().map(move || auth_service.clone()))
        .and_then(profile_handler);

    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type", "authorization"])
        .allow_methods(vec!["GET", "POST", "PUT", "DELETE"]);

    let routes = signup
        .or(login)
        .or(verify_email)
        .or(forgot_password)
        .or(reset_password)
        .or(profile)
        .with(cors)
        .recover(handle_rejection);

    println!("Enhanced Auth Server running on http://localhost:3030");
    println!("Endpoints:");
    println!("  POST /signup - Create new user");
    println!("  POST /login - Login user");
    println!("  POST /verify-email - Verify email address");
    println!("  POST /forgot-password - Request password reset");
    println!("  POST /reset-password - Reset password with token");
    println!("  GET /profile - Get user profile (requires auth)");

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
    Ok(())
}

// Error handling
async fn handle_rejection(err: warp::Rejection) -> Result<impl Reply, std::convert::Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if let Some(AuthError::InvalidToken) = err.find() {
        code = warp::http::StatusCode::UNAUTHORIZED;
        message = "Invalid token";
    } else if let Some(AuthError::MissingToken) = err.find() {
        code = warp::http::StatusCode::UNAUTHORIZED;
        message = "Missing authorization token";
    } else {
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    let json = warp::reply::json(&serde_json::json!({
        "success": false,
        "message": message
    }));

    Ok(warp::reply::with_status(json, code))
}