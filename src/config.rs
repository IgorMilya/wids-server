use std::env;
use std::time::Duration as StdDuration;

/// Environment variable names
pub struct EnvVars;

impl EnvVars {
    pub fn mongo_db_url() -> String {
        env::var("MONGO_DB_URL")
            .expect("MONGO_DB_URL not set in environment variables")
    }

    pub fn jwt_secret() -> String {
        env::var("JWT_SECRET").expect("JWT_SECRET not set")
    }

    pub fn smtp_user() -> String {
        env::var("SMTP_USER").expect("SMTP_USER not set")
    }

    pub fn smtp_pass() -> String {
        env::var("SMTP_PASS").expect("SMTP_PASS not set")
    }

    pub fn smtp_from() -> String {
        env::var("SMTP_FROM")
            .unwrap_or_else(|_| Self::smtp_user())
    }

    pub fn recaptcha_secret() -> Result<String, String> {
        env::var("RECAPTCHA_SECRET")
            .map_err(|_| "RECAPTCHA_SECRET not set".to_string())
    }
}

/// Application constants
pub struct Constants;

impl Constants {
    /// Maximum registration attempts per IP
    pub const MAX_REGISTRATION_ATTEMPTS: usize = 5;
    
    /// Time window for rate limiting (1 hour)
    pub const RATE_LIMIT_WINDOW: StdDuration = StdDuration::from_secs(60 * 60);
    
    /// Database name
    pub const DB_NAME: &'static str = "WISP-APP";
    
    /// SMTP server
    pub const SMTP_SERVER: &'static str = "smtp.gmail.com";
    
    /// reCAPTCHA API endpoint
    pub const RECAPTCHA_VERIFY_URL: &'static str = "https://www.google.com/recaptcha/api/siteverify";
    
    /// Email sender name
    pub const EMAIL_SENDER_NAME: &'static str = "wids";
}

