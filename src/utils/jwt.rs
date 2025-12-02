use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::Result as JWTResult,
};
use chrono::{Duration, Utc};

use crate::config::EnvVars;
use crate::structure::users::Claims;

pub fn create_jwt(user_id: &str, username: Option<&String>) -> String {
    let secret = EnvVars::jwt_secret();
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration as usize,
        username: username.cloned(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("Failed to create token")
}

pub fn create_refresh_token(user_id: &str, username: Option<&String>) -> String {
    let secret = EnvVars::jwt_secret();
    let expiration = Utc::now()
        .checked_add_signed(Duration::days(30))
        .expect("valid timestamp")
        .timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration as usize,
        username: username.cloned(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("Failed to create refresh token")
}

pub fn verify_jwt(token: &str) -> JWTResult<TokenData<Claims>> {
    let secret = EnvVars::jwt_secret();
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
}

