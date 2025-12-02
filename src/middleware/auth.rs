use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    http::StatusCode,
};
use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};

use crate::structure::users::Claims;
use crate::utils::jwt::verify_jwt;

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthUser {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;
    
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("authorization")
            .ok_or(StatusCode::UNAUTHORIZED)?
            .to_str()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
            
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;
            
        let token_data: TokenData<Claims> =
            verify_jwt(token).map_err(|_| StatusCode::UNAUTHORIZED)?;
            
        Ok(AuthUser {
            user_id: token_data.claims.sub,
        })
    }
}

