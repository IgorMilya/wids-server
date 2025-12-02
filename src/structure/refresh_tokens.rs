use mongodb::bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[allow(dead_code)] // Used internally in db/refresh_tokens.rs but not directly in handlers
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: String,
    pub token_hash: String, // Hashed refresh token (never store plaintext)
    pub expires_at: DateTime,
    pub created_at: DateTime,
    pub revoked: bool,
    pub device_info: Option<String>,
}

