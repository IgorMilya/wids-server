use mongodb::bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[allow(dead_code)] 
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime,
    pub created_at: DateTime,
    pub revoked: bool,
    pub device_info: Option<String>,
}

