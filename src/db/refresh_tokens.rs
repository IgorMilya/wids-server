use mongodb::{
    bson::{doc, DateTime},
    Collection, Database,
};
use mongodb::bson::Document;
use futures::TryStreamExt;
use chrono::{Duration, Utc};

use crate::utils::password;

fn hash_refresh_token(token: &str) -> String {
    password::hash_password(token).expect("Failed to hash refresh token")
}

fn verify_refresh_token_hash(token: &str, hash: &str) -> bool {
    password::verify_password(token, hash).unwrap_or(false)
}

pub async fn store_refresh_token(
    db: &Database,
    user_id: &str,
    token: &str,
) -> Result<(), mongodb::error::Error> {
    let tokens_collection: Collection<Document> = db.collection("RefreshTokens");

    let token_hash = hash_refresh_token(token);

    let expires_at = Utc::now()
        .checked_add_signed(Duration::days(30))
        .expect("valid timestamp");

    let token_doc = doc! {
        "user_id": user_id,
        "token_hash": token_hash,
        "expires_at": DateTime::from_millis(expires_at.timestamp_millis()),
        "created_at": DateTime::now(),
        "revoked": false,
        "device_info": None::<String>,
    };

    tokens_collection.insert_one(token_doc).await?;
    Ok(())
}

pub async fn verify_refresh_token_in_db(
    db: &Database,
    user_id: &str,
    token: &str,
) -> Result<bool, mongodb::error::Error> {
    let tokens_collection: Collection<Document> = db.collection("RefreshTokens");

    let filter = doc! {
        "user_id": user_id,
        "revoked": false,
        "expires_at": { "$gt": DateTime::now() }, 
    };

    let mut cursor = tokens_collection.find(filter).await?;

    while let Some(doc) = cursor.try_next().await? {
        if let Some(token_hash) = doc.get("token_hash").and_then(|v| v.as_str()) {
            if verify_refresh_token_hash(token, token_hash) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub async fn revoke_refresh_token(
    db: &Database,
    user_id: &str,
    token: &str,
) -> Result<bool, mongodb::error::Error> {
    let tokens_collection: Collection<Document> = db.collection("RefreshTokens");

    let filter = doc! {
        "user_id": user_id,
        "revoked": false,
    };

    let mut cursor = tokens_collection.find(filter).await?;

    while let Some(doc) = cursor.try_next().await? {
        if let Some(token_hash) = doc.get("token_hash").and_then(|v| v.as_str()) {
            if verify_refresh_token_hash(token, token_hash) {
                if let Some(id) = doc.get("_id").and_then(|v| v.as_object_id()) {
                    let update = doc! {
                        "$set": {
                            "revoked": true,
                        }
                    };
                    tokens_collection.update_one(doc! { "_id": id }, update).await?;
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

pub async fn revoke_all_refresh_tokens_for_user(
    db: &Database,
    user_id: &str,
) -> Result<u64, mongodb::error::Error> {
    let tokens_collection: Collection<Document> = db.collection("RefreshTokens");

    let filter = doc! {
        "user_id": user_id,
        "revoked": false,
    };

    let update = doc! {
        "$set": {
            "revoked": true,
        }
    };

    let result = tokens_collection.update_many(filter, update).await?;
    Ok(result.modified_count)
}

