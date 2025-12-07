use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Collection;

use crate::{
    db::{get_database, get_collection, refresh_tokens},
    middleware::auth::AuthUser,
    structure::profile::{UpdateProfileRequest, UserProfile, UserProfileResponse},
    structure::users::{ChangePasswordRequest, ChangeUsernameRequest, User},
    utils::{error_response, jwt, password, success_response},
};

pub async fn get_user_profile(user: AuthUser) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let profiles: Collection<UserProfile> = get_collection(&db, "UserProfiles");

    match profiles.find_one(doc! { "user_id": &user.user_id }).await {
        Ok(Some(profile)) => {
            Json(UserProfileResponse {
                id: profile.id.to_hex(),
                profiling_preference: profile.profiling_preference,
                speed_network_preference: profile.speed_network_preference,
                confidence_level: profile.confidence_level,
                profile_type: profile.profile_type,
                preferred_authentication: profile.preferred_authentication,
                min_signal_strength: profile.min_signal_strength,
                max_risk_level: profile.max_risk_level,
            })
            .into_response()
        }
        Ok(None) => {
            // Create default profile if none exists
            let default_profile = UserProfile {
                id: ObjectId::new(),
                user_id: user.user_id.clone(),
                profiling_preference: "balanced".to_string(),
                speed_network_preference: "medium".to_string(),
                confidence_level: "medium".to_string(),
                profile_type: "personal".to_string(),
                preferred_authentication: vec!["WPA3".to_string(), "WPA2".to_string()],
                min_signal_strength: Some(50),
                max_risk_level: Some("M".to_string()),
            };

            let profiles_doc: Collection<mongodb::bson::Document> =
                get_collection(&db, "UserProfiles");
            let new_doc = doc! {
                "user_id": &user.user_id,
                "profiling_preference": &default_profile.profiling_preference,
                "speed_network_preference": &default_profile.speed_network_preference,
                "confidence_level": &default_profile.confidence_level,
                "profile_type": &default_profile.profile_type,
                "preferred_authentication": &default_profile.preferred_authentication,
                "min_signal_strength": &default_profile.min_signal_strength,
                "max_risk_level": &default_profile.max_risk_level,
            };

            if let Err(e) = profiles_doc.insert_one(new_doc).await {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
            }

            Json(UserProfileResponse {
                id: default_profile.id.to_hex(),
                profiling_preference: default_profile.profiling_preference,
                speed_network_preference: default_profile.speed_network_preference,
                confidence_level: default_profile.confidence_level,
                profile_type: default_profile.profile_type,
                preferred_authentication: default_profile.preferred_authentication,
                min_signal_strength: default_profile.min_signal_strength,
                max_risk_level: default_profile.max_risk_level,
            })
            .into_response()
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn update_user_profile(
    user: AuthUser,
    Json(payload): Json<UpdateProfileRequest>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let profiles: Collection<mongodb::bson::Document> = get_collection(&db, "UserProfiles");

    let mut update_doc = doc! {};

    if let Some(ref val) = payload.profiling_preference {
        update_doc.insert("profiling_preference", val);
    }
    if let Some(ref val) = payload.speed_network_preference {
        update_doc.insert("speed_network_preference", val);
    }
    if let Some(ref val) = payload.confidence_level {
        update_doc.insert("confidence_level", val);
    }
    if let Some(ref val) = payload.profile_type {
        update_doc.insert("profile_type", val);
    }
    if let Some(ref val) = payload.preferred_authentication {
        update_doc.insert("preferred_authentication", val);
    }
    if let Some(val) = payload.min_signal_strength {
        update_doc.insert("min_signal_strength", val);
    }
    if let Some(ref val) = payload.max_risk_level {
        update_doc.insert("max_risk_level", val);
    }

    if update_doc.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "No fields to update");
    }

    let filter = doc! { "user_id": &user.user_id };
    let update = doc! { "$set": update_doc };

    match profiles.update_one(filter, update).await {
        Ok(result) if result.matched_count > 0 => {
            success_response(StatusCode::OK, serde_json::json!({"status": "profile_updated"}))
        }
        Ok(_) => {
            // Create profile if it doesn't exist
            let default_profile = doc! {
                "user_id": &user.user_id,
                "profiling_preference": payload.profiling_preference.unwrap_or_else(|| "balanced".to_string()),
                "speed_network_preference": payload.speed_network_preference.unwrap_or_else(|| "medium".to_string()),
                "confidence_level": payload.confidence_level.unwrap_or_else(|| "medium".to_string()),
                "profile_type": payload.profile_type.unwrap_or_else(|| "personal".to_string()),
                "preferred_authentication": payload.preferred_authentication.unwrap_or_else(|| vec!["WPA3".to_string(), "WPA2".to_string()]),
                "min_signal_strength": payload.min_signal_strength.unwrap_or(50),
                "max_risk_level": payload.max_risk_level.unwrap_or_else(|| "M".to_string()),
            };
            if let Err(e) = profiles.insert_one(default_profile).await {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
            }
            success_response(StatusCode::OK, serde_json::json!({"status": "profile_created"}))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn change_username_handler(
    user: AuthUser,
    Json(payload): Json<ChangeUsernameRequest>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let users: Collection<mongodb::bson::Document> = get_collection(&db, "Users");

    let obj_id = match ObjectId::parse_str(&user.user_id) {
        Ok(id) => id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid user ID"),
    };

    match users
        .update_one(
            doc! { "_id": obj_id },
            doc! { "$set": { "username": &payload.username } },
        )
        .await
    {
        Ok(result) if result.matched_count > 0 => {
            // Generate new tokens with updated username
            let new_token = jwt::create_jwt(&user.user_id, Some(&payload.username));
            let new_refresh_token = jwt::create_refresh_token(&user.user_id, Some(&payload.username));
            
            // Revoke old refresh token and store new one
            if let Err(e) = refresh_tokens::revoke_all_refresh_tokens_for_user(&db, &user.user_id).await {
                eprintln!("Failed to revoke old refresh tokens after username change: {:?}", e);
            }
            
            if let Err(e) = refresh_tokens::store_refresh_token(&db, &user.user_id, &new_refresh_token).await {
                eprintln!("Failed to store new refresh token after username change: {:?}", e);
            }
            
            success_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "username_updated",
                    "username": payload.username,
                    "token": new_token,
                    "refresh_token": new_refresh_token
                }),
            )
        }
        Ok(_) => error_response(StatusCode::NOT_FOUND, "User not found"),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn change_password_handler(
    user: AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let users: Collection<User> = get_collection(&db, "Users");

    let obj_id = match ObjectId::parse_str(&user.user_id) {
        Ok(id) => id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Invalid user ID"),
    };

    let user_doc = match users.find_one(doc! { "_id": obj_id }).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "User not found"),
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    // Verify current password
    let valid = match password::verify_password(&payload.current_password, &user_doc.password_hash) {
        Ok(is_valid) => is_valid,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password verification failed",
            );
        }
    };

    if !valid {
        return error_response(StatusCode::UNAUTHORIZED, "Invalid current password");
    }

    // Hash new password
    let password_hash = match password::hash_password(&payload.new_password) {
        Ok(hash) => hash,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to hash password",
            );
        }
    };

    // Update password
    match users
        .update_one(
            doc! { "_id": obj_id },
            doc! { "$set": { "password_hash": &password_hash } },
        )
        .await
    {
        Ok(result) if result.matched_count > 0 => {
            // Revoke all refresh tokens for security (user should re-authenticate)
            match refresh_tokens::revoke_all_refresh_tokens_for_user(&db, &user.user_id).await {
                Ok(count) => {
                    eprintln!(
                        "Password changed: Revoked {} refresh token(s) for user {}",
                        count, user.user_id
                    );
                }
                Err(e) => {
                    eprintln!(
                        "Failed to revoke refresh tokens after password change: {:?}",
                        e
                    );
                }
            }

            success_response(
                StatusCode::OK,
                serde_json::json!({"status": "password_updated"}),
            )
        }
        Ok(_) => error_response(StatusCode::NOT_FOUND, "User not found"),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

