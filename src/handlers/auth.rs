use axum::{
    extract::{ConnectInfo, Json},
    http::StatusCode,
    response::IntoResponse,
};
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Collection;
use std::net::SocketAddr;

use crate::{
    db::{get_database, get_collection, refresh_tokens},
    middleware::auth::AuthUser,
    structure::users::{
        LoginRequest, LoginResponse,
        LogoutRequest, RefreshTokenRequest, RefreshTokenResponse, RegisterRequest,
        ResendVerificationRequest, ResetPasswordConfirmRequest, ResetPasswordRequestRequest,
        User, VerifyEmailRequest,
    },
    utils::{
        code::generate_code,
        email::send_email,
        error_response, jwt, password, rate_limit, recaptcha, success_response,
    },
};

pub async fn login_handler(Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    if let Err(err) = recaptcha::ensure_recaptcha(&payload.captcha_token).await {
        return err;
    }

    let db = match get_database().await {
        Ok(db) => db,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            )
        }
    };

    let users: Collection<User> = get_collection(&db, "Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => {
            return error_response(StatusCode::UNAUTHORIZED, "Invalid credentials");
        }
    };

    if !user.is_verified {
        return error_response(StatusCode::FORBIDDEN, "Email not verified");
    }

    let valid = match password::verify_password(&payload.password, &user.password_hash) {
        Ok(is_valid) => is_valid,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password verification failed",
            );
        }
    };

    if !valid {
        return error_response(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }

    let token = jwt::create_jwt(&user.id.to_hex(), user.username.as_ref());
    let refresh_token = jwt::create_refresh_token(&user.id.to_hex(), user.username.as_ref());

    // Store refresh token in database
    if let Err(e) = refresh_tokens::store_refresh_token(&db, &user.id.to_hex(), &refresh_token).await
    {
        eprintln!("Failed to store refresh token: {:?}", e);
    }

    success_response(
        StatusCode::OK,
        LoginResponse {
            token,
            refresh_token,
            user_id: user.id.to_hex(),
            username: user.username.clone(),
        },
    )
}

pub async fn refresh_token_handler(Json(payload): Json<RefreshTokenRequest>) -> impl IntoResponse {
    // Verify the refresh token signature first
    let token_data = match jwt::verify_jwt(&payload.refresh_token) {
        Ok(data) => data,
        Err(_) => {
            return error_response(StatusCode::UNAUTHORIZED, "Invalid refresh token");
        }
    };

    let user_id = token_data.claims.sub.clone();
    let username = token_data.claims.username.clone();

    // Check database connection
    let db = match get_database().await {
        Ok(db) => db,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            );
        }
    };

    // Verify refresh token exists in database and is not revoked
    match refresh_tokens::verify_refresh_token_in_db(&db, &user_id, &payload.refresh_token).await {
        Ok(is_valid) if !is_valid => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "Refresh token revoked or not found",
            );
        }
        Err(e) => {
            eprintln!("Failed to verify refresh token in DB: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to verify refresh token",
            );
        }
        _ => {} // Token is valid
    }

    // Find and revoke the old refresh token
    if let Err(e) = refresh_tokens::revoke_refresh_token(&db, &user_id, &payload.refresh_token).await
    {
        eprintln!("Failed to revoke old refresh token: {:?}", e);
    }

    // Generate new access and refresh tokens
    let new_token = jwt::create_jwt(&user_id, username.as_ref());
    let new_refresh_token = jwt::create_refresh_token(&user_id, username.as_ref());

    // Store new refresh token in database
    if let Err(e) = refresh_tokens::store_refresh_token(&db, &user_id, &new_refresh_token).await {
        eprintln!("Failed to store new refresh token: {:?}", e);
    }

    success_response(
        StatusCode::OK,
        RefreshTokenResponse {
            token: new_token,
            refresh_token: new_refresh_token,
        },
    )
}

pub async fn logout_handler(
    user: AuthUser,
    Json(payload): Json<LogoutRequest>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            );
        }
    };

    // If refresh_token is provided, revoke only that specific token
    // Otherwise, revoke all refresh tokens for the user
    if let Some(refresh_token) = payload.refresh_token {
        match refresh_tokens::revoke_refresh_token(&db, &user.user_id, &refresh_token).await {
            Ok(revoked) if revoked => {
                return success_response(
                    StatusCode::OK,
                    serde_json::json!({"status": "logged_out", "message": "Refresh token revoked"}),
                );
            }
            Ok(_) => {
                return error_response(
                    StatusCode::NOT_FOUND,
                    "Refresh token not found or already revoked",
                );
            }
            Err(e) => {
                eprintln!("Failed to revoke refresh token: {:?}", e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to revoke refresh token",
                );
            }
        }
    } else {
        // Revoke all refresh tokens
        match refresh_tokens::revoke_all_refresh_tokens_for_user(&db, &user.user_id).await {
            Ok(count) => {
                eprintln!("Revoked {} refresh token(s) for user {}", count, user.user_id);
                return success_response(
                    StatusCode::OK,
                    serde_json::json!({"status": "logged_out", "message": format!("Revoked {} token(s)", count)}),
                );
            }
            Err(e) => {
                eprintln!("Failed to revoke all refresh tokens: {:?}", e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to revoke refresh tokens",
                );
            }
        }
    }
}

pub async fn register_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    if let Err(err) = recaptcha::ensure_recaptcha(&payload.captcha_token).await {
        return err;
    }

    // Check rate limit
    if let Err(msg) = rate_limit::check_registration_rate_limit(&addr) {
        return error_response(StatusCode::TOO_MANY_REQUESTS, &msg);
    }

    let db = match get_database().await {
        Ok(db) => db,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            );
        }
    };

    let users: Collection<User> = get_collection(&db, "Users");

    if let Some(existing_user) = users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        if existing_user.is_verified {
            return error_response(StatusCode::CONFLICT, "User already exists");
        }

        let verification_code = generate_code();
        let password_hash = match password::hash_password(&payload.password) {
            Ok(hash) => hash,
            Err(_) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to hash password",
                );
            }
        };

        users
            .update_one(
                doc! { "_id": existing_user.id },
                doc! {
                    "$set": {
                        "password_hash": &password_hash,
                        "verification_code": &verification_code,
                        "is_verified": false,
                    },
                    "$unset": { "reset_code": "" }
                },
            )
            .await
            .unwrap();

        send_email(
            &payload.email,
            "Your verification code",
            &format!("Code: {}", verification_code),
        )
        .await;

        return success_response(
            StatusCode::OK,
            serde_json::json!({"status": "verification_sent", "existing": true}),
        );
    }

    let verification_code = generate_code();
    let password_hash = match password::hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to hash password",
            );
        }
    };

    let new_user = User {
        id: ObjectId::new(),
        email: payload.email.clone(),
        username: None,
        password_hash,
        is_verified: false,
        verification_code: Some(verification_code.clone()),
        reset_code: None,
    };

    users.insert_one(&new_user).await.unwrap();

    send_email(
        &payload.email,
        "Your verification code",
        &format!("Code: {}", verification_code),
    )
    .await;

    success_response(
        StatusCode::OK,
        serde_json::json!({"status": "verification_sent", "existing": false}),
    )
}

pub async fn verify_email_handler(Json(payload): Json<VerifyEmailRequest>) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            );
        }
    };

    let users: Collection<User> = get_collection(&db, "Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => return error_response(StatusCode::NOT_FOUND, "User not found"),
    };

    if user.verification_code != Some(payload.code.clone()) {
        return error_response(StatusCode::BAD_REQUEST, "Invalid verification code");
    }

    users
        .update_one(
            doc! { "_id": user.id },
            doc! {
                "$set": { "is_verified": true },
                "$unset": { "verification_code": "" }
            },
        )
        .await
        .unwrap();

    let token = jwt::create_jwt(&user.id.to_hex(), user.username.as_ref());
    let refresh_token = jwt::create_refresh_token(&user.id.to_hex(), user.username.as_ref());

    // Store refresh token in database
    if let Err(e) = refresh_tokens::store_refresh_token(&db, &user.id.to_hex(), &refresh_token).await
    {
        eprintln!("Failed to store refresh token: {:?}", e);
    }

    success_response(
        StatusCode::OK,
        serde_json::json!({
            "verified": true,
            "token": token,
            "refresh_token": refresh_token,
            "user_id": user.id.to_hex(),
            "username": user.username,
        }),
    )
}

pub async fn resend_verification_handler(
    Json(payload): Json<ResendVerificationRequest>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            );
        }
    };

    let users: Collection<User> = get_collection(&db, "Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => return error_response(StatusCode::NOT_FOUND, "User not found"),
    };

    if user.is_verified {
        return error_response(StatusCode::BAD_REQUEST, "User already verified");
    }

    let verification_code = generate_code();

    users
        .update_one(
            doc! { "_id": user.id },
            doc! { "$set": { "verification_code": &verification_code } },
        )
        .await
        .unwrap();

    send_email(
        &user.email,
        "Your verification code",
        &format!("Code: {}", verification_code),
    )
    .await;

    success_response(
        StatusCode::OK,
        serde_json::json!({"status": "verification_sent"}),
    )
}

pub async fn reset_password_request_handler(
    Json(payload): Json<ResetPasswordRequestRequest>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            );
        }
    };

    let users: Collection<User> = get_collection(&db, "Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => return error_response(StatusCode::NOT_FOUND, "User not found"),
    };

    let reset_code = generate_code();

    users
        .update_one(
            doc! { "_id": user.id },
            doc! { "$set": { "reset_code": &reset_code } },
        )
        .await
        .unwrap();

    send_email(
        &user.email,
        "Reset your password",
        &format!("Reset code: {}", reset_code),
    )
    .await;

    success_response(
        StatusCode::OK,
        serde_json::json!({"status": "reset_code_sent"}),
    )
}

pub async fn reset_password_confirm_handler(
    Json(payload): Json<ResetPasswordConfirmRequest>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database connection failed",
            );
        }
    };

    let users: Collection<User> = get_collection(&db, "Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => return error_response(StatusCode::NOT_FOUND, "User not found"),
    };

    if user.reset_code != Some(payload.code.clone()) {
        return error_response(StatusCode::BAD_REQUEST, "Invalid reset code");
    }

    let password_hash = match password::hash_password(&payload.new_password) {
        Ok(hash) => hash,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to hash password",
            );
        }
    };

    users
        .update_one(
            doc! { "_id": user.id },
            doc! {
                "$set": { "password_hash": &password_hash },
                "$unset": { "reset_code": "" }
            },
        )
        .await
        .unwrap();

    success_response(
        StatusCode::OK,
        serde_json::json!({"status": "password_updated"}),
    )
}

