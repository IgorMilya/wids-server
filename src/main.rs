use axum::{
    Json, Router,
    extract::FromRequestParts,
    extract::{ConnectInfo, Json as JsonExtract, Path, Query},
    http::StatusCode,
    http::request::Parts,
    response::IntoResponse,
    routing::{delete, get, post},
};
use bcrypt::{hash, verify};
use chrono::{Duration, TimeZone, Utc};
use dashmap::DashMap;
use dotenvy::dotenv;
use futures::TryStreamExt;
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::Result as JWTResult,
};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use mongodb::Database;
use mongodb::bson::oid::ObjectId;
use mongodb::bson::{DateTime, Document};
use mongodb::{Client, Collection, bson::doc};
use once_cell::sync::Lazy;
use rand::Rng;
use serde::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::time::{Duration as stdDuration, SystemTime};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

async fn get_collection() -> mongodb::error::Result<Database> {
    let db_url = env::var("MONGO_DB_URL").expect("MONGO_DB_URL not set in environment variables");
    let client = Client::with_uri_str(db_url)
        .await
        .expect("Failed to connect to MongoDB");
    let db = client.database("WISP-APP");
    Ok(db)
}
fn serialize_datetime_as_iso_string<S>(date: &DateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(
        &date
            .try_to_rfc3339_string()
            .unwrap_or_else(|_| "Invalid Date".into()),
    )
}
//-------------------------------------------------------------------------- Blacklist
#[derive(Debug, Serialize, Deserialize)]
pub struct BlacklistedNetwork {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub ssid: String,
    pub bssid: String,
    pub timestamp: DateTime,
    pub reason: Option<String>,
    pub user_id: String,
}
#[derive(Debug, Serialize)]
pub struct BlacklistedNetworkResponse {
    pub id: String,
    pub ssid: String,
    pub bssid: String,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub timestamp: DateTime,
    pub reason: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct NewBlacklistEntry {
    ssid: String,
    bssid: String,
    reason: Option<String>,
}

async fn get_blacklist(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let database = get_collection().await.unwrap();
    let coll: Collection<BlacklistedNetwork> = database.collection("Blacklist");
    let mut filter = doc! { "user_id": &user.user_id }; // <-- filter by user 
    if let Some(ssid) = params.get("ssid") {
        filter.insert("ssid", doc! { "$regex": ssid, "$options": "i" });
    }
    if let Some(date_str) = params.get("date") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
            filter.insert( "timestamp", doc! { "$gte": DateTime::from_millis(start.timestamp_millis()), "$lte": DateTime::from_millis(end.timestamp_millis()) }, );
        }
    }
    let mut cursor = coll.find(filter).await.unwrap();
    let mut results = vec![];
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        results.push(BlacklistedNetworkResponse {
            id: doc.id.to_hex(),
            ssid: doc.ssid,
            bssid: doc.bssid,
            timestamp: doc.timestamp,
            reason: doc.reason,
        });
    }
    Json(results).into_response()
}

async fn delete_from_blacklist(user: AuthUser, Path(id): Path<String>) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let coll: Collection<BlacklistedNetwork> = db.collection("Blacklist");
    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid id"})),
            )
                .into_response();
        }
    };
    let filter = doc! { "_id": obj_id, "user_id": &user.user_id }; // <-- only own entry
    match coll.delete_one(filter).await {
        Ok(res) if res.deleted_count == 1 => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "deleted"})),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn add_to_blacklist(
    user: AuthUser,
    JsonExtract(payload): JsonExtract<NewBlacklistEntry>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let coll: Collection<Document> = db.collection("Blacklist");
    let new_doc = doc! { "ssid": payload.ssid, "bssid": payload.bssid, "timestamp": DateTime::now(), "reason": payload.reason.unwrap_or("Manually added".into()), "user_id": user.user_id, // <-- attach user_id
    };
    match coll.insert_one(new_doc).await {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"status": "added"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ------------------------------------------------- WHITELIST
#[derive(Debug, Serialize, Deserialize)]
pub struct WhitelistedNetwork {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub ssid: String,
    pub bssid: String,
    pub timestamp: DateTime,
    pub user_id: String,
}
#[derive(Debug, Serialize)]
pub struct WhitelistedNetworkResponse {
    pub id: String,
    pub ssid: String,
    pub bssid: String,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub timestamp: DateTime,
}
#[derive(Debug, Deserialize)]
pub struct NewWhitelistEntry {
    ssid: String,
    bssid: String,
}
async fn get_whitelist(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let database = get_collection().await.expect("Failed to connect to DB");
    let coll: Collection<WhitelistedNetwork> = database.collection("Whitelist");
    let mut filter = doc! { "user_id": &user.user_id }; // only this user's entries 
    if let Some(ssid) = params.get("ssid") {
        filter.insert("ssid", doc! { "$regex": ssid, "$options": "i" });
    }
    if let Some(date_str) = params.get("date") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
            filter.insert( "timestamp", doc! { "$gte": DateTime::from_millis(start.timestamp_millis()), "$lte": DateTime::from_millis(end.timestamp_millis()) }, );
        }
    }
    let mut cursor = coll.find(filter).await.unwrap();
    let mut results = vec![];
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        results.push(WhitelistedNetworkResponse {
            id: doc.id.to_hex(),
            ssid: doc.ssid,
            bssid: doc.bssid,
            timestamp: doc.timestamp,
        });
    }
    Json(results).into_response()
}

async fn delete_from_whitelist(user: AuthUser, Path(id): Path<String>) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let coll: Collection<WhitelistedNetwork> = db.collection("Whitelist");
    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid id"})),
            )
                .into_response();
        }
    };
    let filter = doc! { "_id": obj_id, "user_id": &user.user_id }; // only own entry 
    match coll.delete_one(filter).await {
        Ok(res) if res.deleted_count == 1 => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "deleted"})),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn add_to_whitelist(
    user: AuthUser,
    JsonExtract(payload): JsonExtract<NewWhitelistEntry>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let coll: Collection<Document> = db.collection("Whitelist");
    let new_doc = doc! { "ssid": payload.ssid, "bssid": payload.bssid, "timestamp": DateTime::now(), "user_id": user.user_id, // link entry to logged-in user
    };
    match coll.insert_one(new_doc).await {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"status": "added"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

//-----------------------------------------------------------------------------------Logs
#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: String,
    pub network_ssid: String,
    pub network_bssid: Option<String>,
    pub action: String,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub timestamp: DateTime,
    pub details: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct NewLogEntry {
    pub network_ssid: String,
    pub network_bssid: Option<String>,
    pub action: String,
    pub details: Option<String>,
}
async fn add_log(user: AuthUser, Json(payload): JsonExtract<NewLogEntry>) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<Document> = db.collection("Logs");
    let new_doc = doc! { "user_id": user.user_id, "network_ssid": payload.network_ssid, "network_bssid": payload.network_bssid, "action": payload.action, "timestamp": DateTime::now(), "details": payload.details.unwrap_or("".into()), };
    match coll.insert_one(new_doc).await {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"status": "logged"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
async fn get_logs(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<LogEntry> = db.collection("Logs");
    let mut filter = doc! { "user_id": &user.user_id };
    if let Some(action) = params.get("action") {
        filter.insert("action", action);
    }
    if let Some(ssid) = params.get("ssid") {
        filter.insert("network_ssid", doc! { "$regex": ssid, "$options": "i" });
    }
    if let Some(date_str) = params.get("date") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
            filter.insert("timestamp", doc! { "$gte": DateTime::from_millis(start.timestamp_millis()), "$lte": DateTime::from_millis(end.timestamp_millis()) });
        }
    } // Parse pagination params 
    let page: u64 = params.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let limit: u64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(11);
    let skip: u64 = (page - 1) * limit; // Get total count 
    let total = coll
        .count_documents(filter.clone())
        .await
        .unwrap_or_else(|_| 0);
    let mut cursor = match coll.find(filter).skip(skip).limit(limit as i64).await {
        Ok(cursor) => cursor,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let mut results = Vec::new();
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        results.push(doc);
    }
    Json(serde_json::json!({ "total": total, "logs": results })).into_response()
}
//---------------------------------------------------------------------------- Login
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub email: String,
    pub username: Option<String>,
    pub password_hash: String,
    pub is_verified: bool,
    pub verification_code: Option<String>,
    pub reset_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub exp: usize,  // expiration timestamp
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub email: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordConfirm {
    pub email: String,
    pub code: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

async fn send_email(to: &str, subject: &str, body: &str) {
    println!(
        "Sending email from: {:?}",
        env::var("SMTP_USER").expect("SMTP_USER not set")
    );
    let smtp = SmtpTransport::starttls_relay("smtp.gmail.com")
        .unwrap()
        .credentials(Credentials::new(
            env::var("SMTP_USER").expect("SMTP_USER not set"),
            env::var("SMTP_PASS").expect("SMTP_PASS not set"),
        ))
        .build();
    println!("SMTP_FROM: {:?}", &smtp);
    let from_addr = env::var("SMTP_FROM").unwrap_or_else(|_| env::var("SMTP_USER").unwrap());

    let email = Message::builder()
        .from(format!("wids <{}>", from_addr).parse().unwrap())
        .to(Mailbox::new(None, to.parse().unwrap()))
        .subject(subject)
        .body(body.to_string())
        .unwrap();
    println!("Email: {:?}", email);
    let result = smtp.send(&email);
    match result {
        Ok(_) => println!("Email accepted by SMTP server"),
        Err(err) => eprintln!("Email send failed: {err:?}"),
    }
}

static REGISTRATION_ATTEMPTS: Lazy<DashMap<String, Vec<SystemTime>>> = Lazy::new(DashMap::new);
const MAX_ATTEMPTS: usize = 100;
const WINDOW: stdDuration = stdDuration::from_secs(60 * 60);

fn generate_code() -> String {
    let mut rng = rand::rng();
    format!("{:06}", rng.random_range(0..1_000_000))
}
pub struct AuthUser {
    pub user_id: String,
}
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode; // async fn directly, no async_trait
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract Authorization header
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
pub fn create_jwt(user_id: &str) -> String {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET not set");
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .expect("Failed to create token")
}
pub fn verify_jwt(token: &str) -> JWTResult<TokenData<Claims>> {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET not set");
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
}
async fn login_handler(Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    let db = match get_collection().await {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database connection failed"})),
            )
                .into_response();
        }
    };

    let users = db.collection::<User>("Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid credentials"})),
            )
                .into_response();
        }
    };

    if !user.is_verified {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Email not verified"})),
        )
            .into_response();
    }

    let valid = match verify(&payload.password, &user.password_hash) {
        Ok(is_valid) => is_valid,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Password verification failed"})),
            )
                .into_response();
        }
    };

    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentials"})),
        )
            .into_response();
    }

    let token = create_jwt(&user.id.to_hex());

    (
        StatusCode::OK,
        Json(LoginResponse {
            token,
            user_id: user.id.to_hex(),
            username: user.username.clone(),
        }),
    )
        .into_response()
}

async fn register_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    println!("Register request received: {:?}", payload);
    let ip = addr.ip().to_string();
    let now = SystemTime::now();

    let mut entry = REGISTRATION_ATTEMPTS.entry(ip.clone()).or_default();
    entry.retain(|&t| now.duration_since(t).unwrap_or_default() < WINDOW);

    if entry.len() >= MAX_ATTEMPTS {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "Too many registration attempts. Try again later."})),
        )
            .into_response();
    }

    entry.push(now);
    drop(entry);

    let db = match get_collection().await {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database connection failed"})),
            )
                .into_response();
        }
    };

    let users = db.collection::<User>("Users");

    if let Some(existing_user) = users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        if existing_user.is_verified {
            return (
                StatusCode::CONFLICT,
                Json(json!({"error": "User already exists"})),
            )
                .into_response();
        }

        let verification_code = generate_code();
        let password_hash = match hash(&payload.password, 10) {
            Ok(hash) => hash,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to hash password"})),
                )
                    .into_response();
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

        return (
            StatusCode::OK,
            Json(json!({"status": "verification_sent", "existing": true})),
        )
            .into_response();
    }

    let verification_code = generate_code();
    let password_hash = match hash(&payload.password, 10) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to hash password"})),
            )
                .into_response();
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

    (
        StatusCode::OK,
        Json(json!({"status": "verification_sent", "existing": false})),
    )
        .into_response()
}

async fn verify_email_handler(Json(payload): Json<VerifyRequest>) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let users = db.collection::<User>("Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "User not found"})),
            )
                .into_response();
        }
    };

    if user.verification_code != Some(payload.code.clone()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid verification code"})),
        )
            .into_response();
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

    let token = create_jwt(&user.id.to_hex());

    (
        StatusCode::OK,
        Json(json!({
            "verified": true,
            "token": token,
            "user_id": user.id.to_hex(),
            "username": user.username,
        })),
    )
        .into_response()
}

async fn resend_verification_handler(
    Json(payload): Json<ResendVerificationRequest>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let users = db.collection::<User>("Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "User not found"})),
            )
                .into_response();
        }
    };

    if user.is_verified {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "User already verified"})),
        )
            .into_response();
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

    (StatusCode::OK, Json(json!({"status": "verification_sent"}))).into_response()
}

async fn reset_password_request_handler(
    Json(payload): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let users = db.collection::<User>("Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "User not found"})),
            )
                .into_response();
        }
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

    (StatusCode::OK, Json(json!({"status": "reset_code_sent"}))).into_response()
}

async fn reset_password_confirm_handler(
    Json(payload): Json<ResetPasswordConfirm>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let users = db.collection::<User>("Users");

    let user = match users
        .find_one(doc! { "email": &payload.email })
        .await
        .unwrap()
    {
        Some(user) => user,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "User not found"})),
            )
                .into_response();
        }
    };

    if user.reset_code != Some(payload.code.clone()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid reset code"})),
        )
            .into_response();
    }

    let password_hash = match hash(&payload.new_password, 10) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to hash password"})),
            )
                .into_response();
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

    (StatusCode::OK, Json(json!({"status": "password_updated"}))).into_response()
}
//-----------------------------------------------------------------------------------------------
#[tokio::main]
async fn main() {
    dotenv().ok();
    let cors = CorsLayer::very_permissive();
    let app = Router::new()
        .route("/auth/login", post(login_handler))
        .route("/auth/register", post(register_handler))
        .route("/auth/verify", post(verify_email_handler))
        .route(
            "/auth/resend-verification",
            post(resend_verification_handler),
        )
        .route("/auth/reset/request", post(reset_password_request_handler))
        .route("/auth/reset/confirm", post(reset_password_confirm_handler))
        .route("/blacklist", get(get_blacklist).post(add_to_blacklist))
        .route("/blacklist/{id}", delete(delete_from_blacklist))
        .route("/whitelist", get(get_whitelist).post(add_to_whitelist))
        .route("/whitelist/{id}", delete(delete_from_whitelist))
        .route("/logs", get(get_logs).post(add_log))
        .layer(cors);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Listening on http://{}", addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
