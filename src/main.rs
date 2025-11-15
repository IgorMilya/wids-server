use axum::{
    Json, Router,
    extract::FromRequestParts,
    extract::{Json as JsonExtract, Path, Query},
    http::StatusCode,
    http::request::Parts,
    response::IntoResponse,
    routing::{delete, get, post},
};
use bcrypt::{verify};
use chrono::{Duration, TimeZone, Utc};
use dotenvy::dotenv;
use futures::TryStreamExt;
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
    errors::Result as JWTResult,
};
use mongodb::Database;
use mongodb::bson::oid::ObjectId;
use mongodb::bson::{DateTime, Document};
use mongodb::{Client, Collection, bson::doc};
use serde::Serializer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
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
            filter.insert(
                "timestamp",
                doc! {
                    "$gte": DateTime::from_millis(start.timestamp_millis()),
                    "$lte": DateTime::from_millis(end.timestamp_millis())
                },
            );
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


async fn delete_from_blacklist(
    user: AuthUser,
    Path(id): Path<String>
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let coll: Collection<BlacklistedNetwork> = db.collection("Blacklist");
    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid id"}))).into_response(),
    };

    let filter = doc! { "_id": obj_id, "user_id": &user.user_id }; // <-- only own entry
    match coll.delete_one(filter).await {
        Ok(res) if res.deleted_count == 1 => (StatusCode::OK, Json(serde_json::json!({"status": "deleted"}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}


async fn add_to_blacklist(
    user: AuthUser,
    JsonExtract(payload): JsonExtract<NewBlacklistEntry>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let coll: Collection<Document> = db.collection("Blacklist");

    let new_doc = doc! {
        "ssid": payload.ssid,
        "bssid": payload.bssid,
        "timestamp": DateTime::now(),
        "reason": payload.reason.unwrap_or("Manually added".into()),
        "user_id": user.user_id, // <-- attach user_id
    };

    match coll.insert_one(new_doc).await {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({"status": "added"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
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
    Query(params): Query<HashMap<String, String>>
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
            filter.insert(
                "timestamp",
                doc! {
                    "$gte": DateTime::from_millis(start.timestamp_millis()),
                    "$lte": DateTime::from_millis(end.timestamp_millis())
                },
            );
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
/// Accepts optional `ssid` and `date` query parameters.
// async fn get_whitelist(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
//     let database = get_collection().await.expect("Failed to connect to DB");
//     let my_coll: Collection<WhitelistedNetwork> = database.collection("Whitelist");
//
//     // Extract optional params
//     let ssid_query = params.get("ssid");
//     let date_query = params.get("date"); // Expected format: YYYY-MM-DD
//
//     let mut filter = doc! {};
//
//     // SSID case-insensitive partial match
//     if let Some(ssid) = ssid_query {
//         filter.insert(
//             "ssid",
//             doc! {
//                 "$regex": ssid,
//                 "$options": "i"  // Case-insensitive
//             },
//         );
//     }
//
//     // Timestamp exact date match (00:00 to 23:59)
//     if let Some(date_str) = date_query {
//         if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
//             let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
//             let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
//
//             filter.insert(
//                 "timestamp",
//                 doc! {
//                     "$gte": DateTime::from_millis(start.timestamp_millis()),
//                     "$lte": DateTime::from_millis(end.timestamp_millis()),
//                 },
//             );
//         }
//     }
//
//     let mut cursor = match my_coll.find(filter).await {
//         Ok(cursor) => cursor,
//         Err(err) => {
//             let body = Json(serde_json::json!({ "error": err.to_string() }));
//             return (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
//         }
//     };
//
//     let mut results = Vec::new();
//     while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
//         results.push(WhitelistedNetworkResponse {
//             id: doc.id.to_hex(),
//             ssid: doc.ssid,
//             bssid: doc.bssid,
//             timestamp: doc.timestamp,
//         });
//     }
//
//     Json(results).into_response()
// }

async fn delete_from_whitelist(
    user: AuthUser,
    Path(id): Path<String>
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let coll: Collection<WhitelistedNetwork> = db.collection("Whitelist");

    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid id"}))).into_response(),
    };

    let filter = doc! { "_id": obj_id, "user_id": &user.user_id }; // only own entry
    match coll.delete_one(filter).await {
        Ok(res) if res.deleted_count == 1 => (StatusCode::OK, Json(serde_json::json!({"status": "deleted"}))).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

// async fn delete_from_whitelist(Path(id): Path<String>) -> impl IntoResponse {
//     let db = get_collection().await.expect("DB connection");
//     let coll: Collection<WhitelistedNetwork> = db.collection("Whitelist");
//
//     let obj_id = match ObjectId::parse_str(&id) {
//         Ok(oid) => oid,
//         Err(_) => {
//             return (
//                 StatusCode::BAD_REQUEST,
//                 Json(serde_json::json!({"error": "Invalid id"})),
//             )
//                 .into_response();
//         }
//     };
//
//     match coll.delete_one(doc! { "_id": obj_id }).await {
//         Ok(res) if res.deleted_count == 1 => (
//             StatusCode::OK,
//             Json(serde_json::json!({"status": "deleted"})),
//         )
//             .into_response(),
//         Ok(_) => (
//             StatusCode::NOT_FOUND,
//             Json(serde_json::json!({"error": "Not found"})),
//         )
//             .into_response(),
//         Err(e) => (
//             StatusCode::INTERNAL_SERVER_ERROR,
//             Json(serde_json::json!({"error": e.to_string()})),
//         )
//             .into_response(),
//     }
// }
async fn add_to_whitelist(
    user: AuthUser,
    JsonExtract(payload): JsonExtract<NewWhitelistEntry>
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let coll: Collection<Document> = db.collection("Whitelist");

    let new_doc = doc! {
        "ssid": payload.ssid,
        "bssid": payload.bssid,
        "timestamp": DateTime::now(),
        "user_id": user.user_id, // link entry to logged-in user
    };

    match coll.insert_one(new_doc).await {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({"status": "added"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

// async fn add_to_whitelist(
//     JsonExtract(payload): JsonExtract<NewWhitelistEntry>,
// ) -> impl IntoResponse {
//     let db = get_collection().await.expect("DB connection");
//     let coll: Collection<Document> = db.collection("Whitelist");
//
//     let new_doc = doc! {
//         "ssid": payload.ssid,
//         "bssid": payload.bssid,
//         "timestamp": DateTime::now(),
//     };
//
//     match coll.insert_one(new_doc).await {
//         Ok(_) => (
//             StatusCode::CREATED,
//             Json(serde_json::json!({"status": "added"})),
//         )
//             .into_response(),
//         Err(e) => (
//             StatusCode::INTERNAL_SERVER_ERROR,
//             Json(serde_json::json!({"error": e.to_string()})),
//         )
//             .into_response(),
//     }
// }
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

async fn add_log(
    user: AuthUser,
    Json(payload): JsonExtract<NewLogEntry>,
) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<Document> = db.collection("Logs");

    let new_doc = doc! {
        "user_id": user.user_id,
        "network_ssid": payload.network_ssid,
        "network_bssid": payload.network_bssid,
        "action": payload.action,
        "timestamp": DateTime::now(),
        "details": payload.details.unwrap_or("".into()),
    };

    match coll.insert_one(new_doc).await {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({"status": "logged"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn get_logs(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>
) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<LogEntry> = db.collection("Logs");

    let mut filter = doc! { "user_id": &user.user_id };

    if let Some(action) = params.get("action") { filter.insert("action", action); }
    if let Some(ssid) = params.get("ssid") { filter.insert("network_ssid", doc! { "$regex": ssid, "$options": "i" }); }
    if let Some(date_str) = params.get("date") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
            filter.insert("timestamp", doc! {
                "$gte": DateTime::from_millis(start.timestamp_millis()),
                "$lte": DateTime::from_millis(end.timestamp_millis())
            });
        }
    }

    // Parse pagination params
    let page: u64 = params.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let limit: u64 = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(11);
    let skip:u64 = (page - 1) * limit;

    // Get total count
    let total = coll.count_documents(filter.clone()).await.unwrap_or_else(|_| 0);

    let mut cursor = match coll.find(filter).skip(skip).limit(limit as i64).await {
        Ok(cursor) => cursor,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };

    let mut results = Vec::new();
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        results.push(doc);
    }

    Json(serde_json::json!({
        "total": total,
        "logs": results
    })).into_response()
}


//---------------------------------------------------------------------------- Login

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub exp: usize,  // expiration timestamp
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user_id: String,
    pub username: String,
}

pub struct AuthUser {
    pub user_id: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    // async fn directly, no async_trait
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
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

        let token_data: TokenData<Claims> = verify_jwt(token)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

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

async fn login_handler(
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let db_url = std::env::var("MONGO_DB_URL").expect("MONGO_DB_URL not set");
    let client = Client::with_uri_str(db_url)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let users_coll = client.database("WISP-APP").collection::<User>("Users");

    let user_doc = users_coll
        .find_one(doc! { "username": &payload.username })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = match user_doc {
        Some(u) => u,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let valid = verify(&payload.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = create_jwt(&user.id.to_hex());

    Ok(Json(LoginResponse {
        token,
        user_id: user.id.to_hex(),
        username: user.username,
    }))
}

//-----------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    dotenv().ok();
    let cors = CorsLayer::very_permissive();
    // let db_url = env::var("MONGO_DB_URL").expect("MONGO_DB_URL not set");
    // let client = Client::with_uri_str(db_url).await.unwrap();
    // let db = client.database("WISP-APP");
    // let users = db.collection("Users");
    // 
    // // Create password hash
    // let password = "password";
    // let password_hash = hash(password, 10).unwrap();
    // 
    // let new_user = doc! {
    //     "username": "ihor",
    //     "password_hash": password_hash,
    // };
    // 
    // let result = users.insert_one(new_user).await.unwrap();
    // println!("User inserted with id: {}", result.inserted_id);
    let app = Router::new()
        .route("/auth/login", post(login_handler))
        .route("/blacklist", get(get_blacklist).post(add_to_blacklist))
        .route("/blacklist/{id}", delete(delete_from_blacklist))
        .route("/whitelist", get(get_whitelist).post(add_to_whitelist))
        .route("/whitelist/{id}", delete(delete_from_whitelist))
        .route("/logs", get(get_logs).post(add_log))
        .layer(cors);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();
    
    println!("Listening on http://{}", addr);
    
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
