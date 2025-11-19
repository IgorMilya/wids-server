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
use reqwest::Client as ReqwestClient;
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
        let action_str = action.trim();
        if !action_str.is_empty() {
            filter.insert("action", doc! { "$regex": action_str, "$options": "i" });
        }
    }
    if let Some(ssid) = params.get("ssid") {
        let ssid_str = ssid.trim();
        if !ssid_str.is_empty() {
            filter.insert("network_ssid", doc! { "$regex": ssid_str, "$options": "i" });
        }
    }
    // Support date range filtering (date_from and date_till) or single date
    if let Some(date_from_str) = params.get("date_from") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_from_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            filter.insert("timestamp", doc! { "$gte": DateTime::from_millis(start.timestamp_millis()) });
        }
    }
    if let Some(date_till_str) = params.get("date_till") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_till_str, "%Y-%m-%d") {
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
            filter.insert("timestamp", doc! { "$lte": DateTime::from_millis(end.timestamp_millis()) });
        }
    }
    // Support legacy single date parameter
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
    let skip: u64 = (page - 1) * limit; // Parse sort parameters
    let sort_field = params.get("sort_by").unwrap_or(&"timestamp".to_string()).clone();
    let sort_direction_str = params.get("sort_direction").unwrap_or(&"desc".to_string()).clone();
    let sort_direction = if sort_direction_str == "asc" { 1 } else { -1 };
    
    // Map frontend column names to backend field names
    let db_sort_field = match sort_field.as_str() {
        "SSID" => "network_ssid",
        "BSSID" => "network_bssid",
        "Action" => "action",
        "Timestamp" => "timestamp",
        "Details" => "details",
        "network_ssid" => "network_ssid",
        "network_bssid" => "network_bssid",
        "action" => "action",
        "timestamp" => "timestamp",
        "details" => "details",
        _ => "timestamp", // Default to timestamp if unknown field
    };
    
    // Get total count 
    let total = coll
        .count_documents(filter.clone())
        .await
        .unwrap_or_else(|_| 0);
    let sort_options = doc! { db_sort_field: sort_direction };
    let mut cursor = match coll.find(filter).sort(sort_options).skip(skip).limit(limit as i64).await {
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

async fn export_logs(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<LogEntry> = db.collection("Logs");
    let mut filter = doc! { "user_id": &user.user_id };
    
    // Apply same filters as get_logs but without pagination
    if let Some(action) = params.get("action") {
        let action_str = action.trim();
        if !action_str.is_empty() {
            filter.insert("action", doc! { "$regex": action_str, "$options": "i" });
        }
    }
    if let Some(ssid) = params.get("ssid") {
        let ssid_str = ssid.trim();
        if !ssid_str.is_empty() {
            filter.insert("network_ssid", doc! { "$regex": ssid_str, "$options": "i" });
        }
    }
    
    // Support date range filtering (date_from and date_till) or single date
    if let Some(date_from_str) = params.get("date_from") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_from_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            filter.insert("timestamp", doc! { "$gte": DateTime::from_millis(start.timestamp_millis()) });
        }
    }
    if let Some(date_till_str) = params.get("date_till") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_till_str, "%Y-%m-%d") {
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
            filter.insert("timestamp", doc! { "$lte": DateTime::from_millis(end.timestamp_millis()) });
        }
    }
    // Support legacy single date parameter
    if let Some(date_str) = params.get("date") {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
            filter.insert("timestamp", doc! { "$gte": DateTime::from_millis(start.timestamp_millis()), "$lte": DateTime::from_millis(end.timestamp_millis()) });
        }
    }
    
    // Get total count
    let total = coll
        .count_documents(filter.clone())
        .await
        .unwrap_or_else(|_| 0);
    
    // Parse sort parameters (default to timestamp descending)
    let sort_field = params.get("sort_by").unwrap_or(&"timestamp".to_string()).clone();
    let sort_direction_str = params.get("sort_direction").unwrap_or(&"desc".to_string()).clone();
    let sort_direction = if sort_direction_str == "asc" { 1 } else { -1 };
    
    // Map frontend column names to backend field names
    let db_sort_field = match sort_field.as_str() {
        "SSID" => "network_ssid",
        "BSSID" => "network_bssid",
        "Action" => "action",
        "Timestamp" => "timestamp",
        "Details" => "details",
        "network_ssid" => "network_ssid",
        "network_bssid" => "network_bssid",
        "action" => "action",
        "timestamp" => "timestamp",
        "details" => "details",
        _ => "timestamp", // Default to timestamp if unknown field
    };
    
    // Fetch all logs matching the filter (no pagination)
    let sort_options = doc! { db_sort_field: sort_direction };
    let mut cursor = match coll.find(filter).sort(sort_options).await {
        Ok(cursor) => cursor,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
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

//-----------------------------------------------------------------------------------Analytics
#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    pub security_metrics: SecurityMetrics,
    pub connection_stats: ConnectionStats,
    pub blacklist_whitelist: BlacklistWhitelistStats,
    pub user_activity: UserActivityStats,
    pub network_stats: NetworkStats,
    pub time_series: TimeSeriesData,
    pub threat_analytics: ThreatAnalytics,
}

#[derive(Debug, Serialize)]
pub struct SecurityMetrics {
    pub high_risk_connections: i64,
    pub medium_risk_connections: i64,
    pub low_risk_connections: i64,
    pub failed_attempts: i64,
    pub successful_connections: i64,
}

#[derive(Debug, Serialize)]
pub struct ConnectionStats {
    pub total_connections: i64,
    pub connection_success_rate: f64,
    pub total_scan_attempts: i64,
    pub avg_connections_per_day: f64,
}

#[derive(Debug, Serialize)]
pub struct BlacklistWhitelistStats {
    pub total_blacklisted: i64,
    pub total_whitelisted: i64,
    pub blacklist_additions: i64,
    pub blacklist_removals: i64,
    pub whitelist_additions: i64,
    pub whitelist_removals: i64,
    pub blacklist_additions_today: i64,
    pub blacklist_removals_today: i64,
    pub whitelist_additions_today: i64,
    pub whitelist_removals_today: i64,
    pub blacklist_additions_week: i64,
    pub blacklist_removals_week: i64,
    pub whitelist_additions_week: i64,
    pub whitelist_removals_week: i64,
    pub blacklist_additions_month: i64,
    pub blacklist_removals_month: i64,
    pub whitelist_additions_month: i64,
    pub whitelist_removals_month: i64,
}

#[derive(Debug, Serialize)]
pub struct UserActivityStats {
    pub password_changes: i64,
    pub username_changes: i64,
    pub profile_updates: i64,
    pub profile_save_attempts: i64,
}

#[derive(Debug, Serialize)]
pub struct NetworkStats {
    pub most_scanned_networks: Vec<NetworkScanCount>,
    pub unique_networks_scanned: i64,
}

#[derive(Debug, Serialize)]
pub struct NetworkScanCount {
    pub ssid: String,
    pub scan_count: i64,
}

#[derive(Debug, Serialize)]
pub struct TimeSeriesData {
    pub daily_activity: Vec<DailyActivity>,
    pub hourly_activity: Vec<HourlyActivity>,
}

#[derive(Debug, Serialize)]
pub struct DailyActivity {
    pub date: String,
    pub scans: i64,
    pub connections: i64,
    pub blacklist_adds: i64,
    pub whitelist_adds: i64,
}

#[derive(Debug, Serialize)]
pub struct HourlyActivity {
    pub hour: i32,
    pub activity_count: i64,
}

// New analytics structures
#[derive(Debug, Serialize)]
pub struct ThreatsOverTime {
    pub daily: Vec<ThreatTimePoint>,
    pub weekly: Vec<ThreatTimePoint>,
    pub monthly: Vec<ThreatTimePoint>,
    pub by_type: Vec<ThreatTypeTimePoint>,
}

#[derive(Debug, Serialize)]
pub struct ThreatTimePoint {
    pub date: String,
    pub total_threats: i64,
}

#[derive(Debug, Serialize)]
pub struct ThreatTypeTimePoint {
    pub date: String,
    pub threat_type: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct ThreatTypeDistribution {
    pub rogue_aps: i64,
    pub evil_twins: i64,
    pub suspicious_open_networks: i64,
    pub weak_encryption: i64,
    pub deauth_attacks: i64,
    pub mac_spoof_attempts: i64,
    pub blacklisted_networks_detected: i64,
}

#[derive(Debug, Serialize)]
pub struct ChannelUsage {
    pub channel_1: i64,
    pub channel_6: i64,
    pub channel_11: i64,
    pub channels_5ghz: Vec<Channel5Ghz>,
}

#[derive(Debug, Serialize)]
pub struct Channel5Ghz {
    pub channel: i32,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct TopSuspiciousNetwork {
    pub ssid: String,
    pub bssid: String,
    pub risk_score: String, // "L", "M", "H", "C"
    pub threat_count: i64,
}

#[derive(Debug, Serialize)]
pub struct ThreatAnalytics {
    pub threats_over_time: ThreatsOverTime,
    pub threat_type_distribution: ThreatTypeDistribution,
    pub channel_usage: ChannelUsage,
    pub top_suspicious_networks: Vec<TopSuspiciousNetwork>,
}

async fn get_analytics(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Get date filter parameter (day, week, month, year, all)
    let date_filter = params.get("threat_date_filter").map(|s| s.as_str()).unwrap_or("all");
    let db = get_collection().await.expect("DB connection");
    let logs_coll: Collection<Document> = db.collection("Logs");
    let blacklist_coll: Collection<Document> = db.collection("Blacklist");
    let whitelist_coll: Collection<Document> = db.collection("Whitelist");
    
    let user_filter = doc! { "user_id": &user.user_id };
    
    // Security Metrics - Count connections by risk level (from details field)
    // Match patterns like "Risk level: C", "Risk level: H", "risk.*[Cc]", "risk.*[Hh]", etc.
    let high_risk = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id,
            "$and": [
                {
                    "$or": [
                        { "action": "CONNECTED" },
                        { "action": "CONNECTED_RETRY" },
                    ]
                },
                {
                    "$or": [
                        { "details": { "$regex": r"Risk level:\s*[CH]|Risk level:\s*C|Risk level:\s*H|\(Critical\)|\(High\)", "$options": "i" } },
                        { "details": { "$regex": r"risk.*[Hh]", "$options": "i" } },
                        { "details": { "$regex": r"risk.*[Cc]", "$options": "i" } },
                    ]
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let medium_risk = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id,
            "$and": [
                {
                    "$or": [
                        { "action": "CONNECTED" },
                        { "action": "CONNECTED_RETRY" },
                    ]
                },
                {
                    "$or": [
                        { "details": { "$regex": r"Risk level:\s*M", "$options": "i" } },
                        { "details": { "$regex": r"risk.*[Mm]", "$options": "i" } },
                        { "details": { "$regex": r"\(Medium\)", "$options": "i" } },
                    ]
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let low_risk = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id,
            "$and": [
                {
                    "$or": [
                        { "action": "CONNECTED" },
                        { "action": "CONNECTED_RETRY" },
                    ]
                },
                {
                    "$or": [
                        { "details": { "$regex": r"Risk level:\s*L", "$options": "i" } },
                        { "details": { "$regex": r"risk.*[Ll]", "$options": "i" } },
                        { "details": { "$regex": r"\(Low\)|\(Whitelisted\)", "$options": "i" } },
                    ]
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    // Failed attempts - CONNECT_FAILED or connection retries
    let failed_attempts = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id,
            "$or": [
                { "action": { "$regex": "FAILED", "$options": "i" } },
                { "action": "CONNECTED_RETRY" },
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    // Successful connections
    let successful_connections = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "CONNECTED" }
    ).await.unwrap_or(0) as i64;
    
    // Connection Stats
    let total_connections = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id,
            "$or": [
                { "action": "CONNECTED" },
                { "action": "CONNECTED_RETRY" },
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let total_scans = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "SCAN_START" }
    ).await.unwrap_or(0) as i64;
    
    let connection_success_rate = if total_connections > 0 {
        (successful_connections as f64 / total_connections as f64) * 100.0
    } else {
        0.0
    };
    
    // Calculate days since first log (for avg per day)
    let first_log = logs_coll.find_one(
        doc! { "user_id": &user.user_id }
    ).sort(doc! { "timestamp": 1 }).await.ok().flatten();
    
    let days_active = if let Some(log) = first_log {
        if let Some(ts) = log.get("timestamp").and_then(|v| v.as_datetime()) {
            let now = DateTime::now();
            let diff = now.timestamp_millis() - ts.timestamp_millis();
            (diff as f64 / (24.0 * 60.0 * 60.0 * 1000.0)).max(1.0)
        } else {
            1.0
        }
    } else {
        1.0
    };
    
    let avg_connections_per_day = total_connections as f64 / days_active;
    
    // Blacklist/Whitelist Stats
    let total_blacklisted = blacklist_coll.count_documents(user_filter.clone()).await.unwrap_or(0) as i64;
    let total_whitelisted = whitelist_coll.count_documents(user_filter.clone()).await.unwrap_or(0) as i64;
    
    let blacklist_additions = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "BLACKLIST_ADD" }
    ).await.unwrap_or(0) as i64;
    
    let blacklist_removals = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "BLACKLIST_DELETE" }
    ).await.unwrap_or(0) as i64;
    
    let whitelist_additions = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "WHITELIST_ADD" }
    ).await.unwrap_or(0) as i64;
    
    let whitelist_removals = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "WHITELIST_DELETE" }
    ).await.unwrap_or(0) as i64;
    
    // Time-based filtering for blacklist/whitelist stats
    let today_start = DateTime::from_millis(
        Utc::now().timestamp_millis() - ((Utc::now().timestamp() % (24 * 60 * 60)) * 1000)
    );
    let week_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (7 * 24 * 60 * 60 * 1000)
    );
    let month_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (30 * 24 * 60 * 60 * 1000)
    );
    
    let blacklist_additions_today = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "BLACKLIST_ADD",
            "timestamp": doc! { "$gte": today_start }
        }
    ).await.unwrap_or(0) as i64;
    
    let blacklist_removals_today = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "BLACKLIST_DELETE",
            "timestamp": doc! { "$gte": today_start }
        }
    ).await.unwrap_or(0) as i64;
    
    let whitelist_additions_today = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "WHITELIST_ADD",
            "timestamp": doc! { "$gte": today_start }
        }
    ).await.unwrap_or(0) as i64;
    
    let whitelist_removals_today = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "WHITELIST_DELETE",
            "timestamp": doc! { "$gte": today_start }
        }
    ).await.unwrap_or(0) as i64;
    
    let blacklist_additions_week = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "BLACKLIST_ADD",
            "timestamp": doc! { "$gte": week_ago }
        }
    ).await.unwrap_or(0) as i64;
    
    let blacklist_removals_week = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "BLACKLIST_DELETE",
            "timestamp": doc! { "$gte": week_ago }
        }
    ).await.unwrap_or(0) as i64;
    
    let whitelist_additions_week = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "WHITELIST_ADD",
            "timestamp": doc! { "$gte": week_ago }
        }
    ).await.unwrap_or(0) as i64;
    
    let whitelist_removals_week = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "WHITELIST_DELETE",
            "timestamp": doc! { "$gte": week_ago }
        }
    ).await.unwrap_or(0) as i64;
    
    let blacklist_additions_month = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "BLACKLIST_ADD",
            "timestamp": doc! { "$gte": month_ago }
        }
    ).await.unwrap_or(0) as i64;
    
    let blacklist_removals_month = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "BLACKLIST_DELETE",
            "timestamp": doc! { "$gte": month_ago }
        }
    ).await.unwrap_or(0) as i64;
    
    let whitelist_additions_month = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "WHITELIST_ADD",
            "timestamp": doc! { "$gte": month_ago }
        }
    ).await.unwrap_or(0) as i64;
    
    let whitelist_removals_month = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id, 
            "action": "WHITELIST_DELETE",
            "timestamp": doc! { "$gte": month_ago }
        }
    ).await.unwrap_or(0) as i64;
    
    // User Activity Stats
    let password_changes = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "PASSWORD_CHANGED" }
    ).await.unwrap_or(0) as i64;
    
    let username_changes = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "USERNAME_CHANGED" }
    ).await.unwrap_or(0) as i64;
    
    let profile_updates = logs_coll.count_documents(
        doc! { 
            "user_id": &user.user_id,
            "$or": [
                { "action": "PROFILE_UPDATED" },
                { "action": { "$regex": "PROFILE_SETTING_CHANGED", "$options": "i" } },
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let profile_save_attempts = logs_coll.count_documents(
        doc! { "user_id": &user.user_id, "action": "PROFILE_SAVE_ATTEMPTED" }
    ).await.unwrap_or(0) as i64;
    
    // Network Stats - Most scanned networks (count all actions by network_ssid, exclude empty/null/"-")
    let pipeline = vec![
        doc! {
            "$match": doc! { 
                "user_id": &user.user_id,
                "network_ssid": doc! { "$exists": true, "$ne": "", "$ne": "-", "$ne": null }
            }
        },
        doc! {
            "$group": doc! {
                "_id": "$network_ssid",
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "count": -1 }
        },
        doc! {
            "$limit": 10
        },
    ];
    
    let mut most_scanned = Vec::new();
    match logs_coll.aggregate(pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(ssid), Some(count)) = (
                    doc.get("_id").and_then(|v| v.as_str()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    // Only add non-empty SSIDs
                    if !ssid.is_empty() && ssid != "-" {
                        most_scanned.push(NetworkScanCount {
                            ssid: ssid.to_string(),
                            scan_count: count,
                        });
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating most scanned networks: {}", e);
        }
    }
    
    // Unique networks scanned (exclude empty/null/"-")
    let unique_networks_pipeline = vec![
        doc! {
            "$match": doc! { 
                "user_id": &user.user_id,
                "network_ssid": doc! { "$exists": true, "$ne": "", "$ne": "-", "$ne": null }
            }
        },
        doc! {
            "$group": doc! {
                "_id": "$network_ssid"
            }
        },
        doc! {
            "$count": "total"
        },
    ];
    
    let unique_networks = {
        let mut unique_cursor = match logs_coll.aggregate(unique_networks_pipeline).await {
            Ok(cursor) => cursor,
            Err(_) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to aggregate unique networks"})),
            ).into_response(),
        };
        if let Some(doc) = unique_cursor.try_next().await.unwrap_or(None) {
            doc.get("total").and_then(|v| v.as_i64()).unwrap_or(0)
        } else {
            0
        }
    };
    
    // Time Series Data - Daily activity for last 30 days
    let thirty_days_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (30 * 24 * 60 * 60 * 1000)
    );
    
    let daily_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": thirty_days_ago }
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-%m-%d",
                        "date": "$timestamp"
                    }
                },
                "scans": doc! {
                    "$sum": doc! {
                        "$cond": [doc! { "$eq": ["$action", "SCAN_START"] }, 1, 0]
                    }
                },
                "connections": doc! {
                    "$sum": doc! {
                        "$cond": [
                            doc! { "$in": ["$action", vec!["CONNECTED", "CONNECTED_RETRY"] ] },
                            1,
                            0
                        ]
                    }
                },
                "blacklist_adds": doc! {
                    "$sum": doc! {
                        "$cond": [doc! { "$eq": ["$action", "BLACKLIST_ADD"] }, 1, 0]
                    }
                },
                "whitelist_adds": doc! {
                    "$sum": doc! {
                        "$cond": [doc! { "$eq": ["$action", "WHITELIST_ADD"] }, 1, 0]
                    }
                },
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];
    
    let mut daily_activity = Vec::new();
    match logs_coll.aggregate(daily_pipeline).await {
        Ok(mut daily_cursor) => {
            while let Ok(Some(doc)) = daily_cursor.try_next().await {
                if let Some(date) = doc.get("_id").and_then(|v| v.as_str()) {
                    daily_activity.push(DailyActivity {
                        date: date.to_string(),
                        scans: doc.get("scans").and_then(|v| v.as_i64()).unwrap_or(0),
                        connections: doc.get("connections").and_then(|v| v.as_i64()).unwrap_or(0),
                        blacklist_adds: doc.get("blacklist_adds").and_then(|v| v.as_i64()).unwrap_or(0),
                        whitelist_adds: doc.get("whitelist_adds").and_then(|v| v.as_i64()).unwrap_or(0),
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating daily activity: {}", e);
        }
    }
    
    // Hourly activity (last 7 days)
    let seven_days_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (7 * 24 * 60 * 60 * 1000)
    );
    
    let hourly_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": seven_days_ago }
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$hour": "$timestamp"
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];
    
    let mut hourly_activity = Vec::new();
    match logs_coll.aggregate(hourly_pipeline).await {
        Ok(mut hourly_cursor) => {
            while let Ok(Some(doc)) = hourly_cursor.try_next().await {
                if let (Some(hour), Some(count)) = (
                    doc.get("_id").and_then(|v| v.as_i32()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    hourly_activity.push(HourlyActivity {
                        hour,
                        activity_count: count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating hourly activity: {}", e);
        }
    }
    
    // Fill missing hours with 0
    for hour in 0..24 {
        if !hourly_activity.iter().any(|h| h.hour == hour) {
            hourly_activity.push(HourlyActivity { hour, activity_count: 0 });
        }
    }
    hourly_activity.sort_by_key(|h| h.hour);
    
    // ========== THREAT ANALYTICS ==========
    
    // Threats Over Time - Daily (last 30 days)
    let thirty_days_ago_dt = DateTime::from_millis(
        Utc::now().timestamp_millis() - (30 * 24 * 60 * 60 * 1000)
    );
    
    let daily_threats_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": thirty_days_ago_dt },
                "$or": [
                    { "details": doc! { "$regex": r"Risk level:\s*(C|H|M)|\(Critical\)|\(High\)|\(Medium\)", "$options": "i" } },
                    { "action": "BLACKLIST_ADD" },
                    { "details": doc! { "$regex": r"evil.*twin|rogue|deauth|spoof|weak.*encryption|open.*network", "$options": "i" } },
                ]
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-%m-%d",
                        "date": "$timestamp"
                    }
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];
    
    let mut daily_threats = Vec::new();
    match logs_coll.aggregate(daily_threats_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(date), Some(count)) = (
                    doc.get("_id").and_then(|v| v.as_str()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    daily_threats.push(ThreatTimePoint {
                        date: date.to_string(),
                        total_threats: count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating daily threats: {}", e);
        }
    }
    
    // Threats Over Time - Weekly (last 12 weeks)
    let twelve_weeks_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (12 * 7 * 24 * 60 * 60 * 1000)
    );
    
    let weekly_threats_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": twelve_weeks_ago },
                "$or": [
                    { "details": doc! { "$regex": r"Risk level:\s*(C|H|M)|\(Critical\)|\(High\)|\(Medium\)", "$options": "i" } },
                    { "action": "BLACKLIST_ADD" },
                    { "details": doc! { "$regex": r"evil.*twin|rogue|deauth|spoof|weak.*encryption|open.*network", "$options": "i" } },
                ]
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-W%V",
                        "date": "$timestamp"
                    }
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];
    
    let mut weekly_threats = Vec::new();
    match logs_coll.aggregate(weekly_threats_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(date_str)) = cursor.try_next().await {
                if let (Some(date), Some(count)) = (
                    date_str.get("_id").and_then(|v| v.as_str()),
                    date_str.get("count").and_then(|v| v.as_i64()),
                ) {
                    weekly_threats.push(ThreatTimePoint {
                        date: date.to_string(),
                        total_threats: count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating weekly threats: {}", e);
        }
    }
    
    // Threats Over Time - Monthly (last 12 months)
    let twelve_months_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (12 * 30 * 24 * 60 * 60 * 1000)
    );
    
    let monthly_threats_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": twelve_months_ago },
                "$or": [
                    { "details": doc! { "$regex": r"Risk level:\s*(C|H|M)|\(Critical\)|\(High\)|\(Medium\)", "$options": "i" } },
                    { "action": "BLACKLIST_ADD" },
                    { "details": doc! { "$regex": r"evil.*twin|rogue|deauth|spoof|weak.*encryption|open.*network", "$options": "i" } },
                ]
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-%m",
                        "date": "$timestamp"
                    }
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];
    
    let mut monthly_threats = Vec::new();
    match logs_coll.aggregate(monthly_threats_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(date), Some(count)) = (
                    doc.get("_id").and_then(|v| v.as_str()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    monthly_threats.push(ThreatTimePoint {
                        date: date.to_string(),
                        total_threats: count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating monthly threats: {}", e);
        }
    }
    
    // Threats Over Time - By Type
    let threat_type_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": thirty_days_ago_dt },
            }
        },
        doc! {
            "$project": doc! {
                "date": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-%m-%d",
                        "date": "$timestamp"
                    }
                },
                "threat_type": doc! {
                    "$switch": doc! {
                        "branches": vec![
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"evil.*twin", "options": "i" } },
                                "then": "Evil Twin"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"rogue", "options": "i" } },
                                "then": "Rogue AP"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"open.*network|no.*encryption", "options": "i" } },
                                "then": "Suspicious Open Network"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"weak.*encryption|WEP|TKIP", "options": "i" } },
                                "then": "Weak Encryption"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"deauth", "options": "i" } },
                                "then": "Deauth Attack"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"spoof|MAC.*spoof", "options": "i" } },
                                "then": "MAC Spoof Attempt"
                            },
                            doc! {
                                "case": doc! { "$eq": ["$action", "BLACKLIST_ADD"] },
                                "then": "Blacklisted Network"
                            },
                        ],
                        "default": doc! {
                            "$cond": doc! {
                                "if": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"Risk level:\s*[CH]", "options": "i" } },
                                "then": "High/Critical Risk",
                                "else": null
                            }
                        }
                    }
                }
            }
        },
        doc! {
            "$match": doc! {
                "threat_type": doc! { "$ne": null }
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "date": "$date",
                    "threat_type": "$threat_type"
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$project": doc! {
                "_id": 0,
                "date": "$_id.date",
                "threat_type": "$_id.threat_type",
                "count": 1
            }
        },
        doc! {
            "$sort": doc! { "date": 1, "threat_type": 1 }
        },
    ];
    
    let mut threat_type_timepoints = Vec::new();
    match logs_coll.aggregate(threat_type_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(date), Some(threat_type), Some(count)) = (
                    doc.get("date").and_then(|v| v.as_str()),
                    doc.get("threat_type").and_then(|v| v.as_str()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    threat_type_timepoints.push(ThreatTypeTimePoint {
                        date: date.to_string(),
                        threat_type: threat_type.to_string(),
                        count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating threat types over time: {}", e);
        }
    }
    
    // Threat Type Distribution - with date filtering
    let now = Utc::now();
    let date_filter_start = match date_filter {
        "day" => DateTime::from_millis(now.timestamp_millis() - (24 * 60 * 60 * 1000)),
        "week" => DateTime::from_millis(now.timestamp_millis() - (7 * 24 * 60 * 60 * 1000)),
        "month" => DateTime::from_millis(now.timestamp_millis() - (30 * 24 * 60 * 60 * 1000)),
        "year" => DateTime::from_millis(now.timestamp_millis() - (365 * 24 * 60 * 60 * 1000)),
        _ => DateTime::from_millis(0), // "all" - use epoch start
    };
    
    let mut base_filter = doc! {
        "user_id": &user.user_id
    };
    
    if date_filter != "all" {
        base_filter.insert("timestamp", doc! { "$gte": date_filter_start });
    }
    
    let rogue_aps = logs_coll.count_documents(
        doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"rogue", "$options": "i" }
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let evil_twins = logs_coll.count_documents(
        doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"evil.*twin", "$options": "i" }
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let suspicious_open = logs_coll.count_documents(
        doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "$or": [
                        { "details": doc! { "$regex": r"open.*network|no.*encryption", "$options": "i" } },
                        { "details": doc! { "$regex": r"Authentication:\s*Open", "$options": "i" } },
                        { "details": doc! { "$regex": r"Encryption:\s*None", "$options": "i" } },
                    ]
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let weak_encryption = logs_coll.count_documents(
        doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"weak.*encryption|WEP|TKIP", "$options": "i" }
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let deauth_attacks = logs_coll.count_documents(
        doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"deauth", "$options": "i" }
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let mac_spoof = logs_coll.count_documents(
        doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"spoof|MAC.*spoof", "$options": "i" }
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    let blacklisted_detected = logs_coll.count_documents(
        doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "action": "BLACKLIST_ADD"
                }
            ]
        }
    ).await.unwrap_or(0) as i64;
    
    // Channel Usage - Since channels aren't in logs, we'll derive from connection attempts
    // For now, we'll use placeholder logic - this can be enhanced when channel data is available
    let channel_1 = logs_coll.count_documents(
        doc! {
            "user_id": &user.user_id,
            "details": doc! { "$regex": r"channel.*1\b|Channel.*1\b", "$options": "i" }
        }
    ).await.unwrap_or(0) as i64;
    
    let channel_6 = logs_coll.count_documents(
        doc! {
            "user_id": &user.user_id,
            "details": doc! { "$regex": r"channel.*6\b|Channel.*6\b", "$options": "i" }
        }
    ).await.unwrap_or(0) as i64;
    
    let channel_11 = logs_coll.count_documents(
        doc! {
            "user_id": &user.user_id,
            "details": doc! { "$regex": r"channel.*11\b|Channel.*11\b", "$options": "i" }
        }
    ).await.unwrap_or(0) as i64;
    
    // For 5 GHz channels, we'll need to extract from details or use a placeholder
    let mut channels_5ghz = Vec::new();
    // Common 5 GHz channels: 36, 40, 44, 48, 149, 153, 157, 161, 165
    let common_5ghz = vec![36, 40, 44, 48, 149, 153, 157, 161, 165];
    for channel in common_5ghz {
        let count = logs_coll.count_documents(
            doc! {
                "user_id": &user.user_id,
                "details": doc! { "$regex": format!(r"channel.*{}\b|Channel.*{}\b", channel, channel), "$options": "i" }
            }
        ).await.unwrap_or(0) as i64;
        if count > 0 {
            channels_5ghz.push(Channel5Ghz {
                channel,
                count,
            });
        }
    }
    
    // Top Suspicious Networks
    let suspicious_networks_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "$or": [
                    { "details": doc! { "$regex": r"Risk level:\s*(C|H|M)|\(Critical\)|\(High\)|\(Medium\)", "$options": "i" } },
                    { "action": "BLACKLIST_ADD" },
                    { "details": doc! { "$regex": r"evil.*twin|rogue|deauth|spoof|weak.*encryption|open.*network", "$options": "i" } },
                ],
                "network_ssid": doc! { "$exists": true, "$ne": "", "$ne": "-", "$ne": null },
                "network_bssid": doc! { "$exists": true, "$ne": "", "$ne": null },
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "ssid": "$network_ssid",
                    "bssid": "$network_bssid"
                },
                "threat_count": doc! { "$sum": 1 },
                "risk_level": doc! {
                    "$max": doc! {
                        "$switch": doc! {
                            "branches": vec![
                                doc! {
                                    "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"Risk level:\s*C|\(Critical\)", "options": "i" } },
                                    "then": 4
                                },
                                doc! {
                                    "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"Risk level:\s*H|\(High\)", "options": "i" } },
                                    "then": 3
                                },
                                doc! {
                                    "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"Risk level:\s*M|\(Medium\)", "options": "i" } },
                                    "then": 2
                                },
                            ],
                            "default": 1
                        }
                    }
                }
            }
        },
        doc! {
            "$project": doc! {
                "_id": 0,
                "ssid": "$_id.ssid",
                "bssid": "$_id.bssid",
                "threat_count": 1,
                "risk_level": doc! {
                    "$switch": doc! {
                        "branches": vec![
                            doc! { "case": doc! { "$eq": ["$risk_level", 4] }, "then": "C" },
                            doc! { "case": doc! { "$eq": ["$risk_level", 3] }, "then": "H" },
                            doc! { "case": doc! { "$eq": ["$risk_level", 2] }, "then": "M" },
                        ],
                        "default": "L"
                    }
                }
            }
        },
        doc! {
            "$sort": doc! { "threat_count": -1, "risk_level": -1 }
        },
        doc! {
            "$limit": 10
        },
    ];
    
    let mut top_suspicious = Vec::new();
    match logs_coll.aggregate(suspicious_networks_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(ssid), Some(bssid), Some(threat_count), Some(risk_score)) = (
                    doc.get("ssid").and_then(|v| v.as_str()),
                    doc.get("bssid").and_then(|v| v.as_str()),
                    doc.get("threat_count").and_then(|v| v.as_i64()),
                    doc.get("risk_level").and_then(|v| v.as_str()),
                ) {
                    top_suspicious.push(TopSuspiciousNetwork {
                        ssid: ssid.to_string(),
                        bssid: bssid.to_string(),
                        risk_score: risk_score.to_string(),
                        threat_count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating top suspicious networks: {}", e);
        }
    }
    
    let analytics = AnalyticsResponse {
        security_metrics: SecurityMetrics {
            high_risk_connections: high_risk,
            medium_risk_connections: medium_risk,
            low_risk_connections: low_risk,
            failed_attempts,
            successful_connections,
        },
        connection_stats: ConnectionStats {
            total_connections,
            connection_success_rate,
            total_scan_attempts: total_scans,
            avg_connections_per_day,
        },
        blacklist_whitelist: BlacklistWhitelistStats {
            total_blacklisted,
            total_whitelisted,
            blacklist_additions,
            blacklist_removals,
            whitelist_additions,
            whitelist_removals,
            blacklist_additions_today,
            blacklist_removals_today,
            whitelist_additions_today,
            whitelist_removals_today,
            blacklist_additions_week,
            blacklist_removals_week,
            whitelist_additions_week,
            whitelist_removals_week,
            blacklist_additions_month,
            blacklist_removals_month,
            whitelist_additions_month,
            whitelist_removals_month,
        },
        user_activity: UserActivityStats {
            password_changes,
            username_changes,
            profile_updates,
            profile_save_attempts,
        },
        network_stats: NetworkStats {
            most_scanned_networks: most_scanned,
            unique_networks_scanned: unique_networks,
        },
        time_series: TimeSeriesData {
            daily_activity,
            hourly_activity,
        },
        threat_analytics: ThreatAnalytics {
            threats_over_time: ThreatsOverTime {
                daily: daily_threats,
                weekly: weekly_threats,
                monthly: monthly_threats,
                by_type: threat_type_timepoints,
            },
            threat_type_distribution: ThreatTypeDistribution {
                rogue_aps,
                evil_twins,
                suspicious_open_networks: suspicious_open,
                weak_encryption,
                deauth_attacks,
                mac_spoof_attempts: mac_spoof,
                blacklisted_networks_detected: blacklisted_detected,
            },
            channel_usage: ChannelUsage {
                channel_1,
                channel_6,
                channel_11,
                channels_5ghz,
            },
            top_suspicious_networks: top_suspicious,
        },
    };
    
    Json(analytics).into_response()
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
    pub captcha_token: String,
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
    pub captcha_token: String,
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

//---------------------------------------------------------------------------- Profile
#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: String,
    pub profiling_preference: String, // "speed", "security", "balanced"
    pub speed_network_preference: String, // "high", "medium", "low"
    pub confidence_level: String, // "high", "medium", "low"
    pub profile_type: String, // "personal", "work", "public"
    pub network_preference: String, // "more_speed_less_security", "balanced", "more_security_less_speed"
    pub preferred_authentication: Vec<String>, // e.g., ["WPA3", "WPA2"]
    pub min_signal_strength: Option<i32>, // minimum signal strength percentage
    pub max_risk_level: Option<String>, // "L", "M", "H", "C"
}

#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub id: String,
    pub profiling_preference: String,
    pub speed_network_preference: String,
    pub confidence_level: String,
    pub profile_type: String,
    pub network_preference: String,
    pub preferred_authentication: Vec<String>,
    pub min_signal_strength: Option<i32>,
    pub max_risk_level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub profiling_preference: Option<String>,
    pub speed_network_preference: Option<String>,
    pub confidence_level: Option<String>,
    pub profile_type: Option<String>,
    pub network_preference: Option<String>,
    pub preferred_authentication: Option<Vec<String>>,
    pub min_signal_strength: Option<i32>,
    pub max_risk_level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangeUsernameRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

static HTTP_CLIENT: Lazy<ReqwestClient> = Lazy::new(|| ReqwestClient::new());

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

#[derive(Debug, Deserialize)]
struct RecaptchaResponse {
    success: bool,
    #[allow(dead_code)]
    challenge_ts: Option<String>,
    #[allow(dead_code)]
    hostname: Option<String>,
    #[allow(dead_code)]
    score: Option<f32>,
    #[allow(dead_code)]
    action: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

async fn ensure_recaptcha(token: &str) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let secret = env::var("RECAPTCHA_SECRET").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Captcha not configured"})),
        )
    })?;

    let resp = HTTP_CLIENT
        .post("https://www.google.com/recaptcha/api/siteverify")
        .form(&[("secret", secret), ("response", token.to_string())])
        .send()
        .await
        .map_err(|err| {
            eprintln!("Recaptcha request failed: {err:?}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "Captcha verification failed"})),
            )
        })?;

    let body: RecaptchaResponse = resp.json().await.map_err(|err| {
        eprintln!("Recaptcha parse failed: {err:?}");
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "Captcha verification failed"})),
        )
    })?;

    if !body.success {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Captcha verification failed"})),
        ));
    }

    Ok(())
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
    if let Err(err) = ensure_recaptcha(&payload.captcha_token).await {
        return err.into_response();
    }

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
    if let Err(err) = ensure_recaptcha(&payload.captcha_token).await {
        return err.into_response();
    }

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

async fn get_user_profile(user: AuthUser) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let profiles_doc: Collection<Document> = db.collection("UserProfiles");
    let profiles: Collection<UserProfile> = db.collection("UserProfiles");
    
    match profiles.find_one(doc! { "user_id": &user.user_id }).await {
        Ok(Some(profile)) => {
            Json(UserProfileResponse {
                id: profile.id.to_hex(),
                profiling_preference: profile.profiling_preference,
                speed_network_preference: profile.speed_network_preference,
                confidence_level: profile.confidence_level,
                profile_type: profile.profile_type,
                network_preference: profile.network_preference,
                preferred_authentication: profile.preferred_authentication,
                min_signal_strength: profile.min_signal_strength,
                max_risk_level: profile.max_risk_level,
            }).into_response()
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
                network_preference: "balanced".to_string(),
                preferred_authentication: vec!["WPA3".to_string(), "WPA2".to_string()],
                min_signal_strength: Some(50),
                max_risk_level: Some("M".to_string()),
            };
            let new_doc = doc! {
                "user_id": &user.user_id,
                "profiling_preference": &default_profile.profiling_preference,
                "speed_network_preference": &default_profile.speed_network_preference,
                "confidence_level": &default_profile.confidence_level,
                "profile_type": &default_profile.profile_type,
                "network_preference": &default_profile.network_preference,
                "preferred_authentication": &default_profile.preferred_authentication,
                "min_signal_strength": &default_profile.min_signal_strength,
                "max_risk_level": &default_profile.max_risk_level,
            };
            profiles_doc.insert_one(new_doc).await.unwrap();
            Json(UserProfileResponse {
                id: default_profile.id.to_hex(),
                profiling_preference: default_profile.profiling_preference,
                speed_network_preference: default_profile.speed_network_preference,
                confidence_level: default_profile.confidence_level,
                profile_type: default_profile.profile_type,
                network_preference: default_profile.network_preference,
                preferred_authentication: default_profile.preferred_authentication,
                min_signal_strength: default_profile.min_signal_strength,
                max_risk_level: default_profile.max_risk_level,
            }).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ).into_response()
    }
}

async fn update_user_profile(
    user: AuthUser,
    Json(payload): Json<UpdateProfileRequest>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let profiles: Collection<Document> = db.collection("UserProfiles");
    
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
    if let Some(ref val) = payload.network_preference {
        update_doc.insert("network_preference", val);
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
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No fields to update"})),
        ).into_response();
    }
    
    let filter = doc! { "user_id": &user.user_id };
    let update = doc! { "$set": update_doc };
    
    match profiles.update_one(filter, update).await {
        Ok(result) if result.matched_count > 0 => {
            (StatusCode::OK, Json(json!({"status": "profile_updated"}))).into_response()
        }
        Ok(_) => {
            // Create profile if it doesn't exist
            let default_profile = doc! {
                "user_id": &user.user_id,
                "profiling_preference": payload.profiling_preference.unwrap_or_else(|| "balanced".to_string()),
                "speed_network_preference": payload.speed_network_preference.unwrap_or_else(|| "medium".to_string()),
                "confidence_level": payload.confidence_level.unwrap_or_else(|| "medium".to_string()),
                "profile_type": payload.profile_type.unwrap_or_else(|| "personal".to_string()),
                "network_preference": payload.network_preference.unwrap_or_else(|| "balanced".to_string()),
                "preferred_authentication": payload.preferred_authentication.unwrap_or_else(|| vec!["WPA3".to_string(), "WPA2".to_string()]),
                "min_signal_strength": payload.min_signal_strength.unwrap_or(50),
                "max_risk_level": payload.max_risk_level.unwrap_or_else(|| "M".to_string()),
            };
            profiles.insert_one(default_profile).await.unwrap();
            (StatusCode::OK, Json(json!({"status": "profile_created"}))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ).into_response()
    }
}

async fn change_username_handler(
    user: AuthUser,
    Json(payload): Json<ChangeUsernameRequest>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let users: Collection<Document> = db.collection("Users");
    
    let obj_id = match ObjectId::parse_str(&user.user_id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid user ID"})),
            ).into_response();
        }
    };
    
    match users.update_one(
        doc! { "_id": obj_id },
        doc! { "$set": { "username": &payload.username } }
    ).await {
        Ok(result) if result.matched_count > 0 => {
            (StatusCode::OK, Json(json!({"status": "username_updated", "username": payload.username}))).into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ).into_response()
    }
}

async fn change_password_handler(
    user: AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let db = get_collection().await.unwrap();
    let users: Collection<User> = db.collection("Users");
    
    let obj_id = match ObjectId::parse_str(&user.user_id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid user ID"})),
            ).into_response();
        }
    };
    
    let user_doc = match users.find_one(doc! { "_id": obj_id }).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "User not found"})),
            ).into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            ).into_response();
        }
    };
    
    // Verify current password
    let valid = match verify(&payload.current_password, &user_doc.password_hash) {
        Ok(is_valid) => is_valid,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Password verification failed"})),
            ).into_response();
        }
    };
    
    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid current password"})),
        ).into_response();
    }
    
    // Hash new password
    let password_hash = match hash(&payload.new_password, 10) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to hash password"})),
            ).into_response();
        }
    };
    
    // Update password
    match users.update_one(
        doc! { "_id": obj_id },
        doc! { "$set": { "password_hash": &password_hash } }
    ).await {
        Ok(result) if result.matched_count > 0 => {
            (StatusCode::OK, Json(json!({"status": "password_updated"}))).into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "User not found"})),
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ).into_response()
    }
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
        .route("/logs/export", get(export_logs))
        .route("/profile", get(get_user_profile).post(update_user_profile))
        .route("/profile/username", post(change_username_handler))
        .route("/profile/password", post(change_password_handler))
        .route("/analytics", get(get_analytics))
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
