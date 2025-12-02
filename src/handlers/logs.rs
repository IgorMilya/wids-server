use axum::{
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{TimeZone, Utc};
use futures::TryStreamExt;
use mongodb::bson::{doc, DateTime};
use mongodb::Collection;
use std::collections::HashMap;

use crate::{
    db::{get_database, get_collection},
    middleware::auth::AuthUser,
    structure::logs::{LogEntry, NewLogEntry},
    utils::{error_response, success_response},
};

pub async fn add_log(user: AuthUser, Json(payload): Json<NewLogEntry>) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let coll: Collection<mongodb::bson::Document> = get_collection(&db, "Logs");
    let new_doc = doc! {
        "user_id": user.user_id,
        "network_ssid": payload.network_ssid,
        "network_bssid": payload.network_bssid,
        "action": payload.action,
        "timestamp": DateTime::now(),
        "details": payload.details.unwrap_or("".into()),
    };

    match coll.insert_one(new_doc).await {
        Ok(_) => success_response(
            StatusCode::CREATED,
            serde_json::json!({"status": "logged"}),
        ),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn get_logs(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let coll: Collection<LogEntry> = get_collection(&db, "Logs");
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
            filter.insert("timestamp", doc! {
                "$gte": DateTime::from_millis(start.timestamp_millis()),
                "$lte": DateTime::from_millis(end.timestamp_millis())
            });
        }
    }

    // Parse pagination params
    let page: u64 = params.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let limit: u64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(11);
    let skip: u64 = (page - 1) * limit;

    // Parse sort parameters
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
    let mut cursor = match coll
        .find(filter)
        .sort(sort_options)
        .skip(skip)
        .limit(limit as i64)
        .await
    {
        Ok(cursor) => cursor,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let mut results = Vec::new();
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        results.push(doc);
    }

    Json(serde_json::json!({ "total": total, "logs": results })).into_response()
}

pub async fn export_logs(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let coll: Collection<LogEntry> = get_collection(&db, "Logs");
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

    // Support date range filtering
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
            filter.insert("timestamp", doc! {
                "$gte": DateTime::from_millis(start.timestamp_millis()),
                "$lte": DateTime::from_millis(end.timestamp_millis())
            });
        }
    }

    let mut cursor = match coll.find(filter).await {
        Ok(cursor) => cursor,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let mut results = Vec::new();
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        results.push(doc);
    }

    Json(results).into_response()
}

