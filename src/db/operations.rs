use axum::{
    http::StatusCode,
    response::Response,
};
use chrono::TimeZone;
use mongodb::{
    bson::{doc, Document},
    Collection, Database,
};
use serde_json::json;

use crate::utils::{error_response, success_response};

/// Generic function to delete a document by ID with user_id check
pub async fn delete_by_id(
    db: &Database,
    collection_name: &str,
    id: &str,
    user_id: &str,
) -> Response {
    let obj_id = match mongodb::bson::oid::ObjectId::parse_str(id) {
        Ok(id) => id,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "Invalid id");
        }
    };

    let coll: Collection<Document> = db.collection(collection_name);
    let filter = doc! { "_id": obj_id, "user_id": user_id };

    match coll.delete_one(filter).await {
        Ok(res) if res.deleted_count == 1 => {
            success_response(StatusCode::OK, json!({"status": "deleted"}))
        }
        Ok(_) => error_response(StatusCode::NOT_FOUND, "Not found"),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Helper to build date filter for MongoDB queries
pub fn build_date_filter(
    date_str: Option<&String>,
) -> Option<Document> {
    date_str.and_then(|date_str| {
        chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
            .ok()
            .map(|parsed_date| {
                let start = chrono::Utc
                    .from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
                let end = chrono::Utc
                    .from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());
                doc! {
                    "$gte": mongodb::bson::DateTime::from_millis(start.timestamp_millis()),
                    "$lte": mongodb::bson::DateTime::from_millis(end.timestamp_millis())
                }
            })
    })
}

/// Helper to build regex filter for text search
#[allow(dead_code)] // May be useful for future text search features
pub fn build_regex_filter(field: &str, value: &str) -> Document {
    doc! { field: { "$regex": value, "$options": "i" } }
}

