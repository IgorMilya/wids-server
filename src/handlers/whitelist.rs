use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use futures::TryStreamExt;
use mongodb::bson::{doc, DateTime};
use mongodb::Collection;
use std::collections::HashMap;

use crate::{
    db::{get_database, get_collection, operations::build_date_filter},
    middleware::auth::AuthUser,
    structure::whitelist::{WhitelistedNetwork, WhitelistedNetworkResponse, NewWhitelistEntry},
    utils::{error_response, success_response},
};

pub async fn get_whitelist(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let coll: Collection<WhitelistedNetwork> = get_collection(&db, "Whitelist");
    let mut filter = doc! { "user_id": &user.user_id };

    if let Some(ssid) = params.get("ssid") {
        filter.insert("ssid", doc! { "$regex": ssid, "$options": "i" });
    }

    if let Some(date_filter) = build_date_filter(params.get("date")) {
        filter.insert("timestamp", date_filter);
    }

    let mut cursor = match coll.find(filter).await {
        Ok(cursor) => cursor,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

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

pub async fn delete_from_whitelist(user: AuthUser, Path(id): Path<String>) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    crate::db::operations::delete_by_id(&db, "Whitelist", &id, &user.user_id).await
}

pub async fn add_to_whitelist(
    user: AuthUser,
    Json(payload): Json<NewWhitelistEntry>,
) -> impl IntoResponse {
    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };

    let coll: Collection<mongodb::bson::Document> = get_collection(&db, "Whitelist");
    let new_doc = doc! {
        "ssid": payload.ssid,
        "bssid": payload.bssid,
        "timestamp": DateTime::now(),
        "user_id": user.user_id,
    };

    match coll.insert_one(new_doc).await {
        Ok(_) => success_response(
            StatusCode::CREATED,
            serde_json::json!({"status": "added"}),
        ),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

