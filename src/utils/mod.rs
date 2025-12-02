use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use mongodb::bson::DateTime;
use serde::Serializer;
use serde_json::json;

pub mod jwt;
pub mod email;
pub mod recaptcha;
pub mod password;
pub mod code;
pub mod rate_limit;

/// Serialize DateTime as ISO string
pub fn serialize_datetime_as_iso_string<S>(
    date: &DateTime,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(
        &date
            .try_to_rfc3339_string()
            .unwrap_or_else(|_| "Invalid Date".into()),
    )
}

/// Helper to create error response
pub fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

/// Helper to create success response
pub fn success_response<T: serde::Serialize>(status: StatusCode, data: T) -> Response {
    (status, Json(data)).into_response()
}

