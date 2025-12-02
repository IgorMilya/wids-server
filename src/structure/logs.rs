use mongodb::bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};
use crate::utils::serialize_datetime_as_iso_string;

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

