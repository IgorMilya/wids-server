
use mongodb::bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};
use crate::utils::serialize_datetime_as_iso_string;

#[allow(dead_code)] 
#[derive(Debug, Serialize, Deserialize)]
pub struct MonitoringPreferences {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: String,
    pub enabled: bool,
    pub interval_seconds: u64,
    pub alert_types: Vec<String>,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub updated_at: DateTime,
}

#[allow(dead_code)] 
#[derive(Debug, Deserialize)]
pub struct UpdateMonitoringPreferencesRequest {
    pub enabled: Option<bool>,
    pub interval_seconds: Option<u64>,
    pub alert_types: Option<Vec<String>>,
}

#[allow(dead_code)] 
#[derive(Debug, Serialize)]
pub struct MonitoringPreferencesResponse {
    pub id: String,
    pub enabled: bool,
    pub interval_seconds: u64,
    pub alert_types: Vec<String>,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub updated_at: DateTime,
}

