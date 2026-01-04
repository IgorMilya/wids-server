
use mongodb::bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};
use crate::utils::serialize_datetime_as_iso_string;

#[allow(dead_code)] 
#[derive(Debug, Serialize, Deserialize)]
pub struct Threat {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: String,
    pub threat_type: String,
    pub severity: String,
    pub network_ssid: String,
    pub network_bssid: String,
    pub details: String,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub timestamp: DateTime,
    pub acknowledged: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ThreatAlert {
    pub threat_type: String,
    pub severity: String,
    pub network_ssid: String,
    pub network_bssid: String,
    pub details: String,
    pub timestamp: String, 
}

#[allow(dead_code)] 
#[derive(Debug, Serialize)]
pub struct ThreatResponse {
    pub id: String,
    pub threat_type: String,
    pub severity: String,
    pub network_ssid: String,
    pub network_bssid: String,
    pub details: String,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub timestamp: DateTime,
    pub acknowledged: bool,
}

