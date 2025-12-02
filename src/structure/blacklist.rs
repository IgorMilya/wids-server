use mongodb::bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};
use crate::utils::serialize_datetime_as_iso_string;

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
    pub ssid: String,
    pub bssid: String,
    pub reason: Option<String>,
}

impl From<BlacklistedNetwork> for BlacklistedNetworkResponse {
    fn from(network: BlacklistedNetwork) -> Self {
        BlacklistedNetworkResponse {
            id: network.id.to_hex(),
            ssid: network.ssid,
            bssid: network.bssid,
            timestamp: network.timestamp,
            reason: network.reason,
        }
    }
}

