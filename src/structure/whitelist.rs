use mongodb::bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};
use crate::utils::serialize_datetime_as_iso_string;

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
    pub ssid: String,
    pub bssid: String,
}

impl From<WhitelistedNetwork> for WhitelistedNetworkResponse {
    fn from(network: WhitelistedNetwork) -> Self {
        WhitelistedNetworkResponse {
            id: network.id.to_hex(),
            ssid: network.ssid,
            bssid: network.bssid,
            timestamp: network.timestamp,
        }
    }
}

