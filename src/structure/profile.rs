use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub user_id: String,
    pub profiling_preference: String, // "speed", "security", "balanced"
    pub speed_network_preference: String, // "high", "medium", "low"
    pub confidence_level: String, // "high", "medium", "low"
    pub profile_type: String, // "personal", "work"
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
    pub preferred_authentication: Option<Vec<String>>,
    pub min_signal_strength: Option<i32>,
    pub max_risk_level: Option<String>,
}

impl From<UserProfile> for UserProfileResponse {
    fn from(profile: UserProfile) -> Self {
        UserProfileResponse {
            id: profile.id.to_hex(),
            profiling_preference: profile.profiling_preference,
            speed_network_preference: profile.speed_network_preference,
            confidence_level: profile.confidence_level,
            profile_type: profile.profile_type,
            preferred_authentication: profile.preferred_authentication,
            min_signal_strength: profile.min_signal_strength,
            max_risk_level: profile.max_risk_level,
        }
    }
}

