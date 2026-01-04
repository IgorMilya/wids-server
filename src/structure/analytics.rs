use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NetworkStats {
    pub most_scanned_networks: Vec<MostScannedNetwork>,
    pub unique_networks_scanned: i64,
}

#[derive(Debug, Serialize)]
pub struct MostScannedNetwork {
    pub ssid: String,
    pub bssid: String,
    pub scan_count: i64,
}

#[derive(Debug, Serialize)]
pub struct TimeSeriesData {
    pub daily_activity: Vec<DailyActivity>,
    pub hourly_activity: Vec<HourlyActivity>,
}


#[derive(Debug, Serialize)]
pub struct HourlyActivity {
    pub hour: i32,
    pub activity_count: i64,
}

#[derive(Debug, Serialize)]
pub struct ThreatsOverTime {
    pub daily: Vec<ThreatTimePoint>,
    pub weekly: Vec<ThreatTimePoint>,
    pub monthly: Vec<ThreatTimePoint>,
    pub by_type: Vec<ThreatTypeTimePoint>,
}

#[derive(Debug, Serialize)]
pub struct ThreatTimePoint {
    pub date: String,
    pub total_threats: i64,
}

#[derive(Debug, Serialize)]
pub struct ThreatTypeTimePoint {
    pub date: String,
    pub threat_type: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct ThreatTypeDistribution {
    pub rogue_aps: i64,
    pub evil_twins: i64,
    pub suspicious_open_networks: i64,
    pub weak_encryption: i64,
    pub deauth_attacks: i64,
    pub mac_spoof_attempts: i64,
    pub blacklisted_networks_detected: i64,
}

#[derive(Debug, Serialize)]
pub struct ChannelUsage {
    pub channel_1: i64,
    pub channel_6: i64,
    pub channel_11: i64,
    pub channels_5ghz: Vec<Channel5Ghz>,
}

#[derive(Debug, Serialize)]
pub struct Channel5Ghz {
    pub channel: i32,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct TopSuspiciousNetwork {
    pub ssid: String,
    pub bssid: String,
    pub risk_score: String, 
    pub threat_count: i64,
}

#[derive(Debug, Serialize)]
pub struct ThreatAnalytics {
    pub threats_over_time: ThreatsOverTime,
    pub threat_type_distribution: ThreatTypeDistribution,
    pub channel_usage: ChannelUsage,
    pub top_suspicious_networks: Vec<TopSuspiciousNetwork>,
}

#[derive(Debug, Serialize)]
pub struct SecurityMetrics {
    pub high_risk_connections: i64,
    pub medium_risk_connections: i64,
    pub low_risk_connections: i64,
    pub failed_attempts: i64,
    pub successful_connections: i64,
    pub blacklisted_networks_detected: i64,
}

#[derive(Debug, Serialize)]
pub struct ConnectionStats {
    pub total_connections: i64,
    pub connection_success_rate: f64,
    pub total_scan_attempts: i64,
    pub avg_connections_per_day: f64,
}

#[derive(Debug, Serialize)]
pub struct BlacklistWhitelistStats {
    pub total_blacklisted: i64,
    pub total_whitelisted: i64,
    pub blacklist_additions: i64,
    pub blacklist_removals: i64,
    pub whitelist_additions: i64,
    pub whitelist_removals: i64,
    pub blacklist_additions_today: i64,
    pub blacklist_removals_today: i64,
    pub whitelist_additions_today: i64,
    pub whitelist_removals_today: i64,
    pub blacklist_additions_week: i64,
    pub blacklist_removals_week: i64,
    pub whitelist_additions_week: i64,
    pub whitelist_removals_week: i64,
    pub blacklist_additions_month: i64,
    pub blacklist_removals_month: i64,
    pub whitelist_additions_month: i64,
    pub whitelist_removals_month: i64,
}

#[derive(Debug, Serialize)]
pub struct UserActivityStats {
    pub password_changes: i64,
    pub username_changes: i64,
    pub profile_updates: i64,
    pub profile_save_attempts: i64,
}

#[allow(dead_code)] 
#[derive(Debug, Serialize)]
pub struct NetworkScanCount {
    pub ssid: String,
    pub scan_count: i64,
}

#[derive(Debug, Serialize)]
pub struct DailyActivity {
    pub date: String,
    pub scans: i64,
    pub connections: i64,
    pub blacklist_adds: i64,
    pub whitelist_adds: i64,
}

#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    pub security_metrics: SecurityMetrics,
    pub connection_stats: ConnectionStats,
    pub blacklist_whitelist: BlacklistWhitelistStats,
    pub user_activity: UserActivityStats,
    pub network_stats: NetworkStats,
    pub time_series: TimeSeriesData,
    pub threat_analytics: ThreatAnalytics,
}

