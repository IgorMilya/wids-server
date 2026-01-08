use axum::{
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::bson::{doc, DateTime};
use mongodb::Collection;
use std::collections::HashMap;

use crate::{
    db::{get_database, get_collection},
    middleware::auth::AuthUser,
    structure::analytics::{
        AnalyticsResponse, BlacklistWhitelistStats, Channel5Ghz, ChannelUsage, ConnectionStats,
        DailyActivity, HourlyActivity, MostScannedNetwork, NetworkStats,
        SecurityMetrics, ThreatAnalytics, ThreatTimePoint, ThreatTypeDistribution,
        ThreatTypeTimePoint, ThreatsOverTime, TimeSeriesData, TopSuspiciousNetwork,
        UserActivityStats,
    },
    utils::error_response,
};

pub async fn get_analytics(
    user: AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let date_filter = params
        .get("threat_date_filter")
        .map(|s| s.as_str())
        .unwrap_or("all");

    let db = match get_database().await {
        Ok(db) => db,
        Err(e) => {
            let msg = e.to_string();
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &msg);
        }
    };

    let logs_coll: Collection<mongodb::bson::Document> = get_collection(&db, "Logs");
    let blacklist_coll: Collection<mongodb::bson::Document> = get_collection(&db, "Blacklist");
    let whitelist_coll: Collection<mongodb::bson::Document> = get_collection(&db, "Whitelist");

    let user_filter = doc! { "user_id": &user.user_id };

    // ========== SECURITY METRICS ==========
    // High/Critical risk: Match the exact pattern with full label
    // Format: "Risk level: H (High)" or "Risk level: C (Critical)"
    // Use word boundaries and exact matching to prevent false positives
    let high_risk = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "$and": [
                {
                    "$or": [
                        { "action": "CONNECTED" },
                        { "action": "CONNECTED_RETRY" },
                    ]
                },
                {
                    "$or": [
                        // Match "Risk level: H (High)" - H must be followed by space, opening paren, then "High"
                        { "details": { "$regex": r"Risk level:\s*H\s*\(High\)", "$options": "i" } },
                        // Match "Risk level: C (Critical)" - C must be followed by space, opening paren, then "Critical"
                        { "details": { "$regex": r"Risk level:\s*C\s*\(Critical\)", "$options": "i" } },
                    ]
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    // Medium risk: Match "Risk level: M (Medium)" exactly
    let medium_risk = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "$and": [
                {
                    "$or": [
                        { "action": "CONNECTED" },
                        { "action": "CONNECTED_RETRY" },
                    ]
                },
                {
                    "details": { "$regex": r"Risk level:\s*M\s*\(Medium\)", "$options": "i" }
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    // Low/Whitelisted risk: Match "Risk level: L (Low)" or "Risk level: WL (Whitelisted)" exactly
    // CRITICAL: Must ensure L is followed by (Low), not (High) or any other label
    // The pattern explicitly requires L followed by space, opening paren, then "Low"
    let low_risk = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "$and": [
                {
                    "$or": [
                        { "action": "CONNECTED" },
                        { "action": "CONNECTED_RETRY" },
                    ]
                },
                {
                    "$or": [
                        // Match "Risk level: L (Low)" - L must be followed by space, opening paren, then "Low"
                        // This pattern CANNOT match "Risk level: H (High)" because L != H
                        { "details": { "$regex": r"Risk level:\s*L\s*\(Low\)", "$options": "i" } },
                        // Match "Risk level: WL (Whitelisted)" - WL must be followed by space, opening paren, then "Whitelisted"
                        { "details": { "$regex": r"Risk level:\s*WL\s*\(Whitelisted\)", "$options": "i" } },
                    ]
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let failed_attempts = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": { "$regex": "FAILED", "$options": "i" }
        })
        .await
        .unwrap_or(0) as i64;

    let successful_connections = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "$or": [
                { "action": "CONNECTED" },
                { "action": "CONNECTED_RETRY" },
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let blacklisted_networks_detected = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_ADD"
        })
        .await
        .unwrap_or(0) as i64;

    // ========== CONNECTION STATS ==========
    let total_connections = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "$or": [
                { "action": "CONNECTED" },
                { "action": "CONNECTED_RETRY" },
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let total_scans = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "SCAN_START"
        })
        .await
        .unwrap_or(0) as i64;

    let connection_success_rate = if total_connections > 0 {
        (successful_connections as f64 / total_connections as f64) * 100.0
    } else {
        0.0
    };

    let first_log = logs_coll
        .find_one(doc! { "user_id": &user.user_id })
        .sort(doc! { "timestamp": 1 })
        .await
        .ok()
        .flatten();

    let days_active = if let Some(log) = first_log {
        if let Some(ts) = log.get("timestamp").and_then(|v| v.as_datetime()) {
            let now = DateTime::now();
            let diff = now.timestamp_millis() - ts.timestamp_millis();
            (diff as f64 / (24.0 * 60.0 * 60.0 * 1000.0)).max(1.0)
        } else {
            1.0
        }
    } else {
        1.0
    };

    let avg_connections_per_day = total_connections as f64 / days_active;

    // ========== BLACKLIST/WHITELIST STATS ==========
    let total_blacklisted = blacklist_coll
        .count_documents(user_filter.clone())
        .await
        .unwrap_or(0) as i64;

    let total_whitelisted = whitelist_coll
        .count_documents(user_filter.clone())
        .await
        .unwrap_or(0) as i64;

    let blacklist_additions = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_ADD"
        })
        .await
        .unwrap_or(0) as i64;

    let blacklist_removals = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_DELETE"
        })
        .await
        .unwrap_or(0) as i64;

    let whitelist_additions = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "WHITELIST_ADD"
        })
        .await
        .unwrap_or(0) as i64;

    let whitelist_removals = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "WHITELIST_DELETE"
        })
        .await
        .unwrap_or(0) as i64;

    let today_start = DateTime::from_millis(
        Utc::now().timestamp_millis() - ((Utc::now().timestamp() % (24 * 60 * 60)) * 1000),
    );
    let week_ago = DateTime::from_millis(Utc::now().timestamp_millis() - (7 * 24 * 60 * 60 * 1000));
    let month_ago =
        DateTime::from_millis(Utc::now().timestamp_millis() - (30 * 24 * 60 * 60 * 1000));

    let blacklist_additions_today = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_ADD",
            "timestamp": doc! { "$gte": today_start }
        })
        .await
        .unwrap_or(0) as i64;

    let blacklist_removals_today = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_DELETE",
            "timestamp": doc! { "$gte": today_start }
        })
        .await
        .unwrap_or(0) as i64;

    let whitelist_additions_today = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "WHITELIST_ADD",
            "timestamp": doc! { "$gte": today_start }
        })
        .await
        .unwrap_or(0) as i64;

    let whitelist_removals_today = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "WHITELIST_DELETE",
            "timestamp": doc! { "$gte": today_start }
        })
        .await
        .unwrap_or(0) as i64;

    let blacklist_additions_week = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_ADD",
            "timestamp": doc! { "$gte": week_ago }
        })
        .await
        .unwrap_or(0) as i64;

    let blacklist_removals_week = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_DELETE",
            "timestamp": doc! { "$gte": week_ago }
        })
        .await
        .unwrap_or(0) as i64;

    let whitelist_additions_week = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "WHITELIST_ADD",
            "timestamp": doc! { "$gte": week_ago }
        })
        .await
        .unwrap_or(0) as i64;

    let whitelist_removals_week = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "WHITELIST_DELETE",
            "timestamp": doc! { "$gte": week_ago }
        })
        .await
        .unwrap_or(0) as i64;

    let blacklist_additions_month = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_ADD",
            "timestamp": doc! { "$gte": month_ago }
        })
        .await
        .unwrap_or(0) as i64;

    let blacklist_removals_month = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "BLACKLIST_DELETE",
            "timestamp": doc! { "$gte": month_ago }
        })
        .await
        .unwrap_or(0) as i64;

    let whitelist_additions_month = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "WHITELIST_ADD",
            "timestamp": doc! { "$gte": month_ago }
        })
        .await
        .unwrap_or(0) as i64;

    let whitelist_removals_month = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "WHITELIST_DELETE",
            "timestamp": doc! { "$gte": month_ago }
        })
        .await
        .unwrap_or(0) as i64;

    // ========== USER ACTIVITY STATS ==========
    let password_changes = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "PASSWORD_CHANGED"
        })
        .await
        .unwrap_or(0) as i64;

    let username_changes = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "USERNAME_CHANGED"
        })
        .await
        .unwrap_or(0) as i64;

    let profile_updates = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "$or": [
                { "action": "PROFILE_UPDATED" },
                { "action": { "$regex": "PROFILE_SETTING_CHANGED", "$options": "i" } },
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let profile_save_attempts = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "action": "PROFILE_SAVE_ATTEMPTED"
        })
        .await
        .unwrap_or(0) as i64;

    // ========== NETWORK STATS ==========
    let pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "network_ssid": doc! { "$exists": true, "$ne": "", "$ne": "-", "$ne": null }
            }
        },
        doc! {
            "$group": doc! {
                "_id": "$network_ssid",
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "count": -1 }
        },
        doc! {
            "$limit": 10
        },
    ];

    let mut most_scanned = Vec::new();
    match logs_coll.aggregate(pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(ssid), Some(count)) = (
                    doc.get("_id").and_then(|v| v.as_str()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    if !ssid.is_empty() && ssid != "-" {
                        // Get BSSID for this SSID (use first one found)
                        let bssid = logs_coll
                            .find_one(doc! {
                                "user_id": &user.user_id,
                                "network_ssid": ssid,
                                "network_bssid": doc! { "$exists": true, "$ne": null }
                            })
                            .await
                            .ok()
                            .flatten()
                            .and_then(|d| d.get("network_bssid").and_then(|v| v.as_str().map(|s| s.to_string())))
                            .unwrap_or_else(|| "-".to_string());

                        most_scanned.push(MostScannedNetwork {
                            ssid: ssid.to_string(),
                            bssid,
                            scan_count: count,
                        });
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating most scanned networks: {}", e);
        }
    }

    // Calculate networks in lists (blacklist + whitelist)
    let networks_in_lists = total_blacklisted + total_whitelisted;

    // ========== TIME SERIES DATA ==========
    let thirty_days_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (30 * 24 * 60 * 60 * 1000),
    );

    let daily_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": thirty_days_ago }
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-%m-%d",
                        "date": "$timestamp"
                    }
                },
                "scans": doc! {
                    "$sum": doc! {
                        "$cond": [doc! { "$eq": ["$action", "SCAN_START"] }, 1, 0]
                    }
                },
                "connections": doc! {
                    "$sum": doc! {
                        "$cond": [
                            doc! { "$in": ["$action", vec!["CONNECTED", "CONNECTED_RETRY"] ] },
                            1,
                            0
                        ]
                    }
                },
                "blacklist_adds": doc! {
                    "$sum": doc! {
                        "$cond": [doc! { "$eq": ["$action", "BLACKLIST_ADD"] }, 1, 0]
                    }
                },
                "whitelist_adds": doc! {
                    "$sum": doc! {
                        "$cond": [doc! { "$eq": ["$action", "WHITELIST_ADD"] }, 1, 0]
                    }
                },
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];

    let mut daily_activity = Vec::new();
    match logs_coll.aggregate(daily_pipeline).await {
        Ok(mut daily_cursor) => {
            while let Ok(Some(doc)) = daily_cursor.try_next().await {
                if let Some(date) = doc.get("_id").and_then(|v| v.as_str()) {
                    daily_activity.push(DailyActivity {
                        date: date.to_string(),
                        scans: doc.get("scans").and_then(|v| v.as_i64()).unwrap_or(0),
                        connections: doc.get("connections").and_then(|v| v.as_i64()).unwrap_or(0),
                        blacklist_adds: doc
                            .get("blacklist_adds")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0),
                        whitelist_adds: doc
                            .get("whitelist_adds")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0),
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating daily activity: {}", e);
        }
    }

    let seven_days_ago = DateTime::from_millis(Utc::now().timestamp_millis() - (7 * 24 * 60 * 60 * 1000));

    let hourly_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": seven_days_ago }
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$hour": "$timestamp"
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];

    let mut hourly_activity = Vec::new();
    match logs_coll.aggregate(hourly_pipeline).await {
        Ok(mut hourly_cursor) => {
            while let Ok(Some(doc)) = hourly_cursor.try_next().await {
                if let (Some(hour), Some(count)) = (
                    doc.get("_id").and_then(|v| v.as_i32()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    hourly_activity.push(HourlyActivity {
                        hour,
                        activity_count: count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating hourly activity: {}", e);
        }
    }

    for hour in 0..24 {
        if !hourly_activity.iter().any(|h| h.hour == hour) {
            hourly_activity.push(HourlyActivity {
                hour,
                activity_count: 0,
            });
        }
    }
    hourly_activity.sort_by_key(|h| h.hour);

    // ========== THREAT ANALYTICS ==========
    let thirty_days_ago_dt = DateTime::from_millis(
        Utc::now().timestamp_millis() - (30 * 24 * 60 * 60 * 1000),
    );

    let daily_threats_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": thirty_days_ago_dt },
                "$or": [
                    { "details": doc! { "$regex": r"Risk level:\s*(C|H|M)|\(Critical\)|\(High\)|\(Medium\)", "$options": "i" } },
                    { "action": "BLACKLIST_ADD" },
                    { "details": doc! { "$regex": r"evil.*twin|rogue|deauth|spoof|weak.*encryption|open.*network", "$options": "i" } },
                ]
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-%m-%d",
                        "date": "$timestamp"
                    }
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];

    let mut daily_threats = Vec::new();
    match logs_coll.aggregate(daily_threats_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(date), Some(count)) = (
                    doc.get("_id").and_then(|v| v.as_str()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    daily_threats.push(ThreatTimePoint {
                        date: date.to_string(),
                        total_threats: count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating daily threats: {}", e);
        }
    }

    let twelve_weeks_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (12 * 7 * 24 * 60 * 60 * 1000),
    );

    let weekly_threats_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": twelve_weeks_ago },
                "$or": [
                    { "details": doc! { "$regex": r"Risk level:\s*(C|H|M)|\(Critical\)|\(High\)|\(Medium\)", "$options": "i" } },
                    { "action": "BLACKLIST_ADD" },
                    { "details": doc! { "$regex": r"evil.*twin|rogue|deauth|spoof|weak.*encryption|open.*network", "$options": "i" } },
                ]
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-W%V",
                        "date": "$timestamp"
                    }
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];

    let mut weekly_threats = Vec::new();
    match logs_coll.aggregate(weekly_threats_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(date_str)) = cursor.try_next().await {
                if let (Some(date), Some(count)) = (
                    date_str.get("_id").and_then(|v| v.as_str()),
                    date_str.get("count").and_then(|v| v.as_i64()),
                ) {
                    weekly_threats.push(ThreatTimePoint {
                        date: date.to_string(),
                        total_threats: count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating weekly threats: {}", e);
        }
    }

    let twelve_months_ago = DateTime::from_millis(
        Utc::now().timestamp_millis() - (12 * 30 * 24 * 60 * 60 * 1000),
    );

    let monthly_threats_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": twelve_months_ago },
                "$or": [
                    { "details": doc! { "$regex": r"Risk level:\s*(C|H|M)|\(Critical\)|\(High\)|\(Medium\)", "$options": "i" } },
                    { "action": "BLACKLIST_ADD" },
                    { "details": doc! { "$regex": r"evil.*twin|rogue|deauth|spoof|weak.*encryption|open.*network", "$options": "i" } },
                ]
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-%m",
                        "date": "$timestamp"
                    }
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$sort": doc! { "_id": 1 }
        },
    ];

    let mut monthly_threats = Vec::new();
    match logs_coll.aggregate(monthly_threats_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(date), Some(count)) = (
                    doc.get("_id").and_then(|v| v.as_str()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    monthly_threats.push(ThreatTimePoint {
                        date: date.to_string(),
                        total_threats: count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating monthly threats: {}", e);
        }
    }

    let threat_type_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "timestamp": doc! { "$gte": thirty_days_ago_dt },
            }
        },
        doc! {
            "$project": doc! {
                "date": doc! {
                    "$dateToString": doc! {
                        "format": "%Y-%m-%d",
                        "date": "$timestamp"
                    }
                },
                "threat_type": doc! {
                    "$switch": doc! {
                        "branches": vec![
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"evil.*twin", "options": "i" } },
                                "then": "Evil Twin"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"rogue", "options": "i" } },
                                "then": "Rogue AP"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"open.*network|no.*encryption", "options": "i" } },
                                "then": "Suspicious Open Network"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"weak.*encryption|WEP|TKIP", "options": "i" } },
                                "then": "Weak Encryption"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"deauth", "options": "i" } },
                                "then": "Deauth Attack"
                            },
                            doc! {
                                "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"spoof|MAC.*spoof", "options": "i" } },
                                "then": "MAC Spoof Attempt"
                            },
                            doc! {
                                "case": doc! { "$eq": ["$action", "BLACKLIST_ADD"] },
                                "then": "Blacklisted Network"
                            },
                        ],
                        "default": doc! {
                            "$cond": doc! {
                                "if": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"Risk level:\s*[CH]", "options": "i" } },
                                "then": "High/Critical Risk",
                                "else": null
                            }
                        }
                    }
                }
            }
        },
        doc! {
            "$match": doc! {
                "threat_type": doc! { "$ne": null }
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "date": "$date",
                    "threat_type": "$threat_type"
                },
                "count": doc! { "$sum": 1 }
            }
        },
        doc! {
            "$project": doc! {
                "_id": 0,
                "date": "$_id.date",
                "threat_type": "$_id.threat_type",
                "count": 1
            }
        },
        doc! {
            "$sort": doc! { "date": 1, "threat_type": 1 }
        },
    ];

    let mut threat_type_timepoints = Vec::new();
    match logs_coll.aggregate(threat_type_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(date), Some(threat_type), Some(count)) = (
                    doc.get("date").and_then(|v| v.as_str()),
                    doc.get("threat_type").and_then(|v| v.as_str()),
                    doc.get("count").and_then(|v| v.as_i64()),
                ) {
                    threat_type_timepoints.push(ThreatTypeTimePoint {
                        date: date.to_string(),
                        threat_type: threat_type.to_string(),
                        count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating threat types over time: {}", e);
        }
    }

    let now = Utc::now();
    let date_filter_start = match date_filter {
        "day" => DateTime::from_millis(now.timestamp_millis() - (24 * 60 * 60 * 1000)),
        "week" => DateTime::from_millis(now.timestamp_millis() - (7 * 24 * 60 * 60 * 1000)),
        "month" => DateTime::from_millis(now.timestamp_millis() - (30 * 24 * 60 * 60 * 1000)),
        "year" => DateTime::from_millis(now.timestamp_millis() - (365 * 24 * 60 * 60 * 1000)),
        _ => DateTime::from_millis(0), // "all" - use epoch start
    };

    let mut base_filter = doc! {
        "user_id": &user.user_id
    };

    if date_filter != "all" {
        base_filter.insert("timestamp", doc! { "$gte": date_filter_start });
    }

    let rogue_aps = logs_coll
        .count_documents(doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"rogue", "$options": "i" }
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let evil_twins = logs_coll
        .count_documents(doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"evil.*twin", "$options": "i" }
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let suspicious_open = logs_coll
        .count_documents(doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "$or": [
                        { "details": doc! { "$regex": r"open.*network|no.*encryption", "$options": "i" } },
                        { "details": doc! { "$regex": r"Authentication:\s*Open", "$options": "i" } },
                        { "details": doc! { "$regex": r"Encryption:\s*None", "$options": "i" } },
                    ]
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let weak_encryption = logs_coll
        .count_documents(doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"weak.*encryption|WEP|TKIP", "$options": "i" }
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let deauth_attacks = logs_coll
        .count_documents(doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"deauth", "$options": "i" }
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let mac_spoof = logs_coll
        .count_documents(doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "details": doc! { "$regex": r"spoof|MAC.*spoof", "$options": "i" }
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let blacklisted_detected = logs_coll
        .count_documents(doc! {
            "$and": [
                base_filter.clone(),
                doc! {
                    "action": "BLACKLIST_ADD"
                }
            ]
        })
        .await
        .unwrap_or(0) as i64;

    let channel_1 = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "details": doc! { "$regex": r"channel.*1\b|Channel.*1\b", "$options": "i" }
        })
        .await
        .unwrap_or(0) as i64;

    let channel_6 = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "details": doc! { "$regex": r"channel.*6\b|Channel.*6\b", "$options": "i" }
        })
        .await
        .unwrap_or(0) as i64;

    let channel_11 = logs_coll
        .count_documents(doc! {
            "user_id": &user.user_id,
            "details": doc! { "$regex": r"channel.*11\b|Channel.*11\b", "$options": "i" }
        })
        .await
        .unwrap_or(0) as i64;

    let mut channels_5ghz = Vec::new();
    let common_5ghz = vec![36, 40, 44, 48, 149, 153, 157, 161, 165];
    for channel in common_5ghz {
        let count = logs_coll
            .count_documents(doc! {
                "user_id": &user.user_id,
                "details": doc! { "$regex": format!(r"channel.*{}\b|Channel.*{}\b", channel, channel), "$options": "i" }
            })
            .await
            .unwrap_or(0) as i64;
        if count > 0 {
            channels_5ghz.push(Channel5Ghz {
                channel,
                count,
            });
        }
    }

    let suspicious_networks_pipeline = vec![
        doc! {
            "$match": doc! {
                "user_id": &user.user_id,
                "$or": [
                    { "details": doc! { "$regex": r"Risk level:\s*(C|H|M)|\(Critical\)|\(High\)|\(Medium\)", "$options": "i" } },
                    { "action": "BLACKLIST_ADD" },
                    { "details": doc! { "$regex": r"evil.*twin|rogue|deauth|spoof|weak.*encryption|open.*network", "$options": "i" } },
                ],
                "network_ssid": doc! { "$exists": true, "$ne": "", "$ne": "-", "$ne": null },
                "network_bssid": doc! { "$exists": true, "$ne": "", "$ne": null },
            }
        },
        doc! {
            "$group": doc! {
                "_id": doc! {
                    "ssid": "$network_ssid",
                    "bssid": "$network_bssid"
                },
                "threat_count": doc! { "$sum": 1 },
                "risk_level": doc! {
                    "$max": doc! {
                        "$switch": doc! {
                            "branches": vec![
                                doc! {
                                    "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"Risk level:\s*C|\(Critical\)", "options": "i" } },
                                    "then": 4
                                },
                                doc! {
                                    "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"Risk level:\s*H|\(High\)", "options": "i" } },
                                    "then": 3
                                },
                                doc! {
                                    "case": doc! { "$regexMatch": doc! { "input": "$details", "regex": r"Risk level:\s*M|\(Medium\)", "options": "i" } },
                                    "then": 2
                                },
                            ],
                            "default": 1
                        }
                    }
                }
            }
        },
        doc! {
            "$project": doc! {
                "_id": 0,
                "ssid": "$_id.ssid",
                "bssid": "$_id.bssid",
                "threat_count": 1,
                "risk_level": doc! {
                    "$switch": doc! {
                        "branches": vec![
                            doc! { "case": doc! { "$eq": ["$risk_level", 4] }, "then": "C" },
                            doc! { "case": doc! { "$eq": ["$risk_level", 3] }, "then": "H" },
                            doc! { "case": doc! { "$eq": ["$risk_level", 2] }, "then": "M" },
                        ],
                        "default": "L"
                    }
                }
            }
        },
        doc! {
            "$sort": doc! { "threat_count": -1, "risk_level": -1 }
        },
        doc! {
            "$limit": 10
        },
    ];

    let mut top_suspicious = Vec::new();
    match logs_coll.aggregate(suspicious_networks_pipeline).await {
        Ok(mut cursor) => {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let (Some(ssid), Some(bssid), Some(threat_count), Some(risk_score)) = (
                    doc.get("ssid").and_then(|v| v.as_str()),
                    doc.get("bssid").and_then(|v| v.as_str()),
                    doc.get("threat_count").and_then(|v| v.as_i64()),
                    doc.get("risk_level").and_then(|v| v.as_str()),
                ) {
                    top_suspicious.push(TopSuspiciousNetwork {
                        ssid: ssid.to_string(),
                        bssid: bssid.to_string(),
                        risk_score: risk_score.to_string(),
                        threat_count,
                    });
                }
            }
        }
        Err(e) => {
            eprintln!("Error aggregating top suspicious networks: {}", e);
        }
    }

    // ========== BUILD RESPONSE ==========
    let analytics = AnalyticsResponse {
        security_metrics: SecurityMetrics {
            high_risk_connections: high_risk,
            medium_risk_connections: medium_risk,
            low_risk_connections: low_risk,
            failed_attempts,
            successful_connections,
            blacklisted_networks_detected,
        },
        connection_stats: ConnectionStats {
            total_connections,
            connection_success_rate,
            total_scan_attempts: total_scans,
            avg_connections_per_day,
        },
        blacklist_whitelist: BlacklistWhitelistStats {
            total_blacklisted,
            total_whitelisted,
            blacklist_additions,
            blacklist_removals,
            whitelist_additions,
            whitelist_removals,
            blacklist_additions_today,
            blacklist_removals_today,
            whitelist_additions_today,
            whitelist_removals_today,
            blacklist_additions_week,
            blacklist_removals_week,
            whitelist_additions_week,
            whitelist_removals_week,
            blacklist_additions_month,
            blacklist_removals_month,
            whitelist_additions_month,
            whitelist_removals_month,
        },
        user_activity: UserActivityStats {
            password_changes,
            username_changes,
            profile_updates,
            profile_save_attempts,
        },
        network_stats: NetworkStats {
            most_scanned_networks: most_scanned,
            networks_in_lists,
        },
        time_series: TimeSeriesData {
            daily_activity,
            hourly_activity,
        },
        threat_analytics: ThreatAnalytics {
            threats_over_time: ThreatsOverTime {
                daily: daily_threats,
                weekly: weekly_threats,
                monthly: monthly_threats,
                by_type: threat_type_timepoints,
            },
            threat_type_distribution: ThreatTypeDistribution {
                rogue_aps,
                evil_twins,
                suspicious_open_networks: suspicious_open,
                weak_encryption,
                deauth_attacks,
                mac_spoof_attempts: mac_spoof,
                blacklisted_networks_detected: blacklisted_detected,
            },
            channel_usage: ChannelUsage {
                channel_1,
                channel_6,
                channel_11,
                channels_5ghz,
            },
            top_suspicious_networks: top_suspicious,
        },
    };

    Json(analytics).into_response()
}
