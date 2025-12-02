use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::config::Constants;

static REGISTRATION_ATTEMPTS: Lazy<DashMap<String, Vec<SystemTime>>> = Lazy::new(DashMap::new);

/// Check if registration attempts exceed rate limit
pub fn check_registration_rate_limit(addr: &SocketAddr) -> Result<(), String> {
    let ip = addr.ip().to_string();
    let now = SystemTime::now();

    let mut entry = REGISTRATION_ATTEMPTS.entry(ip.clone()).or_default();
    entry.retain(|&t| now.duration_since(t).unwrap_or_default() < Constants::RATE_LIMIT_WINDOW);

    if entry.len() >= Constants::MAX_REGISTRATION_ATTEMPTS {
        return Err("Too many registration attempts. Try again later.".to_string());
    }

    entry.push(now);
    Ok(())
}

