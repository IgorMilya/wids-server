use bcrypt::{hash, verify, DEFAULT_COST};

/// Hash a password using bcrypt
pub fn hash_password(password: &str) -> Result<String, String> {
    hash(password, DEFAULT_COST)
        .map_err(|e| format!("Failed to hash password: {}", e))
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    verify(password, hash)
        .map_err(|e| format!("Failed to verify password: {}", e))
}

