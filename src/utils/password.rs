use bcrypt::{hash, verify, DEFAULT_COST};

pub fn hash_password(password: &str) -> Result<String, String> {
    hash(password, DEFAULT_COST)
        .map_err(|e| format!("Failed to hash password: {}", e))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    verify(password, hash)
        .map_err(|e| format!("Failed to verify password: {}", e))
}

