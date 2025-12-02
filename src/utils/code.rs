use rand::Rng;

/// Generate a 6-digit verification code
pub fn generate_code() -> String {
    let mut rng = rand::rng();
    format!("{:06}", rng.random_range(0..1_000_000))
}

