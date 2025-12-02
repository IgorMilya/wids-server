use axum::{
    http::StatusCode,
    response::Response,
};
use once_cell::sync::Lazy;
use reqwest::Client as ReqwestClient;
use serde::Deserialize;

use crate::config::{Constants, EnvVars};

static HTTP_CLIENT: Lazy<ReqwestClient> = Lazy::new(|| ReqwestClient::new());

#[derive(Debug, Deserialize)]
struct RecaptchaResponse {
    success: bool,
    #[allow(dead_code)]
    challenge_ts: Option<String>,
    #[allow(dead_code)]
    hostname: Option<String>,
    #[allow(dead_code)]
    score: Option<f32>,
    #[allow(dead_code)]
    action: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "error-codes")]
    error_codes: Option<Vec<String>>,
}

/// Verify reCAPTCHA token
pub async fn ensure_recaptcha(token: &str) -> Result<(), Response> {
    let secret = EnvVars::recaptcha_secret().map_err(|_| {
        crate::utils::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Captcha not configured",
        )
    })?;

    let resp = HTTP_CLIENT
        .post(Constants::RECAPTCHA_VERIFY_URL)
        .form(&[("secret", secret), ("response", token.to_string())])
        .send()
        .await
        .map_err(|err| {
            eprintln!("Recaptcha request failed: {err:?}");
            crate::utils::error_response(
                StatusCode::BAD_GATEWAY,
                "Captcha verification failed",
            )
        })?;

    let body: RecaptchaResponse = resp.json().await.map_err(|err| {
        eprintln!("Recaptcha parse failed: {err:?}");
        crate::utils::error_response(
            StatusCode::BAD_GATEWAY,
            "Captcha verification failed",
        )
    })?;

    if !body.success {
        return Err(crate::utils::error_response(
            StatusCode::BAD_REQUEST,
            "Captcha verification failed",
        ));
    }

    Ok(())
}

