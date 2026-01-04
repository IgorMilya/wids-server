mod config;
mod db;
mod handlers;
mod middleware;
mod structure;
mod utils;

use axum::{routing::{delete, get, post}, Router};
use dotenvy::dotenv;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use handlers::{
    analytics, auth, blacklist, logs, profile, whitelist,
};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let cors = CorsLayer::very_permissive();
    
    let app = Router::new()
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/refresh", post(auth::refresh_token_handler))
        .route("/auth/logout", post(auth::logout_handler))
        .route("/auth/register", post(auth::register_handler))
        .route("/auth/verify", post(auth::verify_email_handler))
        .route(
            "/auth/resend-verification",
            post(auth::resend_verification_handler),
        )
        .route("/auth/reset/request", post(auth::reset_password_request_handler))
        .route("/auth/reset/confirm", post(auth::reset_password_confirm_handler))
        
        .route("/blacklist", get(blacklist::get_blacklist).post(blacklist::add_to_blacklist))
        .route("/blacklist/{id}", delete(blacklist::delete_from_blacklist))
        
        .route("/whitelist", get(whitelist::get_whitelist).post(whitelist::add_to_whitelist))
        .route("/whitelist/{id}", delete(whitelist::delete_from_whitelist))
        
        .route("/logs", get(logs::get_logs).post(logs::add_log))
        .route("/logs/export", get(logs::export_logs))
        
        .route("/profile", get(profile::get_user_profile).post(profile::update_user_profile))
        .route("/profile/username", post(profile::change_username_handler))
        .route("/profile/password", post(profile::change_password_handler))
        
        .route("/analytics", get(analytics::get_analytics))
        .layer(cors);
    
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid number");
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Listening on http://{}", addr);
    
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
