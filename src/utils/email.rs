use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use tokio::time::{timeout, Duration};

use crate::config::{Constants, EnvVars};

/// Send an email using SMTP
/// Returns Ok(()) on success, Err(String) on failure
pub async fn send_email(to: &str, subject: &str, body: &str) -> Result<(), String> {
    // Log email attempt with environment check
    let smtp_user = EnvVars::smtp_user();
    let smtp_pass = EnvVars::smtp_pass();
    let smtp_from = EnvVars::smtp_from();
    
    eprintln!("[EMAIL] Attempting to send email to: {}", to);
    eprintln!("[EMAIL] SMTP_USER: {}", smtp_user);
    eprintln!("[EMAIL] SMTP_FROM: {}", smtp_from);
    eprintln!("[EMAIL] SMTP_PASS length: {} chars", smtp_pass.len());
    eprintln!("[EMAIL] SMTP_SERVER: {}", Constants::SMTP_SERVER);
    
    // Clone values for the blocking task
    let smtp_user_clone = smtp_user.clone();
    let smtp_pass_clone = smtp_pass.clone();
    let smtp_from_clone = smtp_from.clone();
    let to_clone = to.to_string();
    let subject_clone = subject.to_string();
    let body_clone = body.to_string();
    
    // Run blocking SMTP operation in a separate thread pool with timeout
    let send_result = timeout(
        Duration::from_secs(30), // 30 second timeout
        tokio::task::spawn_blocking(move || {
            eprintln!("[EMAIL] Building SMTP transport...");
            
            // Build email message inside the blocking task
            let from_mailbox = format!("{} <{}>", Constants::EMAIL_SENDER_NAME, smtp_from_clone)
                .parse()
                .map_err(|e| {
                    let error_msg = format!("Failed to parse FROM address: {:?}", e);
                    eprintln!("[EMAIL ERROR] {}", error_msg);
                    error_msg
                })?;
            
            let to_mailbox = to_clone.parse().map_err(|e| {
                let error_msg = format!("Failed to parse TO address: {:?}", e);
                eprintln!("[EMAIL ERROR] {}", error_msg);
                error_msg
            })?;

            let email = Message::builder()
                .from(from_mailbox)
                .to(Mailbox::new(None, to_mailbox))
                .subject(subject_clone)
                .body(body_clone)
                .map_err(|e| {
                    let error_msg = format!("Failed to build email message: {:?}", e);
                    eprintln!("[EMAIL ERROR] {}", error_msg);
                    error_msg
                })?;
            
            // Build SMTP transport with proper error handling
            let smtp = match SmtpTransport::starttls_relay(Constants::SMTP_SERVER) {
                Ok(builder) => builder
                    .credentials(Credentials::new(
                        smtp_user_clone,
                        smtp_pass_clone,
                    ))
                    .build(),
                Err(e) => {
                    let error_msg = format!("Failed to create SMTP relay: {:?}", e);
                    eprintln!("[EMAIL ERROR] {}", error_msg);
                    return Err(error_msg);
                }
            };
            
            eprintln!("[EMAIL] Attempting to connect to SMTP server...");
            
            // Send email (this is blocking)
            match smtp.send(&email) {
                Ok(_) => {
                    eprintln!("[EMAIL SUCCESS] Email accepted by SMTP server");
                    Ok(())
                }
                Err(err) => {
                    let error_msg = format!("Email send failed: {:?}", err);
                    eprintln!("[EMAIL ERROR] {}", error_msg);
                    
                    // Provide more helpful error messages
                    let detailed_error = if error_msg.contains("Network is unreachable") {
                        format!("{} - This usually means the hosting provider is blocking outbound SMTP connections.", error_msg)
                    } else if error_msg.contains("Connection refused") {
                        format!("{} - SMTP server refused connection. Check firewall settings and SMTP server address.", error_msg)
                    } else if error_msg.contains("timeout") {
                        format!("{} - Connection timed out. SMTP server may be unreachable.", error_msg)
                    } else {
                        error_msg
                    };
                    
                    Err(detailed_error)
                }
            }
        })
    ).await;
    
    match send_result {
        Ok(Ok(Ok(()))) => {
            eprintln!("[EMAIL SUCCESS] Email sent successfully to: {}", to);
            Ok(())
        }
        Ok(Ok(Err(e))) => {
            eprintln!("[EMAIL ERROR] Failed to send email: {}", e);
            Err(e)
        }
        Ok(Err(join_err)) => {
            let error_msg = if join_err.is_panic() {
                "Email send task panicked. This may indicate a critical error.".to_string()
            } else {
                format!("Email send task failed: {:?}", join_err)
            };
            eprintln!("[EMAIL ERROR] {}", error_msg);
            Err(error_msg)
        }
        Err(_elapsed) => {
            // Timeout occurred
            let error_msg = "Email send timed out after 30 seconds. This may indicate network connectivity issues or that the hosting provider is blocking SMTP connections.".to_string();
            eprintln!("[EMAIL ERROR] {}", error_msg);
            Err(error_msg)
        }
    }
}

