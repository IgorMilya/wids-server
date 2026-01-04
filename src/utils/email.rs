use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::Resend;
use crate::config::{Constants, EnvVars};

pub async fn send_email(to: &str, subject: &str, body: &str) -> Result<(), String> {
    let from_email = EnvVars::resend_from_email();
    
    eprintln!("[EMAIL] Attempting to send email to: {}", to);
    eprintln!("[EMAIL] From: {}", from_email);
    eprintln!("[EMAIL] Subject: {}", subject);
    
    let client = Resend::default();
    
    let from = format!("{} <{}>", Constants::EMAIL_SENDER_NAME, from_email);
    let to_array = [to]; 
    
    let html_body = if body.contains("<html") || body.contains("<div") || body.contains("<p>") {
        body.to_string()
    } else {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .code {{ font-size: 24px; font-weight: bold; color: #007bff; padding: 10px; background: #f0f0f0; border-radius: 5px; text-align: center; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>{}</h2>
        <div class="code">{}</div>
        <p>This code will expire after verification.</p>
    </div>
</body>
</html>"#,
            subject, body
        )
    };
    
    let email = CreateEmailBaseOptions::new(&from, to_array, subject)
        .with_html(&html_body);
    
    eprintln!("[EMAIL] Sending email via Resend API...");
    
    match client.emails.send(email).await {
        Ok(response) => {
            eprintln!("[EMAIL SUCCESS] Email sent successfully to: {} (ID: {:?})", to, response.id);
            Ok(())
        }
        Err(err) => {
            let error_msg = format!("Email send failed: {:?}", err);
            eprintln!("[EMAIL ERROR] {}", error_msg);
            eprintln!("[EMAIL ERROR] Full error details: {:#?}", err);
            Err(error_msg)
        }
    }
}
