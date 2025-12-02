use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use crate::config::{Constants, EnvVars};

/// Send an email using SMTP
pub async fn send_email(to: &str, subject: &str, body: &str) {
    println!("Sending email from: {:?}", EnvVars::smtp_user());
    
    let smtp = SmtpTransport::starttls_relay(Constants::SMTP_SERVER)
        .unwrap()
        .credentials(Credentials::new(
            EnvVars::smtp_user(),
            EnvVars::smtp_pass(),
        ))
        .build();
    
    println!("SMTP_FROM: {:?}", &smtp);
    let from_addr = EnvVars::smtp_from();

    let email = Message::builder()
        .from(format!("{} <{}>", Constants::EMAIL_SENDER_NAME, from_addr).parse().unwrap())
        .to(Mailbox::new(None, to.parse().unwrap()))
        .subject(subject)
        .body(body.to_string())
        .unwrap();
    
    println!("Email: {:?}", email);
    let result = smtp.send(&email);
    
    match result {
        Ok(_) => println!("Email accepted by SMTP server"),
        Err(err) => eprintln!("Email send failed: {err:?}"),
    }
}

