use mongodb::{Client, Database};

use crate::config::{Constants, EnvVars};

pub mod operations;
pub mod refresh_tokens;

pub async fn get_database() -> mongodb::error::Result<Database> {
    let db_url = EnvVars::mongo_db_url();
    let client = Client::with_uri_str(db_url)
        .await
        .expect("Failed to connect to MongoDB");
    let db = client.database(Constants::DB_NAME);
    Ok(db)
}

pub fn get_collection<T: Send + Sync>(db: &Database, name: &str) -> mongodb::Collection<T> {
    db.collection(name)
}

