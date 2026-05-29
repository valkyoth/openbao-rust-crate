//! KV v2 read example.

#![allow(clippy::print_stdout)]

use openbao::{Client, Result, SecretString};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct DatabaseCredentials {
    username: String,
    password: SecretString,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = std::env::var("BAO_TOKEN")
        .map(SecretString::from)
        .map_err(|error| {
            openbao::Error::InvalidHeader(format!(
                "BAO_TOKEN must be set for this example: {error}"
            ))
        })?;
    let client = Client::new("https://127.0.0.1:9940")?.try_with_token(token)?;
    let secret = client
        .kv2("secret")?
        .read::<DatabaseCredentials>("production/database")
        .await?;

    println!("username: {}", secret.data.username);
    let _password_is_not_logged = secret.data.password;
    Ok(())
}
