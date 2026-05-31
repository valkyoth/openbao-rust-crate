//! AppRole login example.

use openbao::{Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let role_id = SecretString::from(std::env::var("BAO_ROLE_ID").unwrap_or_default());
    let secret_id = SecretString::from(std::env::var("BAO_SECRET_ID").unwrap_or_default());

    let unauthenticated = Client::new("https://bao.example.com:8200")?;
    let (client, metadata) = unauthenticated.login_approle(role_id, secret_id).await?;
    let _renewable = metadata.renewable;
    let _health = client.sys().health().await?;
    Ok(())
}
