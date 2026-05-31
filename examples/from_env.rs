//! Environment-based authenticated client example.

use openbao::{Client, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::from_env_with_token()?;
    let health = client.sys().health().await?;
    let _sealed = health.sealed;
    Ok(())
}
