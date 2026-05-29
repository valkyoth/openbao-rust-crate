//! System policy and capability example.

use openbao::{Client, Result, SecretString, sys::PolicyWriteRequest};

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

    client
        .sys()
        .enable_kv2("example-secret", Some("example KV v2 mount"))
        .await?;

    client
        .sys()
        .write_policy(
            "example-app-read",
            &PolicyWriteRequest::new(
                r#"path "example-secret/data/app" { capabilities = ["read"] }"#,
            )
            .with_ttl("1h"),
        )
        .await?;

    let capabilities = client
        .sys()
        .capabilities_self(["example-secret/data/app"])
        .await?;
    let _path_capabilities = capabilities.by_path.get("example-secret/data/app");

    Ok(())
}
