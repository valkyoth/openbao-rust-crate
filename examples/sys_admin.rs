//! System policy and capability example.

use openbao::{
    Client, Result,
    sys::{MountEnableRequest, PolicyWriteRequest},
};
use secrecy::SecretString;
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<()> {
    let token = std::env::var("BAO_TOKEN")
        .map(SecretString::from)
        .map_err(|error| {
            openbao::Error::InvalidHeader(format!(
                "BAO_TOKEN must be set for this example: {error}"
            ))
        })?;
    let client = Client::new("https://127.0.0.1:9940")?.with_token(token);

    let mut kv2_options = BTreeMap::new();
    kv2_options.insert("version".to_owned(), "2".to_owned());
    client
        .sys()
        .enable_mount(
            "example-secret",
            &MountEnableRequest {
                backend_type: "kv".to_owned(),
                description: Some("example KV v2 mount".to_owned()),
                config: None,
                options: kv2_options,
                local: Some(true),
                seal_wrap: None,
                external_entropy_access: None,
            },
        )
        .await?;

    client
        .sys()
        .write_policy(
            "example-app-read",
            &PolicyWriteRequest {
                policy: r#"path "example-secret/data/app" { capabilities = ["read"] }"#.to_owned(),
                expiration: None,
                ttl: Some("1h".to_owned()),
                cas: None,
                cas_required: None,
            },
        )
        .await?;

    let capabilities = client
        .sys()
        .capabilities_self(["example-secret/data/app"])
        .await?;
    let _path_capabilities = capabilities.by_path.get("example-secret/data/app");

    Ok(())
}
