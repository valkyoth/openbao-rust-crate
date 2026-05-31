//! Idempotent admin bootstrap example.

use std::collections::BTreeMap;

use openbao::auth::token::TokenCreateRequest;
use openbao::bootstrap::AdminBootstrap;
use openbao::{AclCapability, AclPolicyBuilder, Client, Result, SecretString};

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.try_with_token(token)?;

    let mut policy = AclPolicyBuilder::new();
    policy.allow_path("secret/data/app/*", [AclCapability::Read])?;

    let mut values = BTreeMap::new();
    values.insert(
        "DATABASE_URL".to_owned(),
        SecretString::from("postgres://example"),
    );

    let token_request = TokenCreateRequest::default()
        .with_policies(["app-read"])
        .without_default_policy()
        .with_ttl("1h")?;

    let mut bootstrap = AdminBootstrap::new();
    bootstrap
        .ensure_kv2_mount("secret", Some("application secrets"))?
        .ensure_policy("app-read", &policy)?
        .ensure_kv2_secret_values("secret", "app/config", values)?
        .issue_service_token("app", token_request)?;

    let report = bootstrap.run(&client).await?;
    let _step_count = report.steps.len();
    Ok(())
}
