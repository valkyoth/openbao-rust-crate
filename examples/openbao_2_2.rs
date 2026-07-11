//! Exact OpenBao 2.2.0 verified-client example.

use openbao::{
    Client, Error, OpenBaoCompatibilityPolicy, OpenBaoCompatibilityStatus, OpenBaoConfig,
    OpenBaoVersion, Result, SecretString,
};

#[tokio::main]
async fn main() -> Result<()> {
    let token = std::env::var("BAO_TOKEN")
        .map(SecretString::from)
        .map_err(|_| Error::InvalidHeader("BAO_TOKEN must be set".into()))?;
    let target = OpenBaoVersion::new(2, 2, 0);
    let policy = OpenBaoCompatibilityPolicy::exact(target)?;
    let config = OpenBaoConfig::new("https://bao.example.com:8200")?.compatibility_policy(policy);
    let client = Client::from_config(config)?.try_with_token(token)?;

    let report = client.compatibility_report().await?;
    if report.status() != OpenBaoCompatibilityStatus::Verified
        || report.detected_version() != Some(target)
        || report.profile_version() != Some(target)
    {
        return Err(Error::Internal("OpenBao 2.2.0 profile was not verified"));
    }

    let _health = client.sys().health().await?;
    Ok(())
}
