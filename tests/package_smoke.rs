//! Public-API smoke tests retained in the crates.io source package.

use openbao::{
    Client, ExposeSecret, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion, RetryPolicy,
    SecretString, validate_endpoint_path, validate_mount_path,
};
use std::time::Duration;

#[test]
fn packaged_client_builds_with_an_exact_historical_profile() -> openbao::Result<()> {
    let target = OpenBaoVersion::new(2, 2, 0);
    let policy = OpenBaoCompatibilityPolicy::exact(target)?;
    let config = OpenBaoConfig::new("https://bao.example.com:8200")?
        .compatibility_policy(policy)
        .timeout(Duration::from_secs(10))?;
    let client = Client::from_config(config)?;

    assert_eq!(client.base_url().as_str(), "https://bao.example.com:8200/");
    assert_eq!(target.to_string(), "2.2.0");
    Ok(())
}

#[test]
fn packaged_path_validation_keeps_structured_segments() -> openbao::Result<()> {
    assert_eq!(validate_mount_path("team/secret")?, ["team", "secret"]);
    assert!(validate_endpoint_path("../secret").is_err());
    assert!(validate_endpoint_path("secret?version=1").is_err());
    Ok(())
}

#[test]
fn packaged_retry_policy_preserves_bounded_configuration() -> openbao::Result<()> {
    let policy =
        RetryPolicy::exponential(3, Duration::from_millis(25), Duration::from_millis(250))?
            .without_jitter();

    assert_eq!(policy.max_attempts(), 3);
    assert_eq!(policy.initial_delay(), Duration::from_millis(25));
    assert_eq!(policy.max_delay(), Duration::from_millis(250));
    assert_eq!(policy.jitter_percent(), 0);
    Ok(())
}

#[test]
fn packaged_secret_string_uses_sanitization_secrecy() -> serde_json::Result<()> {
    let secret: openbao::sanitization_secrecy::SecretString =
        serde_json::from_str("\"package-secret\"")?;

    assert_eq!(secret.expose_secret(), "package-secret");
    assert!(!format!("{secret:?}").contains("package-secret"));

    let reexported: SecretString = secret;
    assert_eq!(reexported.expose_secret(), "package-secret");

    let oversized = "x".repeat(openbao::sanitization::DEFAULT_SECRET_STRING_SERDE_MAX_LEN + 1);
    let oversized_json = serde_json::to_string(&oversized)?;
    assert!(serde_json::from_str::<SecretString>(&oversized_json).is_err());
    Ok(())
}
