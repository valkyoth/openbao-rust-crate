//! Public SDK acceptance against an isolated, real FreeRADIUS backend.

use crate::auth::radius::{RadiusConfig, RadiusUserRequest};
use crate::plugin::{ExternalPluginKind, ExternalPluginSelection};
use crate::{
    Client, Error, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion, SecretString,
};
use serde::Deserialize;
use std::io::Read;
use std::time::Duration;

const MOUNT: &str = "fixture-radius";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    address: String,
    version: String,
    ca_pem: String,
    token: SecretString,
    shared: SecretString,
    alice: SecretString,
    bob: SecretString,
    wrong: SecretString,
}

fn checked<T, E>(result: core::result::Result<T, E>) -> T {
    #[allow(clippy::panic)]
    result.unwrap_or_else(|_| panic!("RADIUS SDK fixture assertion failed"))
}

fn denied<T>(result: crate::Result<T>, expected: u16) {
    assert!(matches!(result, Err(Error::Api { status, .. }) if status.as_u16() == expected));
}

macro_rules! stage {
    ($name:literal) => {{
        #[allow(clippy::print_stdout)]
        {
            println!(concat!("radius-sdk-stage:", $name));
        }
    }};
}

#[tokio::test]
#[ignore = "requires signed external RADIUS plugin and isolated FreeRADIUS"]
async fn public_radius_tls() {
    stage!("profile");
    let fixture: Fixture = checked(serde_json::from_reader(std::io::stdin().lock().take(65536)));
    let version = match fixture.version.as_str() {
        "2.7.0" => OpenBaoVersion::new(2, 7, 0),
        "2.7.1" => OpenBaoVersion::new(2, 7, 1),
        "2.7.2" => OpenBaoVersion::new(2, 7, 2),
        _ => checked(Err::<OpenBaoVersion, _>(())),
    };
    let url = checked(reqwest::Url::parse(&fixture.address));
    assert!(
        url.scheme() == "https"
            && url.host_str() == Some("127.0.0.1")
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
    );
    let config = checked(OpenBaoConfig::new(&fixture.address));
    let config = checked(config.only_root_certificates(vec![checked(
        reqwest::Certificate::from_pem(fixture.ca_pem.as_bytes()),
    )]));
    let config = checked(config.timeout(Duration::from_secs(15)))
        .compatibility_policy(checked(OpenBaoCompatibilityPolicy::exact(version)));
    let kind = ExternalPluginKind::RadiusAuth;
    let config = checked(config.external_plugin(checked(ExternalPluginSelection::new(
        kind,
        version,
        MOUNT,
        kind.plugin_version(),
        kind.binary_sha256(),
    ))));
    let anonymous = checked(Client::from_config(config.clone()));
    let client = checked(checked(Client::from_config(config)).try_with_token(fixture.token));
    let report = checked(client.compatibility_report().await);
    assert!(
        report.detected_version() == Some(version) && report.profile_version() == Some(version)
    );
    let admin = checked(client.radius_admin_at(MOUNT));
    stage!("config");
    let mut config = RadiusConfig::new("127.0.0.1", fixture.shared.clone()).with_port(11812);
    config.token_policies = vec!["fixture-radius-base".into()];
    config.unregistered_user_policies = Some("fixture-radius-fallback".into());
    config.token_no_default_policy = Some(true);
    config.token_ttl = Some("5m".into());
    config.token_max_ttl = Some("10m".into());
    config.dial_timeout = Some(1);
    checked(admin.configure(&config).await);
    stage!("mappings");
    checked(
        admin
            .write_user("alice", &RadiusUserRequest::new("fixture-radius-mapped"))
            .await,
    );
    assert!(checked(admin.read_user("alice").await).policies == "fixture-radius-mapped");
    assert!(checked(admin.list_users().await).keys == ["alice"]);
    stage!("mapped-login");
    let (logged, metadata) = checked(
        checked(anonymous.radius_at(MOUNT))
            .login("alice", fixture.alice.clone())
            .await,
    );
    let mut policies = metadata.policies;
    policies.sort();
    assert!(policies == ["fixture-radius-base", "fixture-radius-mapped"]);
    assert!(metadata.metadata.get("username").map(String::as_str) == Some("alice"));
    stage!("fallback-login");
    let (_, metadata) = checked(
        checked(anonymous.radius_at(MOUNT))
            .login("bob", fixture.bob)
            .await,
    );
    let mut policies = metadata.policies;
    policies.sort();
    assert!(policies == ["fixture-radius-base", "fixture-radius-fallback"]);
    stage!("rejections");
    denied(
        checked(anonymous.radius_at(MOUNT))
            .login("alice", fixture.wrong.clone())
            .await,
        400,
    );
    denied(
        checked(anonymous.radius_at(MOUNT))
            .login("missing", fixture.wrong.clone())
            .await,
        400,
    );
    denied(
        checked(logged.radius_admin_at(MOUNT))
            .configure(&config)
            .await,
        403,
    );
    stage!("mapping-removal");
    checked(admin.delete_user("alice").await);
    denied(admin.read_user("alice").await, 404);
    let (_, metadata) = checked(
        checked(anonymous.radius_at(MOUNT))
            .login("alice", fixture.alice.clone())
            .await,
    );
    let mut policies = metadata.policies;
    policies.sort();
    assert!(policies == ["fixture-radius-base", "fixture-radius-fallback"]);
    stage!("shared-secret-rejection");
    config.secret = fixture.wrong;
    checked(admin.configure(&config).await);
    denied(
        checked(anonymous.radius_at(MOUNT))
            .login("alice", fixture.alice.clone())
            .await,
        400,
    );
    config.secret = fixture.shared;
    checked(admin.configure(&config).await);
    let (_, metadata) = checked(
        checked(anonymous.radius_at(MOUNT))
            .login("alice", fixture.alice)
            .await,
    );
    let mut policies = metadata.policies;
    policies.sort();
    assert!(policies == ["fixture-radius-base", "fixture-radius-fallback"]);
    stage!("complete");
}
