//! External Kerberos acceptance with real MIT tickets and verified LDAPS.

use crate::auth::kerberos::{KerberosConfig, KerberosGroupRequest, KerberosLdapConfig};
use crate::plugin::{ExternalPluginKind, ExternalPluginSelection};
use crate::{
    Client, Error, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion, SecretString,
};
use serde::Deserialize;
use std::io::Read;
use std::time::Duration;

const MOUNT: &str = "fixture-kerberos";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    address: String,
    version: String,
    ca_pem: String,
    token: SecretString,
    manager: SecretString,
    keytab: SecretString,
    mapped_ticket: SecretString,
    unmapped_ticket: SecretString,
    wrong_service_ticket: SecretString,
    realm_ticket: SecretString,
    removed_ticket: SecretString,
}

fn checked<T, E>(result: core::result::Result<T, E>) -> T {
    #[allow(clippy::panic)]
    result.unwrap_or_else(|_| panic!("Kerberos SDK fixture assertion failed"))
}

fn denied<T>(result: crate::Result<T>, expected: u16) {
    assert!(matches!(result, Err(Error::Api { status, .. }) if status.as_u16() == expected));
}

macro_rules! stage {
    ($name:literal) => {{
        #[allow(clippy::print_stdout)]
        {
            println!(concat!("kerberos-sdk-stage:", $name));
        }
    }};
}

#[tokio::test]
#[ignore = "requires signed Kerberos plugin, real isolated MIT KDC and LDAPS"]
async fn public_kerberos_tls() {
    stage!("profile");
    let fixture: Fixture = checked(serde_json::from_reader(
        std::io::stdin().lock().take(131072),
    ));
    let version = match fixture.version.as_str() {
        "2.7.0" => OpenBaoVersion::new(2, 7, 0),
        "2.7.1" => OpenBaoVersion::new(2, 7, 1),
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
    let config = checked(config.timeout(Duration::from_secs(5)))
        .compatibility_policy(checked(OpenBaoCompatibilityPolicy::exact(version)));
    let kind = ExternalPluginKind::KerberosAuth;
    let config = checked(config.external_plugin(checked(ExternalPluginSelection::new(
        kind,
        version,
        MOUNT,
        "v0.1.0",
        kind.binary_sha256(),
    ))));
    let anonymous = checked(Client::from_config(config.clone()));
    let client = checked(checked(Client::from_config(config)).try_with_token(fixture.token));
    let report = checked(client.compatibility_report().await);
    assert!(
        report.detected_version() == Some(version) && report.profile_version() == Some(version)
    );
    let admin = checked(client.kerberos_auth_admin_at(MOUNT));

    stage!("config");
    let config = KerberosConfig::new("HTTP/localhost", fixture.keytab)
        .remove_instance_name(false)
        .add_group_aliases(true);
    checked(admin.configure(&config).await);
    let read = checked(admin.read_config().await);
    assert!(read.keytab.is_none() && read.service_account == "HTTP/localhost");
    assert!(checked(admin.read_config_details().await).decode_pac == Some(true));
    checked(admin.configure_with_decode_pac(&config, false).await);
    assert!(checked(admin.read_config_details().await).decode_pac == Some(false));

    stage!("ldap-config");
    let mut ldap = KerberosLdapConfig::new()
        .with_url("ldaps://127.0.0.1:1636")
        .with_bind(
            "cn=manager,ou=people,dc=fixture,dc=invalid",
            fixture.manager,
        )
        .with_token_policy("fixture-kerberos-base");
    ldap.certificate = Some(fixture.ca_pem);
    ldap.userdn = Some("ou=people,dc=fixture,dc=invalid".into());
    ldap.userattr = Some("cn".into());
    ldap.groupdn = Some("ou=groups,dc=fixture,dc=invalid".into());
    ldap.groupattr = Some("cn".into());
    ldap.groupfilter = Some("(&(objectClass=groupOfNames)(member={{.UserDN}}))".into());
    ldap.tls_min_version = Some("tls13".into());
    ldap.tls_max_version = Some("tls13".into());
    ldap.token_no_default_policy = Some(true);
    ldap.token_ttl = Some("5m".into());
    checked(admin.configure_ldap(&ldap).await);
    let read = checked(admin.read_ldap_config().await);
    assert!(read.bindpass.is_none() && read.url.as_deref() == Some("ldaps://127.0.0.1:1636"));

    stage!("mappings");
    checked(
        admin
            .write_group(
                "engineers",
                &KerberosGroupRequest::new("fixture-kerberos-group"),
            )
            .await,
    );
    assert!(checked(admin.read_group("engineers").await).policies == ["fixture-kerberos-group"]);
    assert!(checked(admin.list_groups().await).keys == ["engineers"]);

    stage!("mapped-login");
    let (logged, metadata) = checked(
        checked(anonymous.kerberos_auth_at(MOUNT))
            .login(fixture.mapped_ticket)
            .await,
    );
    let mut policies = metadata.policies;
    policies.sort();
    assert!(policies == ["fixture-kerberos-base", "fixture-kerberos-group"]);
    assert!(metadata.metadata.get("user").map(String::as_str) == Some("alice"));
    assert!(metadata.metadata.get("domain").map(String::as_str) == Some("FIXTURE.INVALID"));
    stage!("unmapped-login");
    let (_, metadata) = checked(
        checked(anonymous.kerberos_auth_at(MOUNT))
            .login(fixture.unmapped_ticket)
            .await,
    );
    assert!(metadata.policies == ["fixture-kerberos-base"]);
    assert!(metadata.metadata.get("user").map(String::as_str) == Some("static"));

    stage!("rejections");
    denied(
        checked(logged.kerberos_auth_admin_at(MOUNT))
            .read_config()
            .await,
        403,
    );
    denied(
        checked(anonymous.kerberos_auth_at(MOUNT))
            .login(SecretString::from("ZmFrZQ=="))
            .await,
        401,
    );
    denied(
        checked(anonymous.kerberos_auth_at(MOUNT))
            .login(fixture.wrong_service_ticket)
            .await,
        401,
    );
    ldap.upndomain = Some("OTHER.INVALID".into());
    checked(admin.configure_ldap(&ldap).await);
    denied(
        checked(anonymous.kerberos_auth_at(MOUNT))
            .login(fixture.realm_ticket)
            .await,
        400,
    );
    ldap.upndomain = Some(String::new());
    checked(admin.configure_ldap(&ldap).await);

    stage!("mapping-removal");
    checked(admin.delete_group("engineers").await);
    denied(admin.read_group("engineers").await, 404);
    let (_, metadata) = checked(
        checked(anonymous.kerberos_auth_at(MOUNT))
            .login(fixture.removed_ticket)
            .await,
    );
    assert!(metadata.policies == ["fixture-kerberos-base"]);
    stage!("complete");
}
