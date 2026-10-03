//! Candidate-only external LDAP acceptance against a real, verified directory.

use crate::auth::ldap::{LdapAuthConfig, LdapAuthMappingRequest};
use crate::plugin::{ExternalPluginKind, ExternalPluginSelection};
use crate::secrets::ldap::{
    LdapCheckInRequest, LdapCheckOutRequest, LdapConfig, LdapDynamicRole, LdapLibrarySet,
    LdapStaticRole,
};
use crate::{
    Client, ExposeSecret, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion, SecretString,
};
use serde::Deserialize;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

const PEOPLE: &str = "ou=people,dc=fixture,dc=invalid";
const MANAGER: &str = "cn=manager,ou=people,dc=fixture,dc=invalid";
const AUTH: &str = "fixture-ldap-auth";
const SECRETS: &str = "fixture-ldap-secrets";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    address: String,
    version: String,
    ca_pem: String,
    ca_path: String,
    ldap_tool: String,
    ldap_port: u16,
    token: SecretString,
    manager: SecretString,
    alice: SecretString,
    static_password: SecretString,
}

fn checked<T, E>(result: core::result::Result<T, E>) -> T {
    #[allow(clippy::panic)]
    result.unwrap_or_else(|_| panic!("LDAP SDK fixture assertion failed"))
}

macro_rules! stage {
    ($name:literal) => {{
        #[allow(clippy::print_stdout)]
        {
            println!(concat!("ldap-sdk-stage:", $name));
        }
    }};
}

fn bind(fixture: &Fixture, dn: &str, password: &SecretString, expected: i32) {
    // The protected tool and public CA pathname come from the privileged runner.
    // Passwords are piped to a descriptor, never placed in argv or environment.
    let mut command = Command::new(&fixture.ldap_tool);
    command
        .args([
            "-x",
            "-o",
            "nettimeout=3",
            "-H",
            &format!("ldaps://127.0.0.1:{}", fixture.ldap_port),
            "-D",
            dn,
            "-y",
            "/dev/stdin",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("LDAPCONF", "/dev/null")
        .env("LDAPRC", "/dev/null")
        .env("LDAPTLS_CACERT", &fixture.ca_path)
        .env("LDAPTLS_REQCERT", "demand")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = checked(command.spawn());
    let mut input = checked(child.stdin.take().ok_or(()));
    checked(input.write_all(password.expose_secret().as_bytes()));
    drop(input);
    assert!(checked(child.wait()).code() == Some(expected));
}

#[tokio::test]
#[ignore = "requires signed external LDAP plugins, isolated LDAPS and candidate-only contracts"]
async fn public_ldap_tls() {
    stage!("profile");
    let fixture: Fixture = checked(serde_json::from_reader(std::io::stdin().lock().take(65536)));
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
    let mut config = checked(config.timeout(Duration::from_secs(5)))
        .compatibility_policy(checked(OpenBaoCompatibilityPolicy::exact(version)));
    for (kind, mount) in [
        (ExternalPluginKind::LdapAuth, AUTH),
        (ExternalPluginKind::LdapSecrets, SECRETS),
    ] {
        config = checked(config.external_plugin(checked(ExternalPluginSelection::new(
            kind,
            version,
            mount,
            "v0.1.0",
            kind.binary_sha256(),
        ))));
    }
    let anonymous = checked(Client::from_config(config.clone()));
    let client =
        checked(checked(Client::from_config(config)).try_with_token(fixture.token.clone()));
    let report = checked(client.compatibility_report().await);
    assert!(
        report.detected_version() == Some(version) && report.profile_version() == Some(version)
    );

    stage!("auth-config");
    let admin = checked(client.ldap_auth_admin_at(AUTH));
    let mut auth_config = LdapAuthConfig::new()
        .with_url("ldaps://127.0.0.1:1636")
        .with_bind(MANAGER, fixture.manager.clone());
    auth_config.certificate = Some(fixture.ca_pem.clone());
    auth_config.userdn = Some(PEOPLE.into());
    auth_config.userattr = Some("cn".into());
    auth_config.groupdn = Some("ou=groups,dc=fixture,dc=invalid".into());
    auth_config.groupattr = Some("cn".into());
    auth_config.groupfilter = Some("(&(objectClass=groupOfNames)(member={{.UserDN}}))".into());
    auth_config.deny_null_bind = Some(true);
    auth_config.tls_min_version = Some("tls13".into());
    auth_config.tls_max_version = Some("tls13".into());
    auth_config.token_no_default_policy = Some(true);
    checked(admin.configure(&auth_config).await);
    assert!(checked(admin.read_config().await).userdn.as_deref() == Some(PEOPLE));
    stage!("mappings");
    checked(
        admin
            .write_group("engineers", &LdapAuthMappingRequest::new("fixture-group"))
            .await,
    );
    checked(
        admin
            .write_user("alice", &LdapAuthMappingRequest::new("fixture-user"))
            .await,
    );
    assert!(checked(admin.read_group("engineers").await).policies == ["fixture-group"]);
    assert!(checked(admin.read_user("alice").await).policies == ["fixture-user"]);
    assert!(checked(admin.list_groups().await).keys == ["engineers"]);
    assert!(checked(admin.list_users().await).keys == ["alice"]);
    stage!("login");
    let (logged, metadata) = checked(
        checked(anonymous.ldap_auth_at(AUTH))
            .login("alice", fixture.alice.clone())
            .await,
    );
    let mut policies = metadata.policies.clone();
    policies.sort();
    assert!(policies == ["fixture-group", "fixture-user"]);
    for (user, password) in [
        ("alice", "wrong-password"),
        ("alice", ""),
        ("*)(cn=*)", fixture.alice.expose_secret()),
    ] {
        assert!(
            checked(anonymous.ldap_auth_at(AUTH))
                .login(user, SecretString::from(password))
                .await
                .is_err()
        );
    }
    assert!(
        checked(logged.ldap_auth_admin_at(AUTH))
            .read_config()
            .await
            .is_err()
    );
    assert!(
        checked(logged.ldap_at(SECRETS))
            .read_config()
            .await
            .is_err()
    );

    stage!("secret-config");
    let ldap = checked(client.ldap_at(SECRETS));
    let mut config = LdapConfig::new(MANAGER, fixture.manager.clone())
        .with_url("ldaps://127.0.0.1:1636")
        .with_schema("openldap");
    config.certificate = Some(fixture.ca_pem.clone());
    config.userdn = Some(PEOPLE.into());
    config.userattr = Some("cn".into());
    checked(ldap.write_config(&config).await);
    assert!(checked(ldap.read_config().await).schema.as_deref() == Some("openldap"));
    stage!("static-create");
    let mut role = checked(LdapStaticRole::new("static").with_rotation_period("1h"));
    role.dn = Some(format!("cn=static,{PEOPLE}"));
    checked(ldap.write_static_role("service", &role).await);
    stage!("static-read");
    assert!(checked(ldap.read_static_role("service").await).username == "static");
    stage!("static-list");
    assert!(checked(ldap.list_static_roles().await).keys == ["service"]);
    stage!("static-credentials");
    let first = checked(ldap.static_credentials("service").await);
    stage!("static-bind");
    bind(
        &fixture,
        checked(role.dn.as_deref().ok_or(())),
        &first.password,
        0,
    );
    bind(
        &fixture,
        checked(role.dn.as_deref().ok_or(())),
        &fixture.static_password,
        49,
    );
    stage!("static-rotate");
    checked(ldap.rotate_static_role("service").await);
    let second = checked(ldap.static_credentials("service").await);
    assert!(first.password.expose_secret() != second.password.expose_secret());
    stage!("static-rotated-bind");
    bind(
        &fixture,
        checked(role.dn.as_deref().ok_or(())),
        &second.password,
        0,
    );
    bind(
        &fixture,
        checked(role.dn.as_deref().ok_or(())),
        &first.password,
        49,
    );

    stage!("dynamic-revocation");
    let creation = format!(
        "dn: cn={{{{.Username}}}},{PEOPLE}\nobjectClass: inetOrgPerson\ncn: {{{{.Username}}}}\nsn: fixture\nuserPassword: {{{{.Password}}}}\n"
    );
    let deletion = format!("dn: cn={{{{.Username}}}},{PEOPLE}\nchangetype: delete\n");
    let mut role = checked(LdapDynamicRole::new(creation, deletion.clone()).with_default_ttl("5m"));
    role.rollback_ldif = Some(deletion);
    role.max_ttl = Some("10m".into());
    checked(ldap.write_dynamic_role("dynamic", &role).await);
    assert!(checked(ldap.read_dynamic_role("dynamic").await).creation_ldif == role.creation_ldif);
    let generated = checked(ldap.dynamic_credentials("dynamic").await);
    assert!(generated.distinguished_names.len() == 1 && generated.lease_duration > 0);
    bind(
        &fixture,
        &generated.distinguished_names[0],
        &generated.password,
        0,
    );
    checked(client.sys().revoke_lease(&generated.lease_id).await);
    bind(
        &fixture,
        &generated.distinguished_names[0],
        &generated.password,
        49,
    );
    stage!("root-rotation");
    checked(ldap.rotate_root().await);
    bind(&fixture, MANAGER, &fixture.manager, 49);
    let generated = checked(ldap.dynamic_credentials("dynamic").await);
    assert!(generated.distinguished_names.len() == 1);
    bind(
        &fixture,
        &generated.distinguished_names[0],
        &generated.password,
        0,
    );
    checked(client.sys().revoke_lease(&generated.lease_id).await);
    bind(
        &fixture,
        &generated.distinguished_names[0],
        &generated.password,
        49,
    );
    stage!("cleanup");
    checked(ldap.delete_dynamic_role("dynamic").await);
    checked(ldap.delete_static_role("service").await);
    stage!("library-create");
    let mut library = checked(LdapLibrarySet::new(["static"]).with_ttl("5m"));
    library.max_ttl = Some("10m".into());
    library.disable_check_in_enforcement = Some(false);
    checked(ldap.write_library_set("pool", &library).await);
    let read = checked(ldap.read_library_set("pool").await);
    assert!(
        read.service_account_names == ["static"]
            && read.disable_check_in_enforcement == Some(false)
    );
    assert!(checked(ldap.list_library_sets().await).keys == ["pool"]);
    stage!("library-status");
    let status = checked(ldap.library_status("pool").await);
    assert!(
        status.service_account_names.len() == 1
            && !status.service_account_names["static"].checked_out
    );
    stage!("library-checkout");
    let request = checked(LdapCheckOutRequest::new().with_ttl("5m"));
    let first = checked(ldap.check_out("pool", &request).await);
    assert!(first.service_account_name == "static" && first.lease_duration > 0);
    let dn = format!("cn=static,{PEOPLE}");
    bind(&fixture, &dn, &first.password, 0);
    assert!(checked(ldap.library_status("pool").await).service_account_names["static"].checked_out);
    assert!(ldap.check_out("pool", &request).await.is_err());
    assert!(
        checked(logged.ldap_at(SECRETS))
            .force_check_in("pool", &LdapCheckInRequest::new(["static"]))
            .await
            .is_err()
    );
    stage!("library-checkin");
    let checkin = LdapCheckInRequest::new(["static"]);
    assert!(checked(ldap.check_in("pool", &checkin).await).check_ins == ["static"]);
    bind(&fixture, &dn, &first.password, 49);
    assert!(
        !checked(ldap.library_status("pool").await).service_account_names["static"].checked_out
    );
    stage!("library-force-checkin");
    let second = checked(ldap.check_out("pool", &request).await);
    bind(&fixture, &dn, &second.password, 0);
    assert!(checked(ldap.force_check_in("pool", &checkin).await).check_ins == ["static"]);
    bind(&fixture, &dn, &second.password, 49);
    assert!(
        !checked(ldap.library_status("pool").await).service_account_names["static"].checked_out
    );
    stage!("library-delete");
    checked(ldap.delete_library_set("pool").await);
    assert!(ldap.read_library_set("pool").await.is_err());
    checked(admin.delete_user("alice").await);
    checked(admin.delete_group("engineers").await);
    checked(ldap.delete_config().await);
    stage!("complete");
}
