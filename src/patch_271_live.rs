//! Exact patch acceptance in a disposable candidate build, never a routing bypass.

use crate::auth::approle::{AppRoleRoleRequest, AppRoleSecretIdRequest};
use crate::secrets::transit::{
    TransitCreateKeyRequest, TransitDecryptRequest, TransitEncryptRequest,
};
use crate::sys::{AuthEnableRequest, MountEnableRequest, WorkflowWriteRequest};
use crate::{
    Client, ExposeSecret, OpenBaoCompatibilityPolicy, OpenBaoCompatibilityStatus, OpenBaoConfig,
    OpenBaoVersion, SecretString,
};
use serde::Deserialize;
use std::{collections::BTreeMap, io::Read, time::Duration};

// The live runner accepts only these literal-only progress messages, never
// formatted values, server responses, or credentials.
macro_rules! stage {
    ($phase:literal) => {{
        #[allow(clippy::print_stdout)]
        {
            println!(concat!("patch-stage:", $phase));
        }
    }};
}
#[cfg(all(
    feature = "kv1",
    feature = "kv2",
    feature = "token",
    feature = "ldap-auth",
    feature = "kerberos-auth",
    feature = "radius-auth",
    feature = "ldap"
))]
pub(super) use stage;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    addresses: [String; 3],
    ca_pem: String,
    token: SecretString,
}

fn checked<T, E>(result: core::result::Result<T, E>) -> T {
    #[allow(clippy::panic)]
    result.unwrap_or_else(|_| panic!("patch SDK TLS assertion failed"))
}

#[tokio::test]
#[ignore = "requires a constrained exact 2.7.1 TLS server and a candidate registry build"]
async fn public_patch_tls() {
    let client = run_patch(OpenBaoVersion::new(2, 7, 1)).await;
    verify_workflow_cas(&client).await;
}

async fn verify_workflow_cas(client: &Client<crate::Authenticated>) {
    stage!("workflow-cas");
    let sys = client.sys();
    let path = "patch-sdk-cas";
    let request = || {
        checked(WorkflowWriteRequest::new(SecretString::from(
            "flow \"check\" { request \"status\" { operation = \"read\" path = \"sys/seal-status\" } }",
        )))
        .require_cas(true)
    };
    let created = checked(
        sys.write_workflow(path, &checked(request().with_cas(-1)))
            .await,
    );
    assert!(created.version == 1 && created.cas_required && !created.allow_unauthenticated);
    let updated = checked(
        sys.write_workflow(path, &checked(request().with_cas(1)))
            .await,
    );
    assert!(updated.version == 2 && updated.cas_required && !updated.allow_unauthenticated);
    for cas in [None, Some(-1), Some(0), Some(1), Some(3)] {
        let rejected = match cas {
            Some(value) => checked(request().with_cas(value)),
            None => request(),
        };
        let result = sys.write_workflow(path, &rejected).await;
        assert!(matches!(result, Err(crate::Error::Api { status, .. }) if status.as_u16() == 400));
        let current = checked(sys.read_workflow(path).await);
        assert!(current.version == 2 && current.cas_required && !current.allow_unauthenticated);
        assert!(current.workflow.expose_secret() == updated.workflow.expose_secret());
    }
    checked(sys.delete_workflow(path).await);
    let deleted = sys.read_workflow(path).await;
    assert!(matches!(deleted, Err(crate::Error::Api { status, .. }) if status.as_u16() == 404));
}

pub(super) async fn run_patch(version: OpenBaoVersion) -> Client<crate::Authenticated> {
    stage!("profile");
    let fixture: Fixture = checked(serde_json::from_reader(std::io::stdin().lock().take(65536)));
    let address = &fixture.addresses[0];
    assert!(fixture.addresses.iter().all(|other| other == address));
    let url = checked(reqwest::Url::parse(address));
    assert!(url.scheme() == "https" && url.host_str() == Some("127.0.0.1"));
    assert!(url.username().is_empty() && url.password().is_none());
    assert!(url.path() == "/" && url.query().is_none() && url.fragment().is_none());
    let config = checked(OpenBaoConfig::new(address));
    let config = checked(config.only_root_certificates(vec![checked(
        reqwest::Certificate::from_pem(fixture.ca_pem.as_bytes()),
    )]));
    let config = checked(config.timeout(Duration::from_secs(5)))
        .compatibility_policy(checked(OpenBaoCompatibilityPolicy::exact(version)));
    let unauthenticated = checked(Client::from_config(config.clone()));
    let client = checked(checked(Client::from_config(config)).try_with_token(fixture.token));
    let report = checked(client.compatibility_report().await);
    assert!(report.status() == OpenBaoCompatibilityStatus::Verified);
    assert!(
        report.profile_version() == Some(version) && report.detected_version() == Some(version)
    );
    assert!(checked(client.sys().health().await).version == version.to_string());
    assert!(OpenBaoCompatibilityPolicy::exact(OpenBaoVersion::new(2, 7, 2)).is_err());
    assert!(OpenBaoCompatibilityPolicy::exact(OpenBaoVersion::new(2, 6, 5)).is_err());

    stage!("approle");
    checked(
        client
            .sys()
            .enable_auth_method(
                "patch-sdk",
                &AuthEnableRequest {
                    backend_type: "approle".to_owned(),
                    description: None,
                    config: None,
                    local: Some(true),
                },
            )
            .await,
    );
    let admin = checked(client.approle_admin_at("patch-sdk"));
    checked(
        admin
            .write_role(
                "fixture",
                &AppRoleRoleRequest {
                    secret_id_ttl: Some("5s".to_owned()),
                    bind_secret_id: Some(true),
                    ..Default::default()
                },
            )
            .await,
    );
    let role = checked(admin.read_role_id("fixture").await);
    let secret = checked(
        admin
            .generate_secret_id("fixture", &AppRoleSecretIdRequest::default())
            .await,
    );
    let login = checked(unauthenticated.approle_at("patch-sdk"));
    let _ = checked(
        login
            .login(role.role_id.clone(), secret.secret_id.clone())
            .await,
    );
    stage!("expiry");
    tokio::time::sleep(Duration::from_secs(6)).await;
    let expired = checked(unauthenticated.approle_at("patch-sdk"))
        .login(role.role_id, secret.secret_id)
        .await;
    assert!(
        matches!(expired, Err(crate::Error::Api { status, .. }) if matches!(status.as_u16(), 400 | 403))
    );

    stage!("transit");
    checked(
        client
            .sys()
            .enable_mount(
                "patch-sdk-transit",
                &MountEnableRequest {
                    backend_type: "transit".to_owned(),
                    description: None,
                    config: None,
                    options: BTreeMap::new(),
                    local: Some(true),
                    seal_wrap: None,
                    external_entropy_access: None,
                },
            )
            .await,
    );
    let transit = checked(client.transit("patch-sdk-transit"));
    checked(
        transit
            .create_key("fixture", &TransitCreateKeyRequest::default())
            .await,
    );
    checked(transit.rotate_key("fixture").await);
    let plaintext = b"disposable-patch-sdk-message";
    let request = checked(TransitEncryptRequest::from_plaintext_bytes(plaintext));
    let mut request = checked(request.with_associated_data_bytes(b"patch-sdk-binding"));
    let latest = checked(transit.encrypt("fixture", &request).await);
    assert!(latest.key_version == Some(2));
    request.key_version = Some(1);
    let encrypted = checked(transit.encrypt("fixture", &request).await);
    assert!(encrypted.key_version == Some(1));
    let decode = checked(
        TransitDecryptRequest::new(encrypted.ciphertext.clone())
            .with_associated_data_bytes(b"patch-sdk-binding"),
    );
    let decoded = checked(transit.decrypt("fixture", &decode).await);
    checked(decoded.plaintext_bytes()).with_secret(|bytes| assert!(bytes == plaintext));
    let wrong = checked(
        TransitDecryptRequest::new(encrypted.ciphertext)
            .with_associated_data_bytes(b"wrong-binding"),
    );
    assert!(matches!(transit.decrypt("fixture", &wrong).await,
        Err(crate::Error::Api { status, .. }) if status == reqwest::StatusCode::BAD_REQUEST));
    checked(client.sys().disable_mount("patch-sdk-transit").await);
    checked(client.sys().disable_auth_method("patch-sdk").await);
    client
}
