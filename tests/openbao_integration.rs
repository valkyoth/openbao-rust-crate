//! Real OpenBao integration flow.
//!
//! These tests are skipped unless `OPENBAO_INTEGRATION=1` is set. Use
//! `scripts/openbao_integration.sh` to start a local TLS OpenBao instance,
//! initialize it, unseal it, and run this file.

#![cfg(all(feature = "kv1", feature = "kv2", feature = "sys", feature = "token"))]
#![allow(clippy::panic)]
#![allow(deprecated)]

use std::{
    collections::BTreeMap,
    env, fs, process,
    time::{SystemTime, UNIX_EPOCH},
};

use openbao::{Client, OpenBaoConfig};
use reqwest::Certificate;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Deserialize, Serialize)]
struct SecretPayload {
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct WrappedPayload {
    value: String,
}

struct IntegrationEnv {
    addr: String,
    token: SecretString,
    ca_cert: Certificate,
}

impl IntegrationEnv {
    fn load() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if env::var("OPENBAO_INTEGRATION").ok().as_deref() != Some("1") {
            return Ok(None);
        }

        let addr = env::var("BAO_ADDR")?;
        let token = match env::var("BAO_TOKEN_FILE") {
            Ok(path) => fs::read_to_string(path)?,
            Err(_) => env::var("BAO_TOKEN")?,
        };
        let ca_path = env::var("BAO_CACERT")?;
        let ca_pem = fs::read(ca_path)?;

        Ok(Some(Self {
            addr,
            token: SecretString::from(token.trim().to_owned()),
            ca_cert: Certificate::from_pem(&ca_pem)?,
        }))
    }

    fn client(self) -> Result<openbao::Client<openbao::Authenticated>, openbao::Error> {
        let config = OpenBaoConfig::new(self.addr)?.only_root_certificates(vec![self.ca_cert])?;
        Ok(Client::from_config(config)?.with_token(self.token))
    }
}

#[tokio::test]
async fn real_openbao_default_feature_flow() -> Result<(), Box<dyn std::error::Error>> {
    let Some(env) = IntegrationEnv::load()? else {
        return Ok(());
    };
    let client = env.client()?;
    let suffix = unique_suffix()?;
    let kv1_mount = format!("obrs-kv1-{suffix}");
    let kv2_mount = format!("obrs-kv2-{suffix}");
    let auth_mount = format!("obrs-auth-{suffix}");
    let policy_name = format!("obrs-policy-{suffix}");

    let _ = client.sys().disable_mount(&kv1_mount).await;
    let _ = client.sys().disable_mount(&kv2_mount).await;
    let _ = client.sys().disable_auth_method(&auth_mount).await;
    let _ = client.sys().delete_policy(&policy_name).await;

    let result = run_flow(&client, &kv1_mount, &kv2_mount, &auth_mount, &policy_name).await;

    let _ = client.sys().disable_mount(&kv1_mount).await;
    let _ = client.sys().disable_mount(&kv2_mount).await;
    let _ = client.sys().disable_auth_method(&auth_mount).await;
    let _ = client.sys().delete_policy(&policy_name).await;

    result?;
    Ok(())
}

async fn run_flow(
    client: &openbao::Client<openbao::Authenticated>,
    kv1_mount: &str,
    kv2_mount: &str,
    auth_mount: &str,
    policy_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let seal = client.sys().seal_status().await?;
    assert!(seal.initialized);
    assert!(!seal.sealed);

    client
        .sys()
        .enable_mount(kv1_mount, &kv_request("kv", BTreeMap::new()))
        .await?;

    let mut kv2_options = BTreeMap::new();
    kv2_options.insert("version".to_owned(), "2".to_owned());
    client
        .sys()
        .enable_mount(kv2_mount, &kv_request("kv", kv2_options))
        .await?;

    let mounts = client.sys().list_mounts().await?;
    assert!(mounts.contains_key(&format!("{kv1_mount}/")));
    assert!(mounts.contains_key(&format!("{kv2_mount}/")));
    assert_eq!(client.sys().read_mount(kv2_mount).await?.backend_type, "kv");

    client
        .sys()
        .enable_auth_method(
            auth_mount,
            &openbao::sys::AuthEnableRequest {
                backend_type: "userpass".to_owned(),
                description: Some("openbao crate integration test".to_owned()),
                config: None,
                local: Some(true),
            },
        )
        .await?;
    let auth_methods = client.sys().list_auth_methods().await?;
    assert!(auth_methods.contains_key(&format!("{auth_mount}/")));
    let auth_tune = client.sys().read_auth_tune(auth_mount).await?;
    client
        .sys()
        .tune_auth_method(auth_mount, &auth_tune)
        .await?;

    let kv1 = client.kv1(kv1_mount)?;
    kv1.write(
        "app/config",
        SecretPayload {
            value: "kv1".to_owned(),
        },
    )
    .await?;
    let kv1_read: SecretPayload = kv1.read("app/config").await?;
    assert_eq!(kv1_read.value, "kv1");
    assert!(
        kv1.list("app")
            .await?
            .keys
            .iter()
            .any(|key| key == "config")
    );

    let kv2 = client.kv2(kv2_mount)?;
    assert_eq!(
        kv2.write("app/config", json!({ "value": "one" }))
            .await?
            .version,
        1
    );
    assert_eq!(
        kv2.patch("app/config", json!({ "extra": "two" }))
            .await?
            .version,
        2
    );
    let kv2_read = kv2.read::<BTreeMap<String, Value>>("app/config").await?;
    assert_eq!(
        kv2_read.data.get("value").and_then(Value::as_str),
        Some("one")
    );
    assert_eq!(
        kv2_read.data.get("extra").and_then(Value::as_str),
        Some("two")
    );
    assert_eq!(kv2.metadata("app/config").await?.current_version, 2);
    assert!(kv2.config().await?.max_versions.is_some());

    let token_info = client.token().lookup_self().await?;
    assert!(token_info.policies.iter().any(|policy| policy == "root"));

    let capability_path = format!("{kv2_mount}/data/app/config");
    client
        .sys()
        .write_policy(
            policy_name,
            &openbao::sys::PolicyWriteRequest {
                policy: format!("path \"{capability_path}\" {{ capabilities = [\"read\"] }}"),
                expiration: None,
                ttl: Some("10m".to_owned()),
                cas: None,
                cas_required: None,
            },
        )
        .await?;
    assert!(
        client
            .sys()
            .list_policies()
            .await?
            .policies
            .iter()
            .any(|policy| policy == policy_name)
    );
    assert!(
        client
            .sys()
            .read_policy(policy_name)
            .await?
            .rules
            .contains(&capability_path)
    );

    let self_capabilities = client
        .sys()
        .capabilities_self([capability_path.clone()])
        .await?;
    assert!(
        self_capabilities
            .by_path
            .get(&capability_path)
            .is_some_and(|capabilities| capabilities.iter().any(|capability| capability == "root"))
    );

    let child_token = client
        .token()
        .create(&openbao::auth::token::TokenCreateRequest {
            policies: vec![policy_name.to_owned()],
            ttl: Some("60s".to_owned()),
            renewable: Some(false),
            no_default_policy: Some(true),
            ..Default::default()
        })
        .await?;
    let token_capabilities = client
        .sys()
        .capabilities(&child_token.client_token, [capability_path.clone()])
        .await?;
    assert!(
        token_capabilities
            .by_path
            .get(&capability_path)
            .is_some_and(|capabilities| capabilities.iter().any(|capability| capability == "read"))
    );
    let accessor_capabilities = client
        .sys()
        .capabilities_accessor(&child_token.accessor, [capability_path.clone()])
        .await?;
    assert!(
        accessor_capabilities
            .by_path
            .get(&capability_path)
            .is_some_and(|capabilities| capabilities.iter().any(|capability| capability == "read"))
    );
    client.token().revoke(&child_token.client_token).await?;

    let wrap_info = client
        .sys()
        .wrapping_wrap(
            "60s",
            &WrappedPayload {
                value: "wrapped".to_owned(),
            },
        )
        .await?;
    assert_eq!(wrap_info.ttl, 60);
    let lookup = client.sys().wrapping_lookup(&wrap_info.token).await?;
    assert_eq!(lookup.creation_ttl, 60);
    let unwrapped: WrappedPayload = client.sys().wrapping_unwrap(Some(&wrap_info.token)).await?;
    assert_eq!(unwrapped.value, "wrapped");

    Ok(())
}

fn kv_request(
    backend_type: &str,
    options: BTreeMap<String, String>,
) -> openbao::sys::MountEnableRequest {
    openbao::sys::MountEnableRequest {
        backend_type: backend_type.to_owned(),
        description: Some("openbao crate integration test".to_owned()),
        config: None,
        options,
        local: Some(true),
        seal_wrap: None,
        external_entropy_access: None,
    }
}

fn unique_suffix() -> Result<String, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(format!("{}-{nanos}", process::id()))
}
