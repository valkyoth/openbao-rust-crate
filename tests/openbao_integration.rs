//! Real OpenBao integration flow.
//!
//! These tests are skipped unless `OPENBAO_INTEGRATION=1` is set. Use
//! `scripts/openbao_integration.sh` to select an exact locked release, start an
//! isolated local TLS instance, verify its version, initialize and unseal it,
//! and run this file.

#![cfg(all(feature = "kv1", feature = "kv2", feature = "sys", feature = "token"))]
#![allow(clippy::panic, clippy::print_stderr)]

use std::{
    collections::BTreeMap,
    env, fs, io, process,
    time::{SystemTime, UNIX_EPOCH},
};

use openbao::{Client, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion};
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
    expected_version: String,
    result_file: String,
}

impl IntegrationEnv {
    fn load() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if env::var("OPENBAO_INTEGRATION").ok().as_deref() != Some("1") {
            return Ok(None);
        }

        let addr = env::var("BAO_ADDR")?;
        let token = fs::read_to_string(env::var("BAO_TOKEN_FILE")?)?;
        let ca_path = env::var("BAO_CACERT")?;
        let ca_pem = fs::read(ca_path)?;
        let expected_version = env::var("OPENBAO_EXPECTED_VERSION")?;
        let result_file = env::var("OPENBAO_RESULT_FILE")?;

        Ok(Some(Self {
            addr,
            token: SecretString::from(token.trim().to_owned()),
            ca_cert: Certificate::from_pem(&ca_pem)?,
            expected_version,
            result_file,
        }))
    }

    fn client(self) -> Result<openbao::Client<openbao::Authenticated>, openbao::Error> {
        let version = self.expected_version.parse::<OpenBaoVersion>()?;
        let policy = OpenBaoCompatibilityPolicy::exact(version)?;
        let config = OpenBaoConfig::new(self.addr)?
            .only_root_certificates(vec![self.ca_cert])?
            .compatibility_policy(policy);
        Client::from_config(config)?.try_with_token(self.token)
    }
}

#[tokio::test]
async fn real_openbao_default_feature_flow() -> Result<(), Box<dyn std::error::Error>> {
    let Some(env) = IntegrationEnv::load()? else {
        return Ok(());
    };
    let expected_version = env.expected_version.clone();
    let result_file = env.result_file.clone();
    let client = env.client()?;
    eprintln!("OpenBao integration stage: health");
    assert_eq!(client.sys().health().await?.version, expected_version);
    let suffix = unique_suffix()?;
    let kv1_mount = format!("obrs-kv1-{suffix}");
    let kv2_mount = format!("obrs-kv2-{suffix}");
    let auth_mount = format!("obrs-auth-{suffix}");
    #[cfg(feature = "operator-ops")]
    let jwt_mount = format!("obrs-jwt-{suffix}");
    let policy_name = format!("obrs-policy-{suffix}");
    #[cfg(feature = "operator-ops")]
    let namespace = format!("obrs-ns-{suffix}");
    #[cfg(feature = "operator-ops")]
    let workflow = format!("obrs-flow-{suffix}");
    #[cfg(feature = "operator-ops")]
    let hashed_user = format!("obrs-user-{suffix}");

    let result = run_flow(&client, &kv1_mount, &kv2_mount, &auth_mount, &policy_name).await;
    #[cfg(feature = "operator-ops")]
    let latest_result = if result.is_ok() && expected_version == "2.6.0" {
        run_2_6_flow(
            &client,
            &kv1_mount,
            &auth_mount,
            &jwt_mount,
            &namespace,
            &workflow,
            &hashed_user,
        )
        .await
    } else {
        Ok(())
    };
    #[cfg(not(feature = "operator-ops"))]
    let latest_result: Result<(), Box<dyn std::error::Error>> = if expected_version == "2.6.0" {
        Err(io::Error::other("OpenBao 2.6.0 integration requires the operator-ops feature").into())
    } else {
        Ok(())
    };
    #[cfg(feature = "operator-ops")]
    if expected_version == "2.6.0" {
        cleanup_2_6_flow(
            &client,
            &jwt_mount,
            &namespace,
            &workflow,
            &auth_mount,
            &hashed_user,
        )
        .await?;
    }
    cleanup_flow(&client, &kv1_mount, &kv2_mount, &auth_mount, &policy_name).await?;
    result?;
    latest_result?;
    write_core_flow_attestation(&result_file, &expected_version)?;
    Ok(())
}

async fn cleanup_flow(
    client: &Client<openbao::Authenticated>,
    kv1_mount: &str,
    kv2_mount: &str,
    auth_mount: &str,
    policy_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = client.sys().disable_mount(kv1_mount).await;
    let _ = client.sys().disable_mount(kv2_mount).await;
    let _ = client.sys().disable_auth_method(auth_mount).await;
    let _ = client.sys().delete_policy(policy_name).await;

    let mounts = client.sys().list_mounts().await?;
    let auth_methods = client.sys().list_auth_methods().await?;
    let policies = client.sys().list_policies().await?;
    if mounts.contains_key(&format!("{kv1_mount}/"))
        || mounts.contains_key(&format!("{kv2_mount}/"))
        || auth_methods.contains_key(&format!("{auth_mount}/"))
        || policies.policies.iter().any(|policy| policy == policy_name)
    {
        return Err(io::Error::other("OpenBao integration resource cleanup failed").into());
    }
    Ok(())
}

const CORE_OPERATION_IDS: [&str; 14] = [
    "health",
    "mount-management",
    "kv1",
    "kv2",
    "policy",
    "token",
    "capabilities",
    "response-wrapping",
    "root-generation-routing",
    "sealable-namespace",
    "workflow",
    "jwt-cel",
    "userpass-password-hash",
    "changed-response-fields",
];

const OPENBAO_2_6_OPERATION_IDS: [&str; 6] = [
    "root-generation-routing",
    "sealable-namespace",
    "workflow",
    "jwt-cel",
    "userpass-password-hash",
    "changed-response-fields",
];

#[derive(Serialize)]
struct CoreFlowAttestation<'a> {
    schema: &'static str,
    version: &'a str,
    executed: Vec<&'static str>,
    skipped: Vec<&'static str>,
}

fn write_core_flow_attestation(
    result_file: &str,
    expected_version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let is_2_6 = expected_version == "2.6.0";
    let encoded = serde_json::to_vec(&CoreFlowAttestation {
        schema: "openbao-core-flow-attestation/v1",
        version: expected_version,
        executed: if is_2_6 {
            CORE_OPERATION_IDS.to_vec()
        } else {
            CORE_OPERATION_IDS[..8].to_vec()
        },
        skipped: if is_2_6 {
            Vec::new()
        } else {
            OPENBAO_2_6_OPERATION_IDS.to_vec()
        },
    })?;
    fs::write(result_file, encoded)?;
    Ok(())
}

#[cfg(feature = "operator-ops")]
async fn run_2_6_flow(
    client: &Client<openbao::Authenticated>,
    kv1_mount: &str,
    userpass_mount: &str,
    jwt_mount: &str,
    namespace: &str,
    workflow: &str,
    hashed_user: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("OpenBao integration stage: root-generation-routing");
    assert!(!client.sys().operator_generate_root_status().await?.started);
    let started = client
        .sys()
        .operator_generate_root_start(&openbao::sys::OperatorTokenGenerationStartRequest::new())
        .await?;
    assert!(started.status.started);
    assert!(started.otp.is_some());
    client.sys().operator_generate_root_cancel().await?;
    assert!(!client.sys().operator_generate_root_status().await?.started);

    eprintln!("OpenBao integration stage: sealable-namespace");
    let creation = client
        .sys()
        .create_sealable_namespace(
            namespace,
            &openbao::sys::SealableNamespaceRequest::new(1, 1)?,
        )
        .await?;
    assert_eq!(creation.key_threshold, 1);
    let share = creation
        .key_shares
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("sealable namespace returned no unseal share"))?;
    if !client.sys().namespace_seal_status(namespace).await?.sealed {
        client.sys().seal_namespace(namespace).await?;
    }
    assert!(client.sys().namespace_seal_status(namespace).await?.sealed);
    assert!(
        !client
            .sys()
            .unseal_namespace(namespace, &share)
            .await?
            .sealed
    );

    eprintln!("OpenBao integration stage: workflow");
    let definition = openbao::sys::WorkflowWriteRequest::new(SecretString::from(format!(
        "flow \"read\" {{ request \"secret\" {{ operation = \"read\" path = \"{kv1_mount}/app/config\" }} }}"
    )))?;
    eprintln!("OpenBao integration stage: workflow-write");
    let stored = client.sys().write_workflow(workflow, &definition).await?;
    assert_eq!(stored.path, workflow);
    eprintln!("OpenBao integration stage: workflow-list");
    assert!(
        client
            .sys()
            .list_workflows()
            .await?
            .keys
            .iter()
            .any(|key| key == workflow)
    );
    eprintln!("OpenBao integration stage: workflow-execute");
    let _ = client
        .sys()
        .execute_workflow(workflow, &openbao::sys::WorkflowData::empty())
        .await?;

    eprintln!("OpenBao integration stage: jwt-cel");
    client
        .sys()
        .enable_auth_method(
            jwt_mount,
            &openbao::sys::AuthEnableRequest {
                backend_type: "jwt".to_owned(),
                description: Some("openbao crate 2.6 integration test".to_owned()),
                config: None,
                local: Some(true),
            },
        )
        .await?;
    let jwt = client.jwt_admin_at(jwt_mount)?;
    let role = openbao::auth::jwt::JwtCelRoleRequest::new(openbao::auth::jwt::JwtCelProgram::new(
        "false",
    )?);
    assert_eq!(jwt.write_cel_role("service", &role).await?.name, "service");
    assert_eq!(jwt.read_cel_role("service").await?.name, "service");
    assert!(
        jwt.list_cel_roles()
            .await?
            .keys
            .iter()
            .any(|name| name == "service")
    );

    eprintln!("OpenBao integration stage: userpass-password-hash");
    let first_hash = openbao::auth::userpass::UserpassPasswordHash::bcrypt(SecretString::from(
        format!("$2b$10${}", "A".repeat(53)),
    ))?;
    let second_hash = openbao::auth::userpass::UserpassPasswordHash::bcrypt(SecretString::from(
        format!("$2b$10${}", "B".repeat(53)),
    ))?;
    let userpass = client.userpass_admin_at(userpass_mount)?;
    userpass
        .write_hashed_user(
            hashed_user,
            &openbao::auth::userpass::UserpassHashedUserRequest::new(first_hash),
        )
        .await?;
    let _ = userpass.read_user(hashed_user).await?;
    userpass
        .update_password_hash(hashed_user, &second_hash)
        .await?;

    eprintln!("OpenBao integration stage: changed-response-fields");
    let seal = client.sys().seal_status().await?;
    assert_eq!(seal.version, "2.6.0");
    assert!(seal.commit_date.is_some());
    Ok(())
}

#[cfg(feature = "operator-ops")]
async fn cleanup_2_6_flow(
    client: &Client<openbao::Authenticated>,
    jwt_mount: &str,
    namespace: &str,
    workflow: &str,
    userpass_mount: &str,
    hashed_user: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = client.sys().operator_generate_root_cancel().await;
    let _ = client.sys().delete_workflow(workflow).await;
    let _ = client
        .jwt_admin_at(jwt_mount)?
        .delete_cel_role("service")
        .await;
    let _ = client
        .userpass_admin_at(userpass_mount)?
        .delete_user(hashed_user)
        .await;
    let _ = client.sys().delete_namespace(namespace).await;
    if client
        .sys()
        .list_namespaces()
        .await?
        .keys
        .iter()
        .any(|path| path.trim_end_matches('/') == namespace)
    {
        let _ = client
            .sys()
            .delete_sealed_namespace(namespace, openbao::sys::SealedNamespaceDeletion::confirm())
            .await;
    }
    let _ = client.sys().disable_auth_method(jwt_mount).await;
    Ok(())
}

async fn run_flow(
    client: &openbao::Client<openbao::Authenticated>,
    kv1_mount: &str,
    kv2_mount: &str,
    auth_mount: &str,
    policy_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("OpenBao integration stage: health");
    let seal = client.sys().seal_status().await?;
    assert!(seal.initialized);
    assert!(!seal.sealed);

    eprintln!("OpenBao integration stage: mount-management");
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

    eprintln!("OpenBao integration stage: kv1");
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

    eprintln!("OpenBao integration stage: kv2");
    let kv2 = client.kv2(kv2_mount)?;
    eprintln!("OpenBao integration stage: kv2-write");
    assert_eq!(
        kv2.write("app/config", json!({ "value": "one" }))
            .await?
            .version,
        1
    );
    eprintln!("OpenBao integration stage: kv2-patch");
    assert_eq!(
        kv2.patch("app/config", json!({ "extra": "two" }))
            .await?
            .version,
        2
    );
    eprintln!("OpenBao integration stage: kv2-read");
    let kv2_read = kv2.read::<BTreeMap<String, Value>>("app/config").await?;
    assert_eq!(
        kv2_read.data.get("value").and_then(Value::as_str),
        Some("one")
    );
    assert_eq!(
        kv2_read.data.get("extra").and_then(Value::as_str),
        Some("two")
    );
    eprintln!("OpenBao integration stage: kv2-metadata");
    assert_eq!(kv2.metadata("app/config").await?.current_version, 2);
    eprintln!("OpenBao integration stage: kv2-config");
    assert!(kv2.config().await?.max_versions.is_some());

    eprintln!("OpenBao integration stage: token");
    let token_info = client.token().lookup_self().await?;
    assert!(token_info.policies.iter().any(|policy| policy == "root"));

    eprintln!("OpenBao integration stage: policy");
    let capability_path = format!("{kv2_mount}/data/app/config");
    client
        .sys()
        .write_policy(
            policy_name,
            &openbao::sys::PolicyWriteRequest {
                policy: format!("path \"{capability_path}\" {{ capabilities = [\"read\"] }}"),
                expiration: None,
                ttl: None,
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

    eprintln!("OpenBao integration stage: capabilities");
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

    eprintln!("OpenBao integration stage: response-wrapping");
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
