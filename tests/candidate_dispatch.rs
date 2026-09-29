//! Only executed by the disposable candidate-build verifier until promotion.
#![cfg(all(
    feature = "sys",
    feature = "transit",
    feature = "pki",
    feature = "operator-ops",
    feature = "unstable-internal-ops",
    feature = "sensitive-http-test-only"
))]
#![allow(clippy::panic)]

use openbao::{
    Authenticated, Client, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion, SecretString,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

struct Step {
    method: &'static str,
    path: &'static str,
    body: Option<serde_json::Value>,
    response: &'static str,
}

fn ok<T, E>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|_| panic!("candidate fixture operation failed"))
}

fn exchange(mut stream: TcpStream, step: Step) {
    ok(stream.set_read_timeout(Some(Duration::from_secs(5))));
    ok(stream.set_write_timeout(Some(Duration::from_secs(5))));
    let mut request = Vec::new();
    let end = loop {
        assert!(request.len() < 16 * 1024, "request exceeds fixture limit");
        let mut byte = [0];
        ok(stream.read_exact(&mut byte));
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break request.len();
        }
    };
    let headers = ok(std::str::from_utf8(&request));
    let mut first = headers.lines().next().unwrap_or("").split_whitespace();
    assert!(first.next() == Some(step.method), "incorrect method");
    assert!(first.next() == Some(step.path), "incorrect path");
    if step.method == "PATCH" {
        assert!(headers.lines().any(|line| line.eq_ignore_ascii_case("content-type: application/merge-patch+json")), "incorrect patch content type");
    }
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| ok(value.trim().parse::<usize>()));
    assert!(length <= 16 * 1024, "body exceeds fixture limit");
    request.resize(end + length, 0);
    ok(stream.read_exact(&mut request[end..]));
    match step.body {
        Some(expected) => {
            let actual: serde_json::Value = ok(serde_json::from_slice(&request[end..]));
            assert!(actual == expected, "incorrect request body");
        }
        None => assert!(length == 0, "unexpected request body"),
    }
    let status = if step.response.is_empty() {
        "204 No Content"
    } else {
        "200 OK"
    };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        step.response.len(),
        step.response
    );
    ok(stream.write_all(response.as_bytes()));
}

fn fixture(
    version: OpenBaoVersion,
    steps: Vec<Step>,
) -> (Client<Authenticated>, thread::JoinHandle<()>) {
    fixture_with_policy(
        version,
        steps,
        ok(OpenBaoCompatibilityPolicy::exact(version)),
    )
}

fn fixture_with_policy(
    version: OpenBaoVersion,
    steps: Vec<Step>,
    policy: OpenBaoCompatibilityPolicy,
) -> (Client<Authenticated>, thread::JoinHandle<()>) {
    let listener = ok(TcpListener::bind("127.0.0.1:0"));
    let address = ok(listener.local_addr());
    ok(listener.set_nonblocking(true));
    let server = thread::spawn(move || {
        let health = format!("{{\"version\":\"{version}\",\"initialized\":true,\"sealed\":false}}");
        let mut steps = steps.into_iter();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut initial = true;
        loop {
            let step = if initial {
                initial = false;
                // The health response is constructed separately to keep fixtures static.
                None
            } else if let Some(step) = steps.next() {
                Some(step)
            } else {
                break;
            };
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture accept timed out");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => panic!("fixture accept failed"),
                }
            };
            if let Some(step) = step {
                exchange(stream, step);
            } else {
                health_exchange(stream, &health);
            }
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    });
    let config = ok(OpenBaoConfig::new(format!("http://{address}")));
    let config = ok(config.allow_sensitive_local_http_for_tests()).compatibility_policy(policy);
    let client = ok(ok(Client::from_config(config))
        .try_with_token(SecretString::from(["fixture-", "candidate"].concat())));
    (client, server)
}

fn health_exchange(mut stream: TcpStream, response: &str) {
    ok(stream.set_read_timeout(Some(Duration::from_secs(5))));
    ok(stream.set_write_timeout(Some(Duration::from_secs(5))));
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16 * 1024, "health request exceeds limit");
        let mut byte = [0];
        ok(stream.read_exact(&mut byte));
        bytes.push(byte[0]);
    }
    assert!(
        bytes.starts_with(b"GET /v1/sys/health "),
        "missing health probe"
    );
    let text = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response}",
        response.len()
    );
    ok(stream.write_all(text.as_bytes()));
}

#[tokio::test]
#[ignore = "requires the disposable candidate-build verifier"]
async fn strict_workflow_list_and_scan_preserve_distinct_methods() {
    let (client, server) = fixture(
        OpenBaoVersion::new(2, 7, 0),
        vec![
            Step {
                method: "LIST",
                path: "/v1/sys/workflows/manage",
                body: None,
                response: r#"{"data":{"keys":["one"]}}"#,
            },
            Step {
                method: "SCAN",
                path: "/v1/sys/workflows/manage?after=one&limit=2",
                body: None,
                response: r#"{"data":{"keys":["two"]}}"#,
            },
        ],
    );
    ok(client.sys().list_workflows().await);
    let options = ok(ok(openbao::ListPageOptions::new().after("one")).limit(2));
    ok(client.sys().scan_workflows(&options).await);
    ok(server.join());
}

#[tokio::test]
#[ignore = "requires the disposable candidate-build verifier"]
async fn strict_transit_rotation_keeps_legacy_empty_body_and_external_reference_separate() {
    let (client, server) = fixture(
        OpenBaoVersion::new(2, 7, 0),
        vec![
            Step {
                method: "POST",
                path: "/v1/transit/keys/local/rotate",
                body: None,
                response: "{}",
            },
            Step {
                method: "POST",
                path: "/v1/transit/keys/remote/rotate",
                body: Some(serde_json::json!({"external_key_ref":"provider:next"})),
                response: r#"{"data":{"name":"remote","type":"external","latest_version":2}}"#,
            },
        ],
    );
    let transit = ok(client.transit("transit"));
    ok(transit.rotate_key("local").await);
    let reference = ok(openbao::secrets::transit::TransitExternalKeyReference::new(
        "provider", "next",
    ));
    let result = ok(transit.rotate_external_key("remote", &reference).await);
    assert_eq!(result.latest_version, 2);
    ok(server.join());
}

#[tokio::test]
#[ignore = "requires the disposable candidate-build verifier"]
async fn strict_inspection_routes_are_version_specific() {
    for (version, path) in [
        (
            OpenBaoVersion::new(2, 5, 5),
            "/v1/sys/internal/inspect/request/root",
        ),
        (
            OpenBaoVersion::new(2, 7, 0),
            "/v1/sys/internal/inspect/request",
        ),
    ] {
        let (client, server) = fixture(
            version,
            vec![Step {
                method: "GET",
                path,
                body: None,
                response: r#"{"data":{}}"#,
            }],
        );
        ok(client.sys().internal_request_inspection().await);
        ok(server.join());
    }
}

#[tokio::test]
#[ignore = "requires the disposable candidate-build verifier"]
async fn historical_profiles_keep_legacy_rotation_and_reject_new_fields() {
    let reference = ok(openbao::secrets::transit::TransitExternalKeyReference::new(
        "provider", "next",
    ));
    let mut checked = 0;
    for version in openbao::openbao_profile_versions()
        .iter()
        .copied()
        .filter(|version| *version < OpenBaoVersion::new(2, 7, 0))
    {
        let (client, server) = fixture(
            version,
            vec![Step {
                method: "POST",
                path: "/v1/transit/keys/local/rotate",
                body: None,
                response: "{}",
            }],
        );
        let transit = ok(client.transit("transit"));
        ok(transit.rotate_key("local").await);
        assert!(matches!(
            transit.rotate_external_key("remote", &reference).await,
            Err(openbao::Error::UnsupportedOpenBaoCapability {
                endpoint: "transit.2.7",
                ..
            })
        ));
        ok(server.join());
        checked += 1;
    }
    assert_eq!(checked, 25);
    let (client, server) = fixture(OpenBaoVersion::new(2, 7, 0), vec![]);
    assert_externalized_engines_rejected(&client).await;
    ok(server.join());
}

async fn assert_externalized_engines_rejected(client: &Client<Authenticated>) {
    #[cfg(all(
        feature = "ldap",
        feature = "ldap-auth",
        feature = "kerberos-auth",
        feature = "radius-auth"
    ))]
    {
        let errors = [
            ok(client.ldap()).read_config().await.err(),
            ok(client.ldap_auth_admin()).read_config().await.err(),
            ok(client.kerberos_auth_admin()).read_config().await.err(),
            ok(client.radius_admin()).list_users().await.err(),
        ];
        for error in errors {
            assert!(
                matches!(error, Some(openbao::Error::UnsupportedOpenBaoCapability { version, .. })
                    if version == OpenBaoVersion::new(2, 7, 0)),
                "externalized engine was not rejected by the selected profile"
            );
        }
    }
    // Feature-subset builds still perform the health exchange expected by the fixture.
    let report = ok(client.compatibility_report().await);
    assert_eq!(report.profile_version(), Some(OpenBaoVersion::new(2, 7, 0)));
}

#[tokio::test]
#[ignore = "requires the disposable candidate-build verifier"]
async fn rolling_range_uses_detected_routes_but_does_not_relax_cas_policy() {
    let old = OpenBaoVersion::new(2, 6, 3);
    let new = OpenBaoVersion::new(2, 7, 0);
    let policy = ok(OpenBaoCompatibilityPolicy::range(ok(
        openbao::OpenBaoVersionRequirement::inclusive(old, new),
    )));
    for version in [old, new] {
        let (client, server) = fixture_with_policy(
            version,
            vec![Step {
                method: "LIST",
                path: "/v1/sys/workflows/manage",
                body: None,
                response: r#"{"data":{"keys":[]}}"#,
            }],
            policy,
        );
        ok(client.sys().list_workflows().await);
        let report = ok(client.compatibility_report().await);
        assert_eq!(report.profile_version(), Some(version));
        let request = ok(
            ok(openbao::sys::WorkflowWriteRequest::new(SecretString::from(
                "flow {}",
            )))
            .with_cas(0),
        );
        assert!(matches!(
            client.sys().write_workflow("candidate", &request).await,
            Err(openbao::Error::InvalidParameter(_))
        ));
        if version == new {
            assert_externalized_engines_rejected(&client).await;
        }
        ok(server.join());
    }
}

#[tokio::test]
#[ignore = "requires the disposable candidate-build verifier"]
async fn strict_external_key_administration_covers_all_thirteen_routes() {
    use openbao::sys::external_keys::*;
    const CONFIG: &str = "/v1/sys/external-keys/configs/provider";
    const KEY: &str = "/v1/sys/external-keys/configs/provider/keys/key";
    const GRANT: &str = "/v1/sys/external-keys/configs/provider/keys/key/grants/team/transit";
    let patch_body = serde_json::json!({"verify":true,"unused":null});
    let (client, server) = fixture(
        OpenBaoVersion::new(2, 7, 0),
        vec![
            Step {
                method: "LIST",
                path: "/v1/sys/external-keys/configs",
                body: None,
                response: r#"{"data":{"keys":["provider"]}}"#,
            },
            Step {
                method: "POST",
                path: CONFIG,
                body: Some(
                    serde_json::json!({"plugin":"transit","verify":true,"address":"https://remote.example","token":"fixture-provider","mount_path":"transit","tls_skip_verify":false}),
                ),
                response: "",
            },
            Step {
                method: "GET",
                path: CONFIG,
                body: None,
                response: r#"{"data":{"plugin":"transit"}}"#,
            },
            Step {
                method: "PATCH",
                path: CONFIG,
                body: Some(patch_body.clone()),
                response: "",
            },
            Step {
                method: "LIST",
                path: "/v1/sys/external-keys/configs/provider/keys",
                body: None,
                response: r#"{"data":{"keys":["key"]}}"#,
            },
            Step {
                method: "POST",
                path: KEY,
                body: Some(
                    serde_json::json!({"verify":true,"name":"remote","version":1,"disable_prehashing":false}),
                ),
                response: "",
            },
            Step {
                method: "GET",
                path: KEY,
                body: None,
                response: r#"{"data":{"name":"remote","version":1}}"#,
            },
            Step {
                method: "PATCH",
                path: KEY,
                body: Some(patch_body),
                response: "",
            },
            Step {
                method: "POST",
                path: GRANT,
                body: None,
                response: "",
            },
            Step {
                method: "LIST",
                path: "/v1/sys/external-keys/configs/provider/keys/key/grants",
                body: None,
                response: r#"{"data":{"keys":["team/transit"]}}"#,
            },
            Step {
                method: "DELETE",
                path: GRANT,
                body: None,
                response: "",
            },
            Step {
                method: "DELETE",
                path: KEY,
                body: None,
                response: "",
            },
            Step {
                method: "DELETE",
                path: CONFIG,
                body: None,
                response: "",
            },
        ],
    );
    let sys = client.sys();
    let options = openbao::ListPageOptions::new();
    assert_eq!(
        ok(sys.list_external_key_configs(&options).await).keys,
        ["provider"]
    );
    let request = ExternalKeyConfigRequest::transit(ok(TransitExternalKeyConfig::new(
        "https://remote.example",
        SecretString::from(["fixture-", "provider"].concat()),
    )));
    ok(sys.write_external_key_config("provider", &request).await);
    ok(sys.read_external_key_config("provider").await);
    let patch_options = || {
        ok(ExternalKeyOptions::from_json(
            sanitization::SecretVec::from_slice(br#"{"unused":null}"#),
        ))
    };
    let ack = ExternalKeyCustomOptionsAcknowledgement::acknowledge_unvalidated_provider;
    ok(sys
        .patch_external_key_config(
            "provider",
            &ExternalKeyConfigPatch::new(patch_options(), ack()),
        )
        .await);
    assert_eq!(
        ok(sys.list_external_keys("provider", &options).await).keys,
        ["key"]
    );
    ok(sys
        .write_external_key(
            "provider",
            "key",
            &ExternalKeyKeyRequest::transit(ok(TransitExternalKey::new("remote", 1))),
        )
        .await);
    ok(sys.read_external_key("provider", "key").await);
    ok(sys
        .patch_external_key(
            "provider",
            "key",
            &ExternalKeyKeyPatch::new(patch_options(), ack()),
        )
        .await);
    ok(sys
        .grant_external_key("provider", "key", "team/transit")
        .await);
    assert_eq!(
        ok(sys.list_external_key_grants("provider", "key").await).keys,
        ["team/transit"]
    );
    ok(sys
        .delete_external_key_grant("provider", "key", "team/transit")
        .await);
    ok(sys.delete_external_key("provider", "key").await);
    ok(sys.delete_external_key_config("provider").await);
    ok(server.join());
}

#[tokio::test]
#[ignore = "requires the disposable candidate-build verifier"]
async fn strict_control_group_review_and_authorization_do_not_execute() {
    let body = serde_json::json!({"accessor":"fixture-accessor"});
    let (client, server) = fixture(
        OpenBaoVersion::new(2, 7, 0),
        vec![
            Step {
                method: "POST",
                path: "/v1/sys/control-group/request",
                body: Some(body.clone()),
                response: r#"{"data":{"approved":false,"request_operation":"read","request_path":"secret/item","request_data":null,"request_entity":{},"authorizations":[]}}"#,
            },
            Step {
                method: "POST",
                path: "/v1/sys/control-group/authorize",
                body: Some(body),
                response: r#"{"data":{"approved":true}}"#,
            },
        ],
    );
    let accessor = ok(openbao::sys::control_groups::ControlGroupAccessor::new(
        SecretString::from(["fixture-", "accessor"].concat()),
    ));
    assert!(!ok(client.sys().read_control_group_request(&accessor).await).approved);
    assert!(ok(client.sys().authorize_control_group(&accessor).await).approved);
    ok(server.join());
}

#[tokio::test]
#[ignore = "requires the disposable candidate-build verifier"]
async fn strict_pki_mldsa_and_kms_fields_use_registered_custom_mount_routes() {
    use openbao::secrets::pki::{
        PkiExternalKeyReference, PkiGenerateKeyRequest, PkiKeyGenerationType,
    };
    let mut steps: Vec<_> = [44, 65, 87]
        .into_iter()
        .map(|bits| Step {
            method: "POST",
            path: "/v1/authority/keys/generate/internal",
            body: Some(serde_json::json!({"key_type":"mldsa","key_bits":bits})),
            response: r#"{"data":{"key_type":"mldsa"}}"#,
        })
        .collect();
    steps.push(Step {
        method: "POST",
        path: "/v1/authority/keys/generate/kms",
        body: Some(serde_json::json!({"external_key_ref":"provider:key"})),
        response: r#"{"data":{"key_type":"rsa","external_key_ref":"provider:key"}}"#,
    });
    let (client, server) = fixture(OpenBaoVersion::new(2, 7, 0), steps);
    let pki = ok(client.pki("authority"));
    for bits in [44, 65, 87] {
        let request = PkiGenerateKeyRequest {
            key_type: Some("mldsa".into()),
            key_bits: Some(bits),
            ..Default::default()
        };
        let key = ok(pki
            .generate_key(PkiKeyGenerationType::Internal, &request)
            .await);
        assert_eq!(key.key_type.as_deref(), Some("mldsa"));
    }
    let reference = ok(PkiExternalKeyReference::new("provider", "key"));
    let key = ok(pki
        .generate_key_kms(&reference, &PkiGenerateKeyRequest::default())
        .await);
    assert_eq!(key.external_key_ref.as_ref(), Some(&reference));
    ok(server.join());
}
