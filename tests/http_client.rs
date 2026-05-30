//! HTTP behavior tests for the OpenBao client.

#![allow(clippy::panic)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use openbao::{Client, Error, OpenBaoConfig, sys::DevBootstrapOptions};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct SecretData {
    value: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NumericSecretData {
    value: u64,
}

#[derive(Serialize)]
struct WrappedData {
    value: String,
}

#[tokio::test]
async fn kv2_read_sends_documented_headers_and_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("GET /v1/secret/data/app/config HTTP/1.1"));
        assert!(request.contains("x-vault-request: true"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"data":{"data":{"value":"ok"},"metadata":{"created_time":"2026-05-27T00:00:00Z","deletion_time":"","destroyed":false,"version":1}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let secret = client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read::<SecretData>("app/config")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(secret.data.value, "ok");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn kv2_read_optional_maps_not_found_to_none() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let _bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let body = r#"{"errors":["not found"]}"#;
        let response = format!(
            "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let secret = client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read_optional::<SecretData>("app/missing")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(secret.is_none());

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn kv2_service_config_reads_data_without_metadata_and_redacts_values() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("GET /v1/secret/data/app/config HTTP/1.1"));
        let body = r#"{"data":{"data":{"DATABASE_URL":"postgres://secret","API_KEY":"key-value"},"metadata":{"created_time":"2026-05-29T00:00:00Z","deletion_time":"","destroyed":false,"version":4}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let config = client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read_service_config("app/config")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        config.get("API_KEY").map(SecretString::expose_secret),
        Some("key-value")
    );
    let debug = format!("{config:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("key-value"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn kv2_delete_accepts_no_content() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("DELETE /v1/secret/data/app/config HTTP/1.1"));
        let response = "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .delete_latest("app/config")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn kv2_read_version_sends_version_query() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("GET /v1/secret/data/app/config?version=3 HTTP/1.1"));
        let body = r#"{"data":{"data":{"value":"old"},"metadata":{"created_time":"2026-05-27T00:00:00Z","deletion_time":"","destroyed":false,"version":3}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let secret = client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read_version::<SecretData>("app/config", 3)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(secret.data.value, "old");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn kv2_patch_sends_merge_patch_content_type() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("PATCH /v1/secret/data/app/config HTTP/1.1"));
        assert!(request.contains("content-type: application/merge-patch+json"));
        assert!(!request.contains("content-type: application/json"));
        let body = r#"{"data":{"created_time":"2026-05-27T00:00:00Z","version":2}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let response = client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .patch("app/config", WrappedData { value: "ok".into() })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(response.version, 2);

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn token_lookup_self_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/auth/token/lookup-self HTTP/1.1"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"data":{"accessor":"accessor-value","display_name":"token","policies":["default"],"renewable":true,"ttl":3600}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let info = client
        .token()
        .lookup_self()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(info.renewable);
    assert_eq!(info.policies, ["default"]);

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_enable_mount_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/mounts/secret HTTP/1.1"));
        assert!(request.contains(r#""type":"kv""#));
        assert!(request.contains(r#""version":"2""#));
        let response = "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let request = openbao::sys::MountEnableRequest::kv2();
    client
        .sys()
        .enable_mount("secret", &request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_enable_kv2_sends_versioned_kv_mount_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/mounts/apps HTTP/1.1"));
        assert!(request.contains(r#""type":"kv""#));
        assert!(request.contains(r#""description":"application secrets""#));
        assert!(request.contains(r#""options":{"version":"2"}"#));
        let response = "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .sys()
        .enable_kv2("apps", Some("application secrets"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_wrapping_wrap_sends_ttl_header() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/wrapping/wrap HTTP/1.1"));
        assert!(request.contains("x-vault-wrap-ttl: 60s"));
        assert!(request.contains(r#""value":"ok""#));
        let body = r#"{"wrap_info":{"token":"wrapping-token","accessor":"wrapping-accessor","ttl":60,"creation_path":"sys/wrapping/wrap"}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let info = client
        .sys()
        .wrapping_wrap(
            "60s",
            &WrappedData {
                value: "ok".to_owned(),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let debug = format!("{info:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("wrapping-token"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_policy_write_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/policy/app-read HTTP/1.1"));
        assert!(request.contains(r#""policy":"path \"secret/*\" { capabilities = [\"read\"] }""#));
        let response = "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .sys()
        .write_policy(
            "app-read",
            &openbao::sys::PolicyWriteRequest {
                policy: r#"path "secret/*" { capabilities = ["read"] }"#.to_owned(),
                expiration: None,
                ttl: None,
                cas: None,
                cas_required: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_capabilities_self_sends_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/capabilities-self HTTP/1.1"));
        assert!(request.contains(r#""paths":["secret/data/app"]"#));
        assert!(!request.contains(r#""token":"#));
        let body = r#"{"data":{"capabilities":["read"],"secret/data/app":["read"]}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let capabilities = client
        .sys()
        .capabilities_self(["secret/data/app"])
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(capabilities.capabilities, ["read"]);
    assert_eq!(
        capabilities.by_path.get("secret/data/app"),
        Some(&vec!["read".to_owned()])
    );

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_enable_audit_device_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/audit/file HTTP/1.1"));
        assert!(request.contains(r#""type":"file""#));
        assert!(request.contains(r#""file_path":"/tmp/openbao-audit.log""#));
        let response = "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let mut options = std::collections::BTreeMap::new();
    options.insert("file_path".to_owned(), "/tmp/openbao-audit.log".to_owned());
    let request = openbao::sys::AuditEnableRequest {
        backend_type: "file".to_owned(),
        description: None,
        options,
        local: None,
    };
    client
        .sys()
        .enable_audit_device("file", &request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_audit_hash_sends_secret_input() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/audit-hash/file HTTP/1.1"));
        assert!(request.contains(r#""input":"secret-value""#));
        let body = r#"{"hash":"hmac-sha256:abc123"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let response = client
        .sys()
        .audit_hash("file", &SecretString::from("secret-value"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(response.hash, "hmac-sha256:abc123");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_lease_lookup_sends_json_body_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/leases/lookup HTTP/1.1"));
        assert!(request.contains(r#""lease_id":"database/creds/readonly/abc""#));
        let body = r#"{"data":{"expire_time":"2026-05-28T12:00:00Z","id":"database/creds/readonly/abc","issue_time":"2026-05-28T11:00:00Z","last_renewal":null,"renewable":true,"ttl":3600}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let lookup = client
        .sys()
        .lookup_lease(&SecretString::from("database/creds/readonly/abc"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(lookup.renewable);
    assert_eq!(lookup.ttl, 3600);
    let debug = format!("{lookup:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("database/creds/readonly/abc"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_lease_renew_maps_response_envelope() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/leases/renew HTTP/1.1"));
        assert!(request.contains(r#""lease_id":"database/creds/readonly/abc""#));
        assert!(request.contains(r#""increment":1800"#));
        let body =
            r#"{"lease_id":"database/creds/readonly/abc","renewable":true,"lease_duration":1800}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let renewal = client
        .sys()
        .renew_lease(
            &SecretString::from("database/creds/readonly/abc"),
            Some(1800),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(renewal.renewable);
    assert_eq!(renewal.lease_duration, 1800);
    let debug = format!("{renewal:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("database/creds/readonly/abc"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_lease_revoke_uses_non_prefix_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/leases/revoke HTTP/1.1"));
        assert!(request.contains(r#""lease_id":"database/creds/readonly/abc""#));
        assert!(!request.contains("/revoke-prefix/"));
        assert!(!request.contains("/revoke-force/"));
        let response = "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .sys()
        .revoke_lease(&SecretString::from("database/creds/readonly/abc"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_plugin_catalog_lists_all_plugins() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("GET /v1/sys/plugins/catalog HTTP/1.1"));
        let body = r#"{"data":{"auth":["ldap"],"database":["postgresql-database-plugin"],"secret":["transit"],"detailed":[{"builtin":true,"deprecation_status":"supported","name":"transit","type":"secret","version":"v2.5.4+builtin.openbao"}]}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let catalog = client
        .sys()
        .list_plugins()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(catalog.secret, ["transit"]);
    assert_eq!(catalog.detailed[0].name, "transit");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_plugin_catalog_entry_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 4096];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            if index == 0 {
                assert!(
                    request
                        .starts_with("POST /v1/sys/plugins/catalog/secret/example-plugin HTTP/1.1")
                );
                assert!(request.contains(r#""version":"v1.0.0""#));
                assert!(request.contains(
                    r#""sha256":"d130b9a0fbfddef9709d8ff92e5e6053ccd246b78632fc03b8548457026961e9""#
                ));
                assert!(request.contains(r#""command":"example-plugin""#));
                assert!(request.contains(r#""args":["--config=/secure/path"]"#));
                assert!(request.contains(r#""env":["TOKEN=secret"]"#));
                let response =
                    "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
                stream
                    .write_all(response.as_bytes())
                    .unwrap_or_else(|error| panic!("{error}"));
            } else if index == 1 {
                assert!(request.starts_with(
                    "GET /v1/sys/plugins/catalog/secret/example-plugin?version=v1.0.0 HTTP/1.1"
                ));
                let body = r#"{"data":{"args":["--config=/secure/path"],"builtin":false,"command":"example-plugin","env":["TOKEN=secret"],"name":"example-plugin","sha256":"d130b9a0fbfddef9709d8ff92e5e6053ccd246b78632fc03b8548457026961e9","version":"v1.0.0"}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .unwrap_or_else(|error| panic!("{error}"));
            } else {
                assert!(request.starts_with(
                    "DELETE /v1/sys/plugins/catalog/secret/example-plugin?version=v1.0.0 HTTP/1.1"
                ));
                let response =
                    "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
                stream
                    .write_all(response.as_bytes())
                    .unwrap_or_else(|error| panic!("{error}"));
            }
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .sys()
        .register_plugin(
            openbao::sys::PluginType::Secret,
            "example-plugin",
            &openbao::sys::PluginRegisterRequest {
                version: Some("v1.0.0".to_owned()),
                sha256: "d130b9a0fbfddef9709d8ff92e5e6053ccd246b78632fc03b8548457026961e9"
                    .to_owned(),
                command: "example-plugin".to_owned(),
                args: vec![SecretString::from("--config=/secure/path")],
                env: vec![SecretString::from("TOKEN=secret")],
                oci: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let info = client
        .sys()
        .read_plugin(
            openbao::sys::PluginType::Secret,
            "example-plugin",
            Some("v1.0.0"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(info.name, "example-plugin");
    assert_eq!(info.args[0].expose_secret(), "--config=/secure/path");
    let debug = format!("{info:?}");
    assert!(debug.contains("<1 redacted>"));
    assert!(!debug.contains("TOKEN=secret"));

    client
        .sys()
        .delete_plugin(
            openbao::sys::PluginType::Secret,
            "example-plugin",
            Some("v1.0.0"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_plugin_reload_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/sys/plugins/reload/backend HTTP/1.1"));
        assert!(request.contains(r#""plugin":"example-plugin""#));
        assert!(request.contains(r#""scope":"global""#));
        let response = "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .sys()
        .reload_plugin_backend(&openbao::sys::PluginReloadRequest {
            plugin: Some("example-plugin".to_owned()),
            mounts: Vec::new(),
            scope: Some("global".to_owned()),
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn transit_create_key_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/transit/keys/app-key HTTP/1.1"));
        assert!(request.contains(r#""type":"aes256-gcm96""#));
        assert!(request.contains(r#""derived":true"#));
        let response = "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .transit("transit")
        .unwrap_or_else(|error| panic!("{error}"))
        .create_key(
            "app-key",
            &openbao::secrets::transit::TransitCreateKeyRequest {
                key_type: Some(openbao::secrets::transit::TransitKeyType::Aes256Gcm96),
                derived: Some(true),
                ..openbao::secrets::transit::TransitCreateKeyRequest::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn transit_encrypt_and_decrypt_use_secret_payloads() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 4096];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = if index == 0 {
                assert!(request.starts_with("POST /v1/transit/encrypt/app-key HTTP/1.1"));
                assert!(request.contains(r#""plaintext":"c2VjcmV0""#));
                assert!(request.contains(r#""context":"YXBw""#));
                r#"{"data":{"ciphertext":"vault:v1:ciphertext","key_version":1}}"#
            } else {
                assert!(request.starts_with("POST /v1/transit/decrypt/app-key HTTP/1.1"));
                assert!(request.contains(r#""ciphertext":"vault:v1:ciphertext""#));
                r#"{"data":{"plaintext":"c2VjcmV0"}}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));
    let transit = client
        .transit("transit")
        .unwrap_or_else(|error| panic!("{error}"));

    let encrypted = transit
        .encrypt(
            "app-key",
            &openbao::secrets::transit::TransitEncryptRequest {
                plaintext: SecretString::from("c2VjcmV0"),
                associated_data: None,
                context: Some(SecretString::from("YXBw")),
                key_version: None,
                nonce: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(encrypted.ciphertext.expose_secret(), "vault:v1:ciphertext");

    let decrypted = transit
        .decrypt(
            "app-key",
            &openbao::secrets::transit::TransitDecryptRequest {
                ciphertext: encrypted.ciphertext,
                associated_data: None,
                context: Some(SecretString::from("YXBw")),
                nonce: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(decrypted.plaintext.expose_secret(), "c2VjcmV0");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn transit_crypto_helpers_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..4 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 4096];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match index {
                0 => {
                    assert!(request.starts_with("POST /v1/transit/hash/sha2-512 HTTP/1.1"));
                    assert!(request.contains(r#""input":"cGF5bG9hZA==""#));
                    r#"{"data":{"sum":"abc123"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/transit/hmac/app-key/sha2-512 HTTP/1.1"));
                    assert!(request.contains(r#""key_version":2"#));
                    r#"{"data":{"hmac":"vault:v1:hmac"}}"#
                }
                2 => {
                    assert!(
                        request.starts_with("POST /v1/transit/sign/signing-key/sha2-256 HTTP/1.1")
                    );
                    assert!(request.contains(r#""prehashed":true"#));
                    r#"{"data":{"signature":"vault:v1:signature"}}"#
                }
                _ => {
                    assert!(
                        request
                            .starts_with("POST /v1/transit/verify/signing-key/sha2-256 HTTP/1.1")
                    );
                    assert!(request.contains(r#""signature":"vault:v1:signature""#));
                    r#"{"data":{"valid":true}}"#
                }
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));
    let transit = client
        .transit("transit")
        .unwrap_or_else(|error| panic!("{error}"));

    let hash = transit
        .hash(
            openbao::secrets::transit::TransitHashAlgorithm::Sha2_512,
            &openbao::secrets::transit::TransitHashRequest {
                input: SecretString::from("cGF5bG9hZA=="),
                format: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(hash.sum.expose_secret(), "abc123");

    let hmac = transit
        .hmac(
            "app-key",
            Some(openbao::secrets::transit::TransitHashAlgorithm::Sha2_512),
            &openbao::secrets::transit::TransitHmacRequest {
                input: SecretString::from("cGF5bG9hZA=="),
                key_version: Some(2),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(hmac.hmac.expose_secret(), "vault:v1:hmac");

    let signature = transit
        .sign(
            "signing-key",
            Some(openbao::secrets::transit::TransitHashAlgorithm::Sha2_256),
            &openbao::secrets::transit::TransitSignRequest {
                input: SecretString::from("cGF5bG9hZA=="),
                key_version: None,
                context: None,
                prehashed: Some(true),
                signature_algorithm: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(signature.signature.expose_secret(), "vault:v1:signature");

    let verified = transit
        .verify(
            "signing-key",
            Some(openbao::secrets::transit::TransitHashAlgorithm::Sha2_256),
            &openbao::secrets::transit::TransitVerifyRequest {
                input: SecretString::from("cGF5bG9hZA=="),
                signature: Some(signature.signature),
                hmac: None,
                context: None,
                prehashed: None,
                signature_algorithm: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(verified.valid);

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn transit_datakey_random_and_rewrap_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 4096];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match index {
                0 => {
                    assert!(
                        request.starts_with("POST /v1/transit/datakey/wrapped/app-key HTTP/1.1")
                    );
                    assert!(request.contains(r#""bits":256"#));
                    r#"{"data":{"ciphertext":"vault:v1:datakey"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/transit/random/platform/32 HTTP/1.1"));
                    assert!(request.contains(r#""format":"base64""#));
                    r#"{"data":{"random_bytes":"cmFuZG9t"}}"#
                }
                _ => {
                    assert!(request.starts_with("POST /v1/transit/rewrap/app-key HTTP/1.1"));
                    assert!(request.contains(r#""ciphertext":"vault:v1:old""#));
                    r#"{"data":{"ciphertext":"vault:v2:new"}}"#
                }
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));
    let transit = client
        .transit("transit")
        .unwrap_or_else(|error| panic!("{error}"));

    let data_key = transit
        .data_key(
            "app-key",
            openbao::secrets::transit::TransitDataKeyType::Wrapped,
            &openbao::secrets::transit::TransitDataKeyRequest {
                bits: Some(256),
                ..openbao::secrets::transit::TransitDataKeyRequest::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(data_key.ciphertext.expose_secret(), "vault:v1:datakey");

    let random = transit
        .random_from_source(
            openbao::secrets::transit::TransitRandomSource::Platform,
            Some(32),
            &openbao::secrets::transit::TransitRandomRequest {
                format: Some(openbao::secrets::transit::TransitOutputFormat::Base64),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(random.random_bytes.expose_secret(), "cmFuZG9t");

    let rewrapped = transit
        .rewrap(
            "app-key",
            &openbao::secrets::transit::TransitRewrapRequest {
                ciphertext: SecretString::from("vault:v1:old"),
                context: None,
                key_version: None,
                nonce: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(rewrapped.ciphertext.expose_secret(), "vault:v2:new");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn redirects_are_not_followed_with_token_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let _bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let response = concat!(
            "HTTP/1.1 302 Found\r\n",
            "location: https://example.invalid/steal-token\r\n",
            "content-length: 0\r\n",
            "\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let error = match client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read::<SecretData>("app/config")
        .await
    {
        Ok(_) => panic!("redirect response unexpectedly succeeded"),
        Err(error) => error,
    };
    match error {
        Error::Api { status, .. } => assert_eq!(status, reqwest::StatusCode::FOUND),
        unexpected => panic!("unexpected error: {unexpected}"),
    }

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn response_content_length_is_bounded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let _bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "content-type: application/json\r\n",
            "content-length: 33554433\r\n",
            "\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let error = match client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read::<SecretData>("app/config")
        .await
    {
        Ok(_) => panic!("oversized response unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Decode(_)));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn response_content_length_uses_client_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let _bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "content-type: application/json\r\n",
            "content-length: 2048\r\n",
            "\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .and_then(|config| config.max_response_bytes(1024))
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let error = match client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read::<SecretData>("app/config")
        .await
    {
        Ok(_) => panic!("client-limited response unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Decode(_)));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn decode_errors_do_not_echo_secret_response_values() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let _bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let body = r#"{"data":{"data":{"value":"SECRET-RESPONSE-FRAGMENT"},"metadata":{"created_time":"2026-05-27T00:00:00Z","deletion_time":"","destroyed":false,"version":1}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let error = match client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read::<NumericSecretData>("app/config")
        .await
    {
        Ok(_) => panic!("schema-mismatched response unexpectedly succeeded"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(message.contains("did not match expected schema"));
    assert!(!message.contains("SECRET-RESPONSE-FRAGMENT"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn non_json_content_type_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let _bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let body = r#"{"data":{"data":{"value":"ok"},"metadata":{"created_time":"2026-05-27T00:00:00Z","deletion_time":"","destroyed":false,"version":1}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let error = match client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read::<SecretData>("app/config")
        .await
    {
        Ok(_) => panic!("non-json content type unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Decode(_)));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn missing_json_content_type_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let _bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let body = r#"{"data":{"data":{"value":"ok"},"metadata":{"created_time":"2026-05-27T00:00:00Z","deletion_time":"","destroyed":false,"version":1}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let error = match client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read::<SecretData>("app/config")
        .await
    {
        Ok(_) => panic!("missing content type unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::Decode(_)));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn dev_bootstrap_initializes_unseals_and_returns_root_client() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..4 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);

            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/init HTTP/1.1"));
                    r#"{"initialized":false}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/init HTTP/1.1"));
                    assert!(request.contains(r#""secret_shares":1"#));
                    assert!(request.contains(r#""secret_threshold":1"#));
                    r#"{"keys":["unseal-key"],"keys_base64":["dW5zZWFsLWtleQ=="],"root_token":"root-token"}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/sys/unseal HTTP/1.1"));
                    assert!(request.contains(r#""key":"unseal-key""#));
                    r#"{"sealed":false,"n":1,"t":1,"progress":0,"version":"2.5.4"}"#
                }
                3 => {
                    assert!(request.starts_with("GET /v1/sys/health HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    r#"{"initialized":true,"sealed":false,"standby":false,"version":"2.5.4"}"#
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let bootstrap = client
        .sys()
        .bootstrap_dev(&DevBootstrapOptions::default())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(bootstrap.root_token.expose_secret(), "root-token");
    assert_eq!(bootstrap.unseal_keys.len(), 1);
    assert!(!bootstrap.unseal_status.sealed);

    let health = bootstrap
        .client
        .sys()
        .health()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(health.initialized);
    assert!(!health.sealed);

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn dev_bootstrap_refuses_non_loopback_targets_before_http() {
    let client = Client::new("https://example.com").unwrap_or_else(|error| panic!("{error}"));
    let error = match client
        .sys()
        .bootstrap_dev(&DevBootstrapOptions::default())
        .await
    {
        Ok(_) => panic!("non-loopback dev bootstrap unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(error, Error::InvalidBaseUrl(_)));
}

#[tokio::test]
async fn kubernetes_login_sends_documented_path_and_secret_jwt() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/auth/kubernetes/login HTTP/1.1"));
        assert!(request.contains(r#""role":"web""#));
        assert!(request.contains(r#""jwt":"service-account-jwt""#));
        let body = r#"{"auth":{"client_token":"k8s-token","accessor":"k8s-accessor","policies":["default"],"metadata":{"role":"web"},"lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let (client, login) = client
        .login_kubernetes("web", SecretString::from("service-account-jwt"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(login.accessor.expose_secret(), "k8s-accessor");
    assert_eq!(client.base_url().as_str(), format!("http://{addr}/"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn kubernetes_admin_config_and_role_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..3 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 4096];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/auth/kubernetes/config HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""token_reviewer_jwt":"reviewer-jwt""#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("POST /v1/auth/kubernetes/role/web HTTP/1.1"));
                    assert!(request.contains(r#""bound_service_account_names":["web"]"#));
                    assert!(request.contains(r#""bound_service_account_namespaces":["prod"]"#));
                    "{}"
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/auth/kubernetes/role HTTP/1.1"));
                    r#"{"data":{"keys":["web"]}}"#
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let admin = client
        .kubernetes_admin()
        .unwrap_or_else(|error| panic!("{error}"));

    admin
        .configure(&openbao::auth::kubernetes::KubernetesConfig {
            kubernetes_host: Some("https://kubernetes.default.svc".to_owned()),
            token_reviewer_jwt: Some(SecretString::from("reviewer-jwt")),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .write_role(
            "web",
            &openbao::auth::kubernetes::KubernetesRole {
                bound_service_account_names: vec!["web".to_owned()],
                bound_service_account_namespaces: vec!["prod".to_owned()],
                policies: vec!["web".to_owned()],
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let roles = admin
        .list_roles()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["web"]);

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn userpass_login_sends_documented_path_and_secret_password() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/auth/userpass/login/alice HTTP/1.1"));
        assert!(request.contains(r#""password":"p-value""#));
        let body = r#"{"auth":{"client_token":"userpass-token","accessor":"userpass-accessor","policies":["default"],"metadata":{"username":"alice"},"lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let (client, login) = client
        .login_userpass("alice", SecretString::from("p-value"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(login.accessor.expose_secret(), "userpass-accessor");
    assert_eq!(
        login.metadata.get("username").map(String::as_str),
        Some("alice")
    );
    assert_eq!(client.base_url().as_str(), format!("http://{addr}/"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn userpass_admin_user_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..6 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 4096];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/auth/userpass/users/alice HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""password":"p-value""#));
                    assert!(request.contains(r#""token_policies":["web"]"#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("GET /v1/auth/userpass/users/alice HTTP/1.1"));
                    r#"{"data":{"token_policies":["web"],"token_ttl":3600,"token_type":"default"}}"#
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/auth/userpass/users HTTP/1.1"));
                    r#"{"data":{"keys":["alice"]}}"#
                }
                3 => {
                    assert!(
                        request.starts_with("POST /v1/auth/userpass/users/alice/password HTTP/1.1")
                    );
                    assert!(request.contains(r#""password":"new-p-value""#));
                    "{}"
                }
                4 => {
                    assert!(
                        request.starts_with("POST /v1/auth/userpass/users/alice/policies HTTP/1.1")
                    );
                    assert!(request.contains(r#""token_policies":["ops"]"#));
                    "{}"
                }
                5 => {
                    assert!(request.starts_with("DELETE /v1/auth/userpass/users/alice HTTP/1.1"));
                    "{}"
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let admin = client
        .userpass_admin()
        .unwrap_or_else(|error| panic!("{error}"));

    admin
        .write_user(
            "alice",
            &openbao::auth::userpass::UserpassUserRequest::new(SecretString::from("p-value"))
                .with_policy("web"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let user = admin
        .read_user("alice")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(user.token_policies, ["web"]);
    let users = admin
        .list_users()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(users.keys, ["alice"]);
    admin
        .update_password("alice", &SecretString::from("new-p-value"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .update_policies("alice", &["ops".to_owned()])
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_user("alice")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn cert_login_sends_documented_path_and_role_name() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        let request = String::from_utf8_lossy(&buffer[..bytes]);
        assert!(request.starts_with("POST /v1/auth/cert/login HTTP/1.1"));
        assert!(request.contains(r#""name":"web-ca""#));
        let body = r#"{"auth":{"client_token":"cert-token","accessor":"cert-accessor","policies":["web"],"lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let (client, login) = client
        .login_cert(Some("web-ca"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        login.accessor.as_ref().map(SecretString::expose_secret),
        Some("cert-accessor")
    );
    assert_eq!(client.base_url().as_str(), format!("http://{addr}/"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn cert_admin_roles_config_and_crls_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..5 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/auth/cert/config HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""disable_binding":true"#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("POST /v1/auth/cert/certs/web-ca HTTP/1.1"));
                    assert!(request.contains(r#""certificate":"-----BEGIN CERTIFICATE-----"#));
                    assert!(request.contains(r#""allowed_dns_sans":["web.example.com"]"#));
                    "{}"
                }
                2 => {
                    assert!(
                        request.starts_with("LIST /v1/auth/cert/certs?after=old&limit=10 HTTP/1.1")
                    );
                    r#"{"data":{"keys":["web-ca"]}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/auth/cert/crls/web-crl HTTP/1.1"));
                    assert!(request.contains(r#""url":"https://example.com/web.crl""#));
                    "{}"
                }
                4 => {
                    assert!(request.starts_with("LIST /v1/auth/cert/crls HTTP/1.1"));
                    r#"{"data":{"keys":["web-crl"]}}"#
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let admin = client
        .cert_admin()
        .unwrap_or_else(|error| panic!("{error}"));

    admin
        .configure(&openbao::auth::cert::CertAuthConfig {
            disable_binding: Some(true),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .write_role(
            "web-ca",
            &openbao::auth::cert::CertRole {
                certificate: "-----BEGIN CERTIFICATE-----".to_owned(),
                allowed_dns_sans: vec!["web.example.com".to_owned()],
                token_policies: vec!["web".to_owned()],
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let roles = admin
        .list_roles(Some("old"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["web-ca"]);
    admin
        .write_crl(
            "web-crl",
            &openbao::auth::cert::CertCrl {
                url: "https://example.com/web.crl".to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let crls = admin
        .list_crls(None, None)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(crls.keys, ["web-crl"]);

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_role_urls_issue_sign_revoke_and_cert_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..8 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/pki/config/urls HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(
                        r#""issuing_certificates":["https://issuer.example/v1/pki/ca"]"#
                    ));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("POST /v1/pki/roles/web HTTP/1.1"));
                    assert!(request.contains(r#""allowed_domains":["example.com"]"#));
                    "{}"
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/pki/roles HTTP/1.1"));
                    r#"{"data":{"keys":["web"]}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/pki/issue/web HTTP/1.1"));
                    assert!(request.contains(r#""common_name":"api.example.com""#));
                    r#"{"data":{"certificate":"issued-cert","issuing_ca":"ca","ca_chain":["ca"],"private_key":"private-key","private_key_type":"rsa","serial_number":"01:02","expiration":1893456000}}"#
                }
                4 => {
                    assert!(request.starts_with("POST /v1/pki/sign/web HTTP/1.1"));
                    assert!(request.contains(r#""csr":"-----BEGIN CERTIFICATE REQUEST-----""#));
                    r#"{"data":{"certificate":"signed-cert","serial_number":"01:03"}}"#
                }
                5 => {
                    assert!(request.starts_with("POST /v1/pki/revoke HTTP/1.1"));
                    assert!(request.contains(r#""serial_number":"01:02""#));
                    r#"{"data":{"revocation_time":1893456001}}"#
                }
                6 => {
                    assert!(request.starts_with("LIST /v1/pki/certs HTTP/1.1"));
                    r#"{"data":{"keys":["01:02"]}}"#
                }
                7 => {
                    assert!(request.starts_with("GET /v1/pki/cert/01:02 HTTP/1.1"));
                    r#"{"data":{"certificate":"issued-cert"}}"#
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    pki.write_urls(&openbao::secrets::pki::PkiUrlsConfig {
        issuing_certificates: vec!["https://issuer.example/v1/pki/ca".to_owned()],
        ..Default::default()
    })
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    pki.write_role(
        "web",
        &openbao::secrets::pki::PkiRole {
            allowed_domains: vec!["example.com".to_owned()],
            allow_subdomains: Some(true),
            key_type: Some("rsa".to_owned()),
            key_bits: Some(3072),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let roles = pki
        .list_roles()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["web"]);

    let issued = pki
        .issue(
            "web",
            &openbao::secrets::pki::PkiIssueRequest {
                common_name: "api.example.com".to_owned(),
                ttl: Some("24h".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issued.certificate, "issued-cert");
    assert_eq!(
        issued.private_key.as_ref().map(SecretString::expose_secret),
        Some("private-key")
    );

    let signed = pki
        .sign(
            "web",
            &openbao::secrets::pki::PkiSignRequest {
                csr: "-----BEGIN CERTIFICATE REQUEST-----".to_owned(),
                common_name: Some("api.example.com".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(signed.serial_number.as_deref(), Some("01:03"));

    let revocation = pki
        .revoke(&openbao::secrets::pki::PkiRevokeRequest {
            serial_number: "01:02".to_owned(),
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(revocation.revocation_time, Some(1893456001));

    let certs = pki
        .list_certificates()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(certs.keys, ["01:02"]);
    let certificate = pki
        .read_certificate("01:02")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(certificate.certificate, "issued-cert");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_authority_crl_and_tidy_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..7 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/pki/root/generate/internal HTTP/1.1"));
                    assert!(request.contains(r#""common_name":"root.example.com""#));
                    r#"{"data":{"certificate":"root-cert","serial_number":"10:01","expiration":1893456000}}"#
                }
                1 => {
                    assert!(
                        request.starts_with("POST /v1/pki/intermediate/generate/exported HTTP/1.1")
                    );
                    assert!(request.contains(r#""common_name":"issuer.example.com""#));
                    r#"{"data":{"csr":"intermediate-csr","private_key":"intermediate-key","private_key_type":"rsa"}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/pki/root/sign-intermediate HTTP/1.1"));
                    assert!(request.contains(r#""csr":"intermediate-csr""#));
                    r#"{"data":{"certificate":"signed-intermediate","serial_number":"10:02"}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/pki/intermediate/set-signed HTTP/1.1"));
                    assert!(request.contains(r#""certificate":"signed-intermediate""#));
                    "{}"
                }
                4 => {
                    assert!(request.starts_with("POST /v1/pki/config/crl HTTP/1.1"));
                    assert!(request.contains(r#""expiry":"72h""#));
                    "{}"
                }
                5 => {
                    assert!(request.starts_with("POST /v1/pki/crl/rotate HTTP/1.1"));
                    r#"{"data":{"success":true}}"#
                }
                6 => {
                    assert!(request.starts_with("POST /v1/pki/tidy HTTP/1.1"));
                    assert!(request.contains(r#""tidy_cert_store":true"#));
                    "{}"
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let root = pki
        .generate_root(
            openbao::secrets::pki::PkiKeyGenerationType::Internal,
            &openbao::secrets::pki::PkiGenerateRootRequest {
                common_name: "root.example.com".to_owned(),
                key_type: Some("rsa".to_owned()),
                key_bits: Some(4096),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(root.certificate.as_deref(), Some("root-cert"));

    let intermediate = pki
        .generate_intermediate(
            openbao::secrets::pki::PkiKeyGenerationType::Exported,
            &openbao::secrets::pki::PkiGenerateIntermediateRequest {
                common_name: "issuer.example.com".to_owned(),
                key_type: Some("rsa".to_owned()),
                key_bits: Some(3072),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(intermediate.csr.as_deref(), Some("intermediate-csr"));
    assert_eq!(
        intermediate
            .private_key
            .as_ref()
            .map(SecretString::expose_secret),
        Some("intermediate-key")
    );

    let signed = pki
        .sign_intermediate(&openbao::secrets::pki::PkiSignIntermediateRequest {
            csr: "intermediate-csr".to_owned(),
            common_name: Some("issuer.example.com".to_owned()),
            permitted_dns_domains: vec!["example.com".to_owned()],
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(signed.certificate, "signed-intermediate");

    pki.set_signed_intermediate(&openbao::secrets::pki::PkiSetSignedIntermediateRequest {
        certificate: "signed-intermediate".to_owned(),
    })
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    pki.write_crl_config(&openbao::secrets::pki::PkiCrlConfig {
        expiry: Some("72h".to_owned()),
        auto_rebuild: Some(true),
        ..Default::default()
    })
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let rotation = pki
        .rotate_crl()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(rotation.success);
    pki.tidy(&openbao::secrets::pki::PkiTidyRequest {
        tidy_cert_store: Some(true),
        tidy_revoked_certs: Some(true),
        safety_buffer: Some("72h".to_owned()),
        ..Default::default()
    })
    .await
    .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_issuer_and_key_lifecycle_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..6 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("LIST /v1/pki/issuers HTTP/1.1"));
                    r#"{"data":{"keys":["issuer-1"]}}"#
                }
                1 => {
                    assert!(request.starts_with("GET /v1/pki/issuer/issuer-1 HTTP/1.1"));
                    r#"{"data":{"issuer_id":"issuer-1","issuer_name":"root-x1","key_id":"key-1","key_name":"root-key","certificate":"root-cert","ca_chain":["root-cert"],"manual_chain":["self"],"crl_distribution_points":["https://issuer.example/crl"],"issuing_certificates":["https://issuer.example/ca"],"ocsp_servers":["https://issuer.example/ocsp"],"usage":["issuing-certificates","crl-signing"],"leaf_not_after_behavior":"err"}}"#
                }
                2 => {
                    assert!(request.starts_with("DELETE /v1/pki/issuer/issuer-1 HTTP/1.1"));
                    "{}"
                }
                3 => {
                    assert!(request.starts_with("LIST /v1/pki/keys HTTP/1.1"));
                    r#"{"data":{"keys":["key-1"]}}"#
                }
                4 => {
                    assert!(request.starts_with("GET /v1/pki/key/key-1 HTTP/1.1"));
                    r#"{"data":{"key_id":"key-1","key_name":"root-key","key_type":"rsa","key_bits":4096}}"#
                }
                5 => {
                    assert!(request.starts_with("DELETE /v1/pki/key/key-1 HTTP/1.1"));
                    "{}"
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let issuers = pki
        .list_issuers()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuers.keys, ["issuer-1"]);
    let issuer = pki
        .read_issuer("issuer-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer.issuer_name.as_deref(), Some("root-x1"));
    assert_eq!(issuer.usage, ["issuing-certificates", "crl-signing"]);
    pki.delete_issuer("issuer-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let keys = pki
        .list_keys()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(keys.keys, ["key-1"]);
    let key = pki
        .read_key("key-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(key.key_type.as_deref(), Some("rsa"));
    assert_eq!(key.key_bits, Some(4096));
    pki.delete_key("key-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_acme_config_and_eab_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..8 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/pki/config/acme HTTP/1.1"));
                    r#"{"data":{"allowed_issuers":["*"],"allowed_roles":["web"],"default_directory_policy":"role:web","dns_resolver":"8.8.8.8:53","eab_policy":"always-required","enabled":true}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/pki/config/acme HTTP/1.1"));
                    assert!(request.contains(r#""allowed_roles":["web"]"#));
                    assert!(request.contains(r#""eab_policy":"always-required""#));
                    r#"{"data":{"allowed_issuers":["*"],"allowed_roles":["web"],"default_directory_policy":"role:web","eab_policy":"always-required","enabled":true}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/pki/acme/new-eab HTTP/1.1"));
                    r#"{"data":{"created_on":"2026-05-29T00:00:00Z","id":"eab-default","key_type":"hs","acme_directory":"acme/directory","key":"default-secret"}}"#
                }
                3 => {
                    assert!(
                        request.starts_with("POST /v1/pki/issuer/issuer-1/acme/new-eab HTTP/1.1")
                    );
                    r#"{"data":{"id":"eab-issuer","key_type":"hs","acme_directory":"issuer/issuer-1/acme/directory","key":"issuer-secret"}}"#
                }
                4 => {
                    assert!(request.starts_with("POST /v1/pki/roles/web/acme/new-eab HTTP/1.1"));
                    r#"{"data":{"id":"eab-role","key_type":"hs","acme_directory":"roles/web/acme/directory","key":"role-secret"}}"#
                }
                5 => {
                    assert!(request.starts_with(
                        "POST /v1/pki/issuer/issuer-1/roles/web/acme/new-eab HTTP/1.1"
                    ));
                    r#"{"data":{"id":"eab-issuer-role","key_type":"hs","acme_directory":"issuer/issuer-1/roles/web/acme/directory","key":"issuer-role-secret"}}"#
                }
                6 => {
                    assert!(request.starts_with("LIST /v1/pki/eab HTTP/1.1"));
                    r#"{"data":{"keys":["eab-default"],"key_info":{"eab-default":{"created_on":"2026-05-29T00:00:00Z","key_type":"hs","acme_directory":"acme/directory"}}}}"#
                }
                7 => {
                    assert!(request.starts_with("DELETE /v1/pki/eab/eab-default HTTP/1.1"));
                    "{}"
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let config = pki
        .read_acme_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(config.allowed_roles, ["web"]);
    assert_eq!(config.eab_policy.as_deref(), Some("always-required"));

    let updated = pki
        .write_acme_config(&openbao::secrets::pki::PkiAcmeConfig {
            allowed_issuers: vec!["*".to_owned()],
            allowed_roles: vec!["web".to_owned()],
            default_directory_policy: Some("role:web".to_owned()),
            eab_policy: Some("always-required".to_owned()),
            enabled: Some(true),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(updated.enabled, Some(true));

    let default_eab = pki
        .generate_acme_eab()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(default_eab.key.expose_secret(), "default-secret");
    let issuer_eab = pki
        .generate_issuer_acme_eab("issuer-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer_eab.id, "eab-issuer");
    let role_eab = pki
        .generate_role_acme_eab("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(role_eab.id, "eab-role");
    let issuer_role_eab = pki
        .generate_issuer_role_acme_eab("issuer-1", "web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer_role_eab.id, "eab-issuer-role");

    let eab_tokens = pki
        .list_acme_eab_tokens()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(eab_tokens.keys, ["eab-default"]);
    assert_eq!(
        eab_tokens
            .key_info
            .get("eab-default")
            .and_then(|info| info.key_type.as_deref()),
        Some("hs")
    );
    pki.delete_acme_eab_token("eab-default")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_issuer_patch_revoke_and_import_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..7 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("PATCH /v1/pki/issuer/issuer-1 HTTP/1.1"));
                    assert!(request.contains("content-type: application/merge-patch+json"));
                    assert!(request.contains(r#""issuer_name":"root-x2""#));
                    r#"{"data":{"issuer_id":"issuer-1","issuer_name":"root-x2","key_id":"key-1","usage":"issuing-certificates,crl-signing"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/pki/issuer/issuer-1/revoke HTTP/1.1"));
                    r#"{"data":{"issuer_id":"issuer-1","issuer_name":"root-x2","key_id":"key-1","revocation_time":1893456002}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/pki/config/ca HTTP/1.1"));
                    assert!(request.contains(r#""pem_bundle":"-----BEGIN PRIVATE KEY-----"#));
                    r#"{"data":{"imported_issuers":["issuer-2"],"imported_keys":["key-2"],"existing_issuers":[],"existing_keys":[],"mapping":{"issuer-2":"key-2"}}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/pki/issuers/import/bundle HTTP/1.1"));
                    assert!(request.contains(r#""pem_bundle":"-----BEGIN PRIVATE KEY-----"#));
                    r#"{"data":{"imported_issuers":["issuer-3"],"imported_keys":["key-3"],"existing_issuers":[],"existing_keys":[],"mapping":{"issuer-3":"key-3"}}}"#
                }
                4 => {
                    assert!(request.starts_with("POST /v1/pki/issuers/import/cert HTTP/1.1"));
                    assert!(request.contains(r#""pem_bundle":"-----BEGIN CERTIFICATE-----"#));
                    r#"{"data":{"imported_issuers":["issuer-4"],"imported_keys":[],"existing_issuers":[],"existing_keys":[],"mapping":{}}}"#
                }
                5 => {
                    assert!(request.starts_with("POST /v1/pki/keys/import HTTP/1.1"));
                    assert!(request.contains(r#""key_name":"imported-key""#));
                    assert!(request.contains(r#""pem_bundle":"-----BEGIN PRIVATE KEY-----"#));
                    r#"{"data":{"key_id":"key-5","key_name":"imported-key","key_type":"rsa","key_bits":4096}}"#
                }
                6 => {
                    assert!(request.starts_with("POST /v1/pki/key/key-5 HTTP/1.1"));
                    assert!(request.contains(r#""key_name":"renamed-key""#));
                    r#"{"data":{"key_id":"key-5","key_name":"renamed-key","key_type":"rsa","key_bits":4096}}"#
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(OpenBaoConfig::allow_localhost_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let issuer = pki
        .patch_issuer(
            "issuer-1",
            &openbao::secrets::pki::PkiIssuerPatch {
                issuer_name: Some("root-x2".to_owned()),
                usage: Some(vec![
                    "issuing-certificates".to_owned(),
                    "crl-signing".to_owned(),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer.issuer_name.as_deref(), Some("root-x2"));

    let revoked = pki
        .revoke_issuer("issuer-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(revoked.revocation_time, Some(1893456002));

    let private_bundle =
        SecretString::from("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----");
    let legacy_import = pki
        .import_ca_bundle(&private_bundle)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        legacy_import.mapping.get("issuer-2").map(String::as_str),
        Some("key-2")
    );
    let bundle_import = pki
        .import_issuer_bundle(&private_bundle)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(bundle_import.imported_keys, ["key-3"]);
    let cert_import = pki
        .import_issuer_certificates("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(cert_import.imported_issuers, ["issuer-4"]);

    let imported_key = pki
        .import_key(&private_bundle, Some("imported-key"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(imported_key.key_name.as_deref(), Some("imported-key"));
    let renamed = pki
        .rename_key("key-5", "renamed-key")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(renamed.key_name.as_deref(), Some("renamed-key"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}
