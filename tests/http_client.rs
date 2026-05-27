//! HTTP behavior tests for the OpenBao client.

#![allow(clippy::panic)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use openbao::{Client, Error, OpenBaoConfig};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct SecretData {
    value: String,
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

    let mut options = std::collections::BTreeMap::new();
    options.insert("version".to_owned(), "2".to_owned());
    let request = openbao::sys::MountEnableRequest {
        backend_type: "kv".to_owned(),
        description: None,
        config: None,
        options,
        local: None,
        seal_wrap: None,
        external_entropy_access: None,
    };
    client
        .sys()
        .enable_mount("secret", &request)
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
