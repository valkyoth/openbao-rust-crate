//! HTTP behavior tests for the OpenBao client.

#![allow(clippy::panic)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

use openbao::{Client, Error, OpenBaoConfig};
use secrecy::SecretString;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SecretData {
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
        .delete_latest("app/config")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

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

    let error = match client.kv2("secret").read::<SecretData>("app/config").await {
        Ok(_) => panic!("redirect response unexpectedly succeeded"),
        Err(error) => error,
    };
    match error {
        Error::Api { status, .. } => assert_eq!(status, reqwest::StatusCode::FOUND),
        unexpected => panic!("unexpected error: {unexpected}"),
    }

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}
