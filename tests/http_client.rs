//! HTTP behavior tests for the OpenBao client.

#![cfg(feature = "sensitive-http-test-only")]
#![allow(clippy::panic)]
#![allow(deprecated)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};
#[cfg(feature = "operator-ops")]
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use openbao::{
    Authenticated, Client, Error, Method, OpenBaoConfig, ResponseEnvelope, RetryPolicy,
    RetryableMethod, Unauthenticated, sys::DevBootstrapOptions,
};
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

fn allow_mock_http(config: OpenBaoConfig) -> openbao::Result<OpenBaoConfig> {
    config.allow_sensitive_local_http_for_tests()
}

fn test_secret(parts: &[&str]) -> SecretString {
    SecretString::from(parts.concat())
}

trait TestTokenExt {
    fn with_token(self, token: SecretString) -> Client<Authenticated>;
}

impl TestTokenExt for Client<Unauthenticated> {
    fn with_token(self, token: SecretString) -> Client<Authenticated> {
        self.try_with_token(token)
            .unwrap_or_else(|error| panic!("{error}"))
    }
}

fn read_http_request(stream: &mut impl Read) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let bytes = stream
            .read(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        if bytes == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..bytes]);
        if http_request_is_complete(&request) {
            break;
        }
    }
    String::from_utf8(request).unwrap_or_else(|error| {
        let bytes = error.into_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

fn http_request_is_complete(request: &[u8]) -> bool {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    request.len() >= body_start + content_length
}

#[cfg(feature = "operator-ops")]
fn test_operation_id() -> String {
    static NEXT_TEST_OPERATION_ID: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT_TEST_OPERATION_ID.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{timestamp:x}{sequence:x}")
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["test-", "token"]));

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
async fn transport_errors_do_not_display_request_url() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/secret/data/app/config HTTP/1.1"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let result = client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .read::<SecretData>("app/config")
        .await;
    let error = match result {
        Ok(_) => panic!("server unexpectedly returned a response"),
        Err(error) => error,
    };

    server.join().unwrap_or_else(|error| panic!("{error:?}"));

    assert!(matches!(error, Error::Transport(_)));
    let message = error.to_string();
    assert!(!message.contains(&addr.to_string()));
    assert!(!message.contains("/v1/secret/data/app/config"));
}

#[tokio::test]
async fn wait_until_unsealed_uses_seal_status_until_ready() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for sealed in [true, false] {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /v1/sys/seal-status HTTP/1.1"));
            let body = format!(
                r#"{{"type":"shamir","initialized":true,"sealed":{sealed},"n":1,"t":1,"progress":0,"version":"2.5.5"}}"#
            );
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let status = client
        .sys()
        .wait_until_unsealed_with_delay(
            Duration::from_secs(1),
            Duration::from_millis(1),
            |_| async {},
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert!(status.initialized);
    assert!(!status.sealed);
    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn wrapping_context_requests_wrap_ttl_and_typed_unwrap() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..2 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/secret/custom HTTP/1.1"));
                    assert!(request.contains("x-vault-token: test-token"));
                    assert!(request.contains("x-vault-wrap-ttl: 5m"));
                    assert!(request.contains(r#""value":"wrap-me""#));
                    r#"{"data":null,"wrap_info":{"token":"wrap-token","accessor":"wrap-accessor","ttl":300,"creation_time":"2026-06-04T00:00:00Z","creation_path":"secret/custom"}}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/wrapping/unwrap HTTP/1.1"));
                    assert!(request.contains("x-vault-token: test-token"));
                    assert!(request.contains(r#""token":"wrap-token""#));
                    r#"{"data":{"value":"ok"},"lease_duration":0,"renewable":false}"#.to_owned()
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let wrapped = client
        .wrapping("5m")
        .unwrap_or_else(|error| panic!("{error}"))
        .request_json::<ResponseEnvelope<SecretData>, _>(
            Method::POST,
            "secret/custom",
            Some(&WrappedData {
                value: "wrap-me".to_owned(),
            }),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(wrapped.ttl(), 300);
    assert_eq!(wrapped.token().expose_secret(), "wrap-token");
    let debug = format!("{wrapped:?}");
    assert!(!debug.contains("wrap-token"));
    assert!(!debug.contains("wrap-accessor"));

    let envelope = wrapped
        .unwrap()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(envelope.data.value, "ok");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn explicit_retry_policy_retries_temporary_api_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for (index, status) in ["503 Service Unavailable", "429 Too Many Requests", "200 OK"]
            .into_iter()
            .enumerate()
        {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /v1/sys/health HTTP/1.1"));
            let body = if index == 2 {
                r#"{"initialized":true,"sealed":false,"standby":false,"version":"2.5.5"}"#
            } else {
                r#"{"errors":["temporary"]}"#
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));
    let policy = RetryPolicy::exponential(3, Duration::from_millis(5), Duration::from_millis(20))
        .unwrap_or_else(|error| panic!("{error}"))
        .without_jitter();
    let mut delays = Vec::new();

    let health: openbao::sys::Health = client
        .request_json_with_retry(
            RetryableMethod::Get,
            "sys/health",
            Option::<&openbao::Empty>::None,
            policy,
            |delay| {
                delays.push(delay);
                async {}
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert!(health.initialized);
    assert!(!health.sealed);
    assert_eq!(
        delays,
        vec![Duration::from_millis(5), Duration::from_millis(10)]
    );
    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn explicit_retry_policy_does_not_retry_non_temporary_api_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/sys/health HTTP/1.1"));
        let body = r#"{"errors":["permission denied"]}"#;
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));
    let policy = RetryPolicy::exponential(3, Duration::from_millis(5), Duration::from_millis(20))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut delay_count = 0;

    let error = match client
        .request_json_with_retry::<openbao::sys::Health, openbao::Empty, _, _>(
            RetryableMethod::Get,
            "sys/health",
            None,
            policy,
            |_delay| {
                delay_count += 1;
                async {}
            },
        )
        .await
    {
        Ok(_) => panic!("forbidden response unexpectedly succeeded"),
        Err(error) => error,
    };

    assert!(error.is_forbidden());
    assert_eq!(delay_count, 0);
    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[test]
fn retry_policy_validates_bounds() {
    assert!(
        RetryPolicy::exponential(0, Duration::from_millis(1), Duration::from_millis(1)).is_err()
    );
    assert!(
        RetryPolicy::exponential(9, Duration::from_millis(1), Duration::from_millis(1)).is_err()
    );
    assert!(RetryPolicy::exponential(2, Duration::ZERO, Duration::from_millis(1)).is_err());
    assert!(
        RetryPolicy::exponential(2, Duration::from_millis(2), Duration::from_millis(1)).is_err()
    );
    let policy = RetryPolicy::exponential(2, Duration::from_millis(1), Duration::from_millis(2))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(policy.max_attempts(), 2);
    assert_eq!(policy.initial_delay(), Duration::from_millis(1));
    assert_eq!(policy.max_delay(), Duration::from_millis(2));
    assert_eq!(policy.jitter_percent(), 20);
    assert_eq!(policy.without_jitter().jitter_percent(), 0);
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
            "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
async fn raw_byte_request_sends_custom_protocol_headers() {
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
        assert!(request.starts_with("POST /v1/pki/ocsp HTTP/1.1"));
        assert!(request.contains("accept: application/ocsp-response"));
        assert!(request.contains("content-type: application/ocsp-request"));
        assert!(request.ends_with("ocsp-request-der"));

        let body = "ocsp-response-der";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/ocsp-response\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let response = client
        .request_bytes_headers_accepting(
            openbao::Method::POST,
            "pki/ocsp",
            &[],
            &[
                (
                    openbao::reqwest::header::ACCEPT,
                    openbao::reqwest::header::HeaderValue::from_static("application/ocsp-response"),
                ),
                (
                    openbao::reqwest::header::CONTENT_TYPE,
                    openbao::reqwest::header::HeaderValue::from_static("application/ocsp-request"),
                ),
            ],
            Some(b"ocsp-request-der"),
            &[openbao::StatusCode::OK],
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    response.with_secret(|bytes| assert_eq!(bytes, b"ocsp-response-der"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn raw_byte_request_rejects_unexpected_content_type_when_accept_is_set() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/sys/storage/raft/snapshot HTTP/1.1"));
        assert!(request.contains("accept: application/octet-stream"));

        let body = "<html>not a snapshot</html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let error = match client
        .request_bytes_accepting(
            openbao::Method::GET,
            "sys/storage/raft/snapshot",
            &[],
            Some(openbao::reqwest::header::HeaderValue::from_static(
                "application/octet-stream",
            )),
            None,
            &[openbao::StatusCode::OK],
        )
        .await
    {
        Ok(_) => panic!("wrong binary content type unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unexpected content-type"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn cubbyhole_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..5 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 4096];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let (status, body) = match index {
                0 => {
                    assert!(request.starts_with("POST /v1/cubbyhole/handoff HTTP/1.1"));
                    assert!(request.contains(r#""value":"ok""#));
                    ("204 No Content", "{}")
                }
                1 => {
                    assert!(request.starts_with("GET /v1/cubbyhole/handoff HTTP/1.1"));
                    ("200 OK", r#"{"data":{"value":"ok"}}"#)
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/cubbyhole HTTP/1.1"));
                    ("200 OK", r#"{"data":{"keys":["handoff"]}}"#)
                }
                3 => {
                    assert!(request.starts_with("GET /v1/cubbyhole/missing HTTP/1.1"));
                    ("404 Not Found", r#"{"errors":["missing"]}"#)
                }
                4 => {
                    assert!(request.starts_with("DELETE /v1/cubbyhole/handoff HTTP/1.1"));
                    ("204 No Content", "{}")
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["test-", "token"]));
    let cubbyhole = client.cubbyhole().unwrap_or_else(|error| panic!("{error}"));

    cubbyhole
        .write("handoff", WrappedData { value: "ok".into() })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let secret = cubbyhole
        .read::<SecretData>("handoff")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(secret.value, "ok");
    let keys = cubbyhole
        .list("")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(keys.keys, ["handoff"]);
    let missing = cubbyhole
        .read_optional::<SecretData>("missing")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(missing.is_none());
    cubbyhole
        .delete("handoff")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
async fn kv2_list_sends_pagination_query() {
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
        assert!(request.starts_with("LIST /v1/secret/metadata/app?after=config&limit=10 HTTP/1.1"));
        let body = r#"{"data":{"keys":["config"]}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let keys = client
        .kv2("secret")
        .unwrap_or_else(|error| panic!("{error}"))
        .list_after("app", Some("config"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(keys.keys, ["config"]);

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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
async fn sys_leader_status_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/sys/leader HTTP/1.1"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"ha_enabled":true,"is_self":true,"leader_address":"https://127.0.0.1:8200","leader_cluster_address":"https://127.0.0.1:8201","performance_standby":false,"performance_standby_last_remote_wal":42}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let status = client
        .sys()
        .leader_status()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(status.ha_enabled);
    assert!(status.is_self);
    assert_eq!(
        status.leader_address.as_deref(),
        Some("https://127.0.0.1:8200")
    );
    assert_eq!(status.performance_standby_last_remote_wal, Some(42));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_ha_status_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/sys/ha-status HTTP/1.1"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"Nodes":[{"hostname":"node1","api_address":"https://10.0.0.2:8200","cluster_address":"https://10.0.0.2:8201","active_node":true,"last_echo":null,"version":"2.5.5"},{"hostname":"node2","api_address":"https://10.0.0.3:8200","cluster_address":"https://10.0.0.3:8201","active_node":false,"last_echo":"2026-06-02T00:00:00Z","version":"2.5.5"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let status = client
        .sys()
        .ha_status()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(status.nodes.len(), 2);
    assert!(status.nodes[0].active_node);
    assert_eq!(status.nodes[1].hostname, "node2");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_key_status_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/sys/key-status HTTP/1.1"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"term":3,"install_time":"2026-06-02T00:00:00Z","encryptions":74718331}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let status = client
        .sys()
        .key_status()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(status.term, 3);
    assert_eq!(status.encryptions, 74_718_331);

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "operator-ops")]
#[tokio::test]
async fn sys_step_down_leader_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("POST /v1/sys/step-down HTTP/1.1"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = "{}";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .sys()
        .step_down_leader()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_openapi_document_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(
            request.starts_with(
                "GET /v1/sys/internal/specs/openapi?generic_mount_paths=true HTTP/1.1"
            )
        );
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"openapi":"3.0.2","paths":{}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let document = client
        .sys()
        .openapi_document(true)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(document["openapi"], "3.0.2");
    assert!(document["paths"].is_object());

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_internal_ui_helpers_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..3 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/internal/ui/namespaces HTTP/1.1"));
                    r#"{"namespaces":["team/","team/app/"]}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with("GET /v1/sys/internal/ui/mounts HTTP/1.1"));
                    r#"{"auth":{"github/":{"description":"GitHub auth","type":"github"}},"secret":{"custom-secrets/":{"description":"Custom secrets","options":{"version":"2"},"type":"kv"}}}"#.to_owned()
                }
                2 => {
                    assert!(request.starts_with(
                        "GET /v1/sys/internal/ui/mounts/custom-secrets/app/config HTTP/1.1"
                    ));
                    assert!(request.contains("x-vault-token: test-token"));
                    r#"{"accessor":"kv_1234","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"Custom secrets","external_entropy_access":false,"local":false,"options":{"version":"2"},"path":"custom-secrets/","seal_wrap":false,"type":"kv","uuid":"4bb40403-d9ba-d2ee-087a-4c6d371db5f2"}"#.to_owned()
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let unauthenticated = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let namespaces = unauthenticated
        .sys()
        .ui_namespaces()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(namespaces.namespaces, ["team/", "team/app/"]);

    let mounts = unauthenticated
        .sys()
        .ui_mounts()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        mounts
            .secret
            .get("custom-secrets/")
            .and_then(|mount| mount.options.as_ref())
            .and_then(|options| options.get("version"))
            .map(String::as_str),
        Some("2")
    );

    let client = unauthenticated.with_token(SecretString::from("test-token"));
    let details = client
        .sys()
        .ui_mount_details("custom-secrets/app/config")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(details.backend_type, "kv");
    assert_eq!(details.path, "custom-secrets/");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_tool_helpers_use_documented_paths_and_redact_outputs() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..3 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/sys/tools/random/32 HTTP/1.1"));
                    assert!(request.contains("x-vault-token: test-token"));
                    assert!(request.contains(r#""format":"base64""#));
                    r#"{"data":{"random_bytes":"cmFuZG9t"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/tools/random/all/64 HTTP/1.1"));
                    assert!(request.contains(r#""format":"hex""#));
                    r#"{"data":{"random_bytes":"72616e646f6d"}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/sys/tools/hash/sha2-256 HTTP/1.1"));
                    assert!(request.contains(r#""input":"cGF5bG9hZA==""#));
                    assert!(request.contains(r#""format":"base64""#));
                    r#"{"data":{"sum":"c2hhMjU2"}}"#
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let random = client
        .sys()
        .random(
            &openbao::sys::SysRandomRequest::new()
                .with_bytes(32)
                .with_format(openbao::sys::SysToolsOutputFormat::Base64),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(random.random_bytes.expose_secret(), "cmFuZG9t");
    let debug = format!("{random:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("cmFuZG9t"));

    let random = client
        .sys()
        .random_from_source(
            openbao::sys::SysRandomSource::All,
            &openbao::sys::SysRandomRequest::new()
                .with_bytes(64)
                .with_format(openbao::sys::SysToolsOutputFormat::Hex),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(random.random_bytes.expose_secret(), "72616e646f6d");

    let hash = client
        .sys()
        .hash(
            openbao::sys::SysHashAlgorithm::Sha2_256,
            &openbao::sys::SysHashRequest::from_base64_input(test_secret(&["cGF5", "bG9hZA=="]))
                .with_format(openbao::sys::SysToolsOutputFormat::Base64),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(hash.sum.expose_secret(), "c2hhMjU2");
    let debug = format!("{hash:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("c2hhMjU2"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_metrics_json_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..2 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let (content_type, body) = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/metrics?format=json HTTP/1.1"));
                    assert!(request.contains("x-vault-token: test-token"));
                    (
                        "application/json",
                        r#"{"Gauges":[{"Name":"bao.core.unsealed","Value":1.0}],"Counters":[]}"#,
                    )
                }
                1 => {
                    assert!(request.starts_with("GET /v1/sys/metrics?format=prometheus HTTP/1.1"));
                    assert!(request.contains("accept: text/plain"));
                    (
                        "text/plain; version=0.0.4",
                        "# HELP bao_core_unsealed OpenBao unsealed\nbao_core_unsealed 1\n",
                    )
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let metrics = client
        .sys()
        .metrics_json()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(metrics["Gauges"].is_array());
    assert!(metrics["Counters"].is_array());

    let metrics = client
        .sys()
        .metrics_prometheus()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(metrics.contains("bao_core_unsealed 1"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_host_info_json_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/sys/host-info HTTP/1.1"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"data":{"cpu":[{"cpu":0,"vendorId":"GenuineIntel"}],"host":{"hostname":"openbao-server-1"},"memory":{"total":17179869184},"timestamp":"2026-06-02T00:00:00Z"}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let info = client
        .sys()
        .host_info_json()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(info["host"]["hostname"], "openbao-server-1");
    assert!(info["cpu"].is_array());

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_sanitized_config_state_json_sends_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/sys/config/state/sanitized HTTP/1.1"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"api_addr":"https://127.0.0.1:8200","default_lease_ttl":0,"listeners":[{"type":"tcp","config":{"address":"127.0.0.1:8200","tls_disable":0}}],"storage":{"type":"raft"}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let state = client
        .sys()
        .sanitized_config_state_json()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(state["storage"]["type"], "raft");
    assert_eq!(state["listeners"][0]["type"], "tcp");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn token_orphan_and_accessor_renew_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match index {
                0 => {
                    assert!(request.starts_with("POST /v1/auth/token/create-orphan HTTP/1.1"));
                    assert!(request.contains(r#""policies":["app-read"]"#));
                    assert!(request.contains(r#""renewable":true"#));
                    format!(
                        r#"{{"auth":{{"client_token":"{}{}","accessor":"{}{}","policies":["app-read"],"token_policies":["app-read"],"lease_duration":1800,"renewable":true}}}}"#,
                        "orphan-", "token", "accessor-", "value"
                    )
                }
                1 => {
                    assert!(request.starts_with("POST /v1/auth/token/renew-accessor HTTP/1.1"));
                    assert!(
                        request.contains(&format!(r#""accessor":"{}{}""#, "accessor-", "value"))
                    );
                    assert!(request.contains(r#""increment":"15m""#));
                    format!(
                        r#"{{"auth":{{"client_token":"{}{}","accessor":"{}{}","policies":["app-read"],"token_policies":["app-read"],"lease_duration":900,"renewable":true}}}}"#,
                        "renewed-", "token", "accessor-", "value"
                    )
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let orphan = client
        .token()
        .create_orphan(
            &openbao::auth::token::TokenCreateRequest {
                renewable: Some(true),
                ..Default::default()
            }
            .with_policies(["app-read"]),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(orphan.lease_duration, 1800);

    let renewed = client
        .token()
        .renew_accessor(&orphan.accessor, Some("15m"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(renewed.lease_duration, 900);

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_logger_helpers_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..5 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/loggers HTTP/1.1"));
                    r#"{"audit":"trace","core":"info"}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with("GET /v1/sys/loggers/core HTTP/1.1"));
                    r#"{"core":"info"}"#.to_owned()
                }
                2 => {
                    assert!(request.starts_with("POST /v1/sys/loggers HTTP/1.1"));
                    assert!(request.contains(r#""level":"debug""#));
                    String::new()
                }
                3 => {
                    assert!(request.starts_with("POST /v1/sys/loggers/core HTTP/1.1"));
                    assert!(request.contains(r#""level":"warn""#));
                    String::new()
                }
                4 => {
                    assert!(request.starts_with("DELETE /v1/sys/loggers/core HTTP/1.1"));
                    String::new()
                }
                _ => unreachable!(),
            };
            let response = if body.is_empty() {
                "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
                    .to_owned()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let levels = client
        .sys()
        .logger_levels()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(levels.get("core"), Some("info"));
    assert_eq!(levels.as_map().len(), 2);

    let core = client
        .sys()
        .logger_level("core")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(core.get("core"), Some("info"));

    client
        .sys()
        .set_logger_levels(openbao::sys::LoggerLevel::Debug)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    client
        .sys()
        .set_logger_level("core", openbao::sys::LoggerLevel::Warn)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    client
        .sys()
        .reset_logger_level("core")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_version_history_uses_documented_list_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("LIST /v1/sys/version-history HTTP/1.1"));
        assert!(request.contains("x-vault-token: test-token"));
        let body = r#"{"keys":["2.5.3","2.5.5"],"key_info":{"2.5.3":{"build_date":null,"previous_version":null,"timestamp_installed":"2026-05-01T00:00:00Z"},"2.5.5":{"build_date":"2026-05-26T00:00:00Z","previous_version":"2.5.3","timestamp_installed":"2026-05-27T00:00:00Z"}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let history = client
        .sys()
        .version_history()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(history.keys.iter().any(|version| version == "2.5.5"));
    assert_eq!(
        history
            .key_info
            .get("2.5.5")
            .and_then(|entry| entry.previous_version.as_deref()),
        Some("2.5.3")
    );

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_cors_config_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..3 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/config/cors HTTP/1.1"));
                    r#"{"enabled":true,"allowed_origins":["https://app.example.com"],"allowed_headers":["X-Custom-Header"]}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/config/cors HTTP/1.1"));
                    assert!(request.contains(r#""allowed_origins":["https://app.example.com"]"#));
                    assert!(request.contains(r#""allowed_headers":["X-Custom-Header"]"#));
                    "{}".to_owned()
                }
                2 => {
                    assert!(request.starts_with("DELETE /v1/sys/config/cors HTTP/1.1"));
                    "{}".to_owned()
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let config = client
        .sys()
        .cors_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(config.enabled);
    assert_eq!(config.allowed_origins, ["https://app.example.com"]);

    client
        .sys()
        .write_cors_config(
            &openbao::sys::CorsConfigRequest::new(["https://app.example.com"])
                .with_allowed_header("X-Custom-Header"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    client
        .sys()
        .delete_cors_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_namespace_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..6 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("LIST /v1/sys/namespaces HTTP/1.1"));
                    r#"{"data":{"keys":["team/"],"key_info":{"team/":{"id":"ns-team","path":"team/","custom_metadata":{"owner":"platform"}}}}}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/namespaces/team/app HTTP/1.1"));
                    assert!(request.contains(r#""custom_metadata":{"owner":"platform"}"#));
                    String::new()
                }
                2 => {
                    assert!(request.starts_with("GET /v1/sys/namespaces/team/app HTTP/1.1"));
                    r#"{"id":"ns-app","path":"team/app/","custom_metadata":{"owner":"platform"}}"#
                        .to_owned()
                }
                3 => {
                    assert!(request.starts_with("PATCH /v1/sys/namespaces/team/app HTTP/1.1"));
                    assert!(request.contains("content-type: application/merge-patch+json"));
                    assert!(request.contains(r#""custom_metadata":{"env":"dev"}"#));
                    String::new()
                }
                4 => {
                    assert!(request.starts_with("PATCH /v1/sys/namespaces/team/app HTTP/1.1"));
                    assert!(request.contains("content-type: application/merge-patch+json"));
                    assert!(request.contains(r#""custom_metadata":null"#));
                    String::new()
                }
                5 => {
                    assert!(request.starts_with("DELETE /v1/sys/namespaces/team/app HTTP/1.1"));
                    String::new()
                }
                _ => unreachable!(),
            };
            let response = if body.is_empty() {
                "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
                    .to_owned()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let namespaces = client
        .sys()
        .list_namespaces()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(namespaces.keys.iter().any(|namespace| namespace == "team/"));
    assert_eq!(
        namespaces
            .key_info
            .get("team/")
            .and_then(|namespace| namespace.custom_metadata.get("owner"))
            .map(String::as_str),
        Some("platform")
    );

    client
        .sys()
        .create_namespace(
            "team/app",
            &openbao::sys::NamespaceRequest::new().with_metadata("owner", "platform"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let namespace = client
        .sys()
        .read_namespace("team/app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(namespace.id, "ns-app");
    assert_eq!(namespace.path, "team/app/");

    client
        .sys()
        .patch_namespace(
            "team/app",
            &openbao::sys::NamespaceRequest::new().with_metadata("env", "dev"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    client
        .sys()
        .clear_namespace_metadata("team/app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    client
        .sys()
        .delete_namespace("team/app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_rate_limit_quota_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..7 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/quotas/config HTTP/1.1"));
                    r#"{"data":{"enable_rate_limit_audit_logging":false,"enable_rate_limit_response_headers":true,"rate_limit_exempt_paths":["sys/health","sys/seal-status"]}}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/quotas/config HTTP/1.1"));
                    assert!(request.contains(r#""enable_rate_limit_audit_logging":true"#));
                    assert!(request.contains(r#""rate_limit_exempt_paths":["sys/health"]"#));
                    String::new()
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/sys/quotas/rate-limit HTTP/1.1"));
                    r#"{"data":{"keys":["global-rate-limiter"]}}"#.to_owned()
                }
                3 => {
                    assert!(request.starts_with(
                        "POST /v1/sys/quotas/rate-limit/global-rate-limiter HTTP/1.1"
                    ));
                    assert!(request.contains(r#""rate":897.3"#));
                    assert!(request.contains(r#""interval":"2m""#));
                    assert!(request.contains(r#""block_interval":"5m""#));
                    String::new()
                }
                4 => {
                    assert!(
                        request.starts_with(
                            "GET /v1/sys/quotas/rate-limit/global-rate-limiter HTTP/1.1"
                        )
                    );
                    r#"{"data":{"block_interval":300,"interval":2,"name":"global-rate-limiter","path":"","rate":897.3,"role":"","type":"rate-limit"}}"#.to_owned()
                }
                5 => {
                    assert!(request.starts_with(
                        "DELETE /v1/sys/quotas/rate-limit/global-rate-limiter HTTP/1.1"
                    ));
                    String::new()
                }
                6 => {
                    assert!(request.starts_with("DELETE /v1/sys/quotas/config HTTP/1.1"));
                    String::new()
                }
                _ => unreachable!(),
            };
            let response = if body.is_empty() {
                "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
                    .to_owned()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let quota_config = client
        .sys()
        .read_rate_limit_quota_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(quota_config.enable_rate_limit_response_headers);
    assert_eq!(
        quota_config.rate_limit_exempt_paths,
        ["sys/health", "sys/seal-status"]
    );

    let mut quota_config = openbao::sys::RateLimitQuotaConfig::new().with_exempt_path("sys/health");
    quota_config.enable_rate_limit_audit_logging = true;
    client
        .sys()
        .write_rate_limit_quota_config(&quota_config)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let quotas = client
        .sys()
        .list_rate_limit_quotas()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        quotas
            .keys
            .iter()
            .any(|quota| quota == "global-rate-limiter")
    );

    client
        .sys()
        .write_rate_limit_quota(
            "global-rate-limiter",
            &openbao::sys::RateLimitQuotaRequest::new(897.3)
                .with_interval("2m")
                .with_block_interval("5m"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let quota = client
        .sys()
        .read_rate_limit_quota("global-rate-limiter")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(quota.name, "global-rate-limiter");
    assert_eq!(quota.rate, 897.3);

    client
        .sys()
        .delete_rate_limit_quota("global-rate-limiter")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    client
        .sys()
        .delete_rate_limit_quota_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_locked_users_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..3 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/locked-users HTTP/1.1"));
                    r#"{"data":{"by_namespace":[{"namespace_id":"root","namespace_path":"","counts":2,"mount_accessors":[{"mount_accessor":"auth_userpass_1234","counts":2,"alias_identifiers":["alice","bob"]}]}],"total":2}}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with("GET /v1/sys/locked-users HTTP/1.1"));
                    assert!(request.contains(r#""mount_accessor":"auth_userpass_1234""#));
                    r#"{"data":{"by_namespace":[{"namespace_id":"root","namespace_path":"","counts":1,"mount_accessors":[{"mount_accessor":"auth_userpass_1234","counts":1,"alias_identifiers":["alice"]}]}],"total":1}}"#.to_owned()
                }
                2 => {
                    assert!(request.starts_with(
                        "POST /v1/sys/locked-users/auth_userpass_1234/unlock/alice HTTP/1.1"
                    ));
                    String::new()
                }
                _ => unreachable!(),
            };
            let response = if body.is_empty() {
                "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
                    .to_owned()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let locked = client
        .sys()
        .list_locked_users()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(locked.total, 2);
    assert_eq!(
        locked.by_namespace[0].mount_accessors[0].alias_identifiers,
        ["alice", "bob"]
    );

    let locked = client
        .sys()
        .list_locked_users_for_accessor("auth_userpass_1234")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(locked.total, 1);
    assert_eq!(
        locked.by_namespace[0].mount_accessors[0].alias_identifiers,
        ["alice"]
    );

    client
        .sys()
        .unlock_user("auth_userpass_1234", "alice")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_raft_storage_helpers_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..12 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/sys/storage/raft/join HTTP/1.1"));
                    assert!(
                        request.contains(r#""leader_api_addr":"https://leader.example.com:8200""#)
                    );
                    assert!(request.contains(r#""leader_client_key":"leader-client-key""#));
                    assert!(request.contains(r#""auto_join":"provider-metadata""#));
                    r#"{"joined":true}"#.as_bytes().to_vec()
                }
                1 => {
                    assert!(request.starts_with("GET /v1/sys/storage/raft/configuration HTTP/1.1"));
                    r#"{"data":{"config":{"index":24,"servers":[{"address":"127.0.0.1:8201","leader":true,"node_id":"raft1","protocol_version":"3","voter":true},{"address":"127.0.0.2:8201","leader":false,"node_id":"raft2","protocol_version":"3","voter":false}]}}}"#.as_bytes().to_vec()
                }
                2 => {
                    assert!(request.starts_with("POST /v1/sys/storage/raft/remove-peer HTTP/1.1"));
                    assert!(request.contains(r#""server_id":"raft2""#));
                    Vec::new()
                }
                3 => {
                    assert!(request.starts_with("POST /v1/sys/storage/raft/promote HTTP/1.1"));
                    assert!(request.contains(r#""server_id":"raft2""#));
                    assert!(request.contains(r#""dr_operation_token":"dr-operation-token""#));
                    Vec::new()
                }
                4 => {
                    assert!(request.starts_with("POST /v1/sys/storage/raft/demote HTTP/1.1"));
                    assert!(request.contains(r#""server_id":"raft2""#));
                    Vec::new()
                }
                5 => {
                    assert!(request.starts_with("POST /v1/sys/storage/raft/bootstrap HTTP/1.1"));
                    Vec::new()
                }
                6 => {
                    assert!(request.starts_with("GET /v1/sys/storage/raft/snapshot HTTP/1.1"));
                    assert!(request.contains("accept: application/octet-stream"));
                    b"raft-snapshot-bytes".to_vec()
                }
                7 => {
                    assert!(request.starts_with("POST /v1/sys/storage/raft/snapshot HTTP/1.1"));
                    assert!(request.contains("content-type: application/octet-stream"));
                    assert!(request.contains("restore-snapshot"));
                    Vec::new()
                }
                8 => {
                    assert!(
                        request.starts_with("POST /v1/sys/storage/raft/snapshot-force HTTP/1.1")
                    );
                    assert!(request.contains("force-restore-snapshot"));
                    Vec::new()
                }
                9 => {
                    assert!(
                        request.starts_with("GET /v1/sys/storage/raft/autopilot/state HTTP/1.1")
                    );
                    r#"{"healthy":true,"failure_tolerance":1,"servers":{"raft1":{"id":"raft1","name":"raft1","address":"127.0.0.1:8201","node_status":"alive","last_contact":"0s","last_term":3,"last_index":459,"healthy":true,"stable_since":"2026-06-02T00:00:00Z","status":"leader","meta":null}},"leader":"raft1","voters":["raft1"],"non_voters":null}"#.as_bytes().to_vec()
                }
                10 => {
                    assert!(
                        request.starts_with(
                            "GET /v1/sys/storage/raft/autopilot/configuration HTTP/1.1"
                        )
                    );
                    r#"{"cleanup_dead_servers":false,"dead_server_last_contact_threshold":"24h0m0s","last_contact_threshold":"10s","max_trailing_logs":1000,"min_quorum":3,"server_stabilization_time":"10s"}"#.as_bytes().to_vec()
                }
                11 => {
                    assert!(
                        request.starts_with(
                            "POST /v1/sys/storage/raft/autopilot/configuration HTTP/1.1"
                        )
                    );
                    assert!(request.contains(r#""cleanup_dead_servers":true"#));
                    assert!(request.contains(r#""last_contact_threshold":"10s""#));
                    assert!(request.contains(r#""min_quorum":"3""#));
                    Vec::new()
                }
                _ => unreachable!(),
            };
            let response = if body.is_empty() {
                "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
                    .to_owned()
            } else if step == 6 {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    String::from_utf8_lossy(&body)
                )
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    String::from_utf8_lossy(&body)
                )
            };
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let join = openbao::sys::RaftJoinRequest::new("https://leader.example.com:8200")
        .with_leader_client_key(test_secret(&["leader", "-client-key"]))
        .with_auto_join(test_secret(&["provider", "-metadata"]));
    let join_response = client
        .sys()
        .raft_join(&join)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(join_response.joined);

    let configuration = client
        .sys()
        .raft_configuration()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(configuration.config.index, 24);
    assert_eq!(configuration.config.servers[0].node_id, "raft1");

    client
        .sys()
        .raft_remove_peer(&openbao::sys::RaftPeerRequest::new("raft2"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    client
        .sys()
        .raft_promote_peer(
            &openbao::sys::RaftPeerRequest::new("raft2")
                .with_dr_operation_token(test_secret(&["dr", "-operation-token"])),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    client
        .sys()
        .raft_demote_peer(&openbao::sys::RaftPeerRequest::new("raft2"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    client
        .sys()
        .raft_bootstrap()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let snapshot = client
        .sys()
        .raft_snapshot()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    snapshot.with_secret(|bytes| assert_eq!(bytes, b"raft-snapshot-bytes"));
    client
        .sys()
        .raft_restore_snapshot(b"restore-snapshot")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    client
        .sys()
        .raft_force_restore_snapshot(b"force-restore-snapshot")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let state = client
        .sys()
        .raft_autopilot_state_json()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(state["leader"], "raft1");

    let autopilot = client
        .sys()
        .raft_autopilot_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(autopilot.min_quorum.as_deref(), Some("3"));

    let mut autopilot = openbao::sys::RaftAutopilotConfig::new()
        .with_last_contact_threshold("10s")
        .with_server_stabilization_time("10s");
    autopilot.cleanup_dead_servers = Some(true);
    autopilot.dead_server_last_contact_threshold = Some("24h".to_owned());
    autopilot.max_trailing_logs = Some("1000".to_owned());
    autopilot.min_quorum = Some("3".to_owned());
    client
        .sys()
        .write_raft_autopilot_config(&autopilot)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_remount_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let migration_id = "ef3ba21c-8be8-4e5f-8d00-cb46a532c665";
    let server = thread::spawn(move || {
        for step in 0..2 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/sys/remount HTTP/1.1"));
                    assert!(request.contains(r#""from":"ns1/ns2/secret""#));
                    assert!(request.contains(r#""to":"ns1/ns3/new-secret""#));
                    format!(r#"{{"migration_id":"{migration_id}"}}"#)
                }
                1 => {
                    assert!(request.starts_with(&format!(
                        "GET /v1/sys/remount/status/{migration_id} HTTP/1.1"
                    )));
                    format!(
                        r#"{{"migration_id":"{migration_id}","migration_info":{{"source_mount":"ns1/ns2/secret","target_mount":"ns1/ns3/new-secret","status":"success"}}}}"#
                    )
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let response = client
        .sys()
        .remount(&openbao::sys::RemountRequest::new(
            "ns1/ns2/secret",
            "ns1/ns3/new-secret",
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(response.migration_id, migration_id);

    let status = client
        .sys()
        .remount_status(&response.migration_id)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(status.migration_info.status, "success");
    assert_eq!(status.migration_info.target_mount, "ns1/ns3/new-secret");

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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
async fn sys_password_policy_and_resultant_acl_helpers_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..6 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("LIST /v1/sys/policies/password HTTP/1.1"));
                    r#"{"keys":["db-policy"]}"#
                }
                1 => {
                    assert!(
                        request.starts_with("POST /v1/sys/policies/password/db-policy HTTP/1.1")
                    );
                    assert!(request.contains(r#""policy":"length = 20"#));
                    "{}"
                }
                2 => {
                    assert!(
                        request.starts_with("GET /v1/sys/policies/password/db-policy HTTP/1.1")
                    );
                    r#"{"policy":"length = 20\nrule \"charset\" { charset = \"abc\" }\n"}"#
                }
                3 => {
                    assert!(
                        request.starts_with(
                            "GET /v1/sys/policies/password/db-policy/generate HTTP/1.1"
                        )
                    );
                    r#"{"password":"generated-password"}"#
                }
                4 => {
                    assert!(request.starts_with("GET /v1/sys/internal/ui/resultant-acl HTTP/1.1"));
                    r#"{"exact_paths":{"secret/data/app":{"capabilities":["read"]}},"glob_paths":{"secret/metadata/app/":{"capabilities":["list"]}},"root":false}"#
                }
                5 => {
                    assert!(
                        request.starts_with("DELETE /v1/sys/policies/password/db-policy HTTP/1.1")
                    );
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));
    let sys = client.sys();

    let policies = sys
        .list_password_policies()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(policies.keys, ["db-policy"]);
    sys.write_password_policy(
        "db-policy",
        &openbao::sys::PasswordPolicyWriteRequest::new(
            "length = 20\nrule \"charset\" { charset = \"abc\" }\n",
        ),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let policy = sys
        .read_password_policy("db-policy")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(policy.policy.contains("length = 20"));
    let generated = sys
        .generate_password("db-policy")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(generated.password.expose_secret(), "generated-password");
    assert!(!format!("{generated:?}").contains("generated-password"));
    let acl = sys
        .resultant_acl()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(acl.exact_paths["secret/data/app"].capabilities().can_read());
    assert!(
        acl.glob_paths["secret/metadata/app/"]
            .capabilities()
            .can_list()
    );
    sys.delete_password_policy("db-policy")
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
    assert!(capabilities.single_path().can_read());
    assert!(capabilities.can_read_path("/secret/data/app"));
    assert!(!capabilities.can_delete_path("secret/data/app"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn sys_mfa_validate_sends_secret_payload_and_returns_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("POST /v1/sys/mfa/validate HTTP/1.1"));
        assert!(request.contains("x-vault-token: root-token"));
        assert!(request.contains(r#""mfa_request_id":"mfa-request-id""#));
        assert!(request.contains(r#""method-id":["123456"]"#));
        let body = r#"{"auth":{"client_token":"client-token","accessor":"token-accessor","policies":["default"],"token_policies":["default"],"identity_policies":null,"metadata":{"username":"alice"},"orphan":true,"entity_id":"entity-id","lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));

    let auth = client
        .sys()
        .validate_mfa(
            &openbao::sys::MfaValidateRequest::new("mfa-request-id")
                .with_passcode("method-id", SecretString::from("123456")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(auth.client_token.expose_secret(), "client-token");
    assert_eq!(auth.accessor.expose_secret(), "token-accessor");
    assert_eq!(
        auth.metadata.get("username").map(String::as_str),
        Some("alice")
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
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
async fn sys_audited_request_header_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..4 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(
                        request.starts_with("GET /v1/sys/config/auditing/request-headers HTTP/1.1")
                    );
                    r#"{"headers":{"X-Forwarded-For":{"hmac":true}}}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with(
                        "GET /v1/sys/config/auditing/request-headers/x-forwarded-for HTTP/1.1"
                    ));
                    r#"{"X-Forwarded-For":{"hmac":true}}"#.to_owned()
                }
                2 => {
                    assert!(request.starts_with(
                        "POST /v1/sys/config/auditing/request-headers/x-forwarded-for HTTP/1.1"
                    ));
                    assert!(request.contains(r#""hmac":true"#));
                    String::new()
                }
                3 => {
                    assert!(request.starts_with(
                        "DELETE /v1/sys/config/auditing/request-headers/x-forwarded-for HTTP/1.1"
                    ));
                    String::new()
                }
                _ => unreachable!(),
            };
            let response = if body.is_empty() {
                "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
                    .to_owned()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let headers = client
        .sys()
        .list_audited_request_headers()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        headers
            .headers
            .get("X-Forwarded-For")
            .is_some_and(|config| config.hmac)
    );

    let header = client
        .sys()
        .read_audited_request_header("X-Forwarded-For")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(header.hmac);

    client
        .sys()
        .write_audited_request_header(
            "X-Forwarded-For",
            openbao::sys::AuditedRequestHeaderConfig::new(true),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    client
        .sys()
        .delete_audited_request_header("X-Forwarded-For")
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
async fn sys_lease_tidy_uses_documented_path() {
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
        assert!(request.starts_with("POST /v1/sys/leases/tidy HTTP/1.1"));
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    client
        .sys()
        .tidy_leases()
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
        let body = r#"{"data":{"auth":["ldap"],"database":["postgresql-database-plugin"],"secret":["transit"],"detailed":[{"builtin":true,"deprecation_status":"supported","name":"transit","type":"secret","version":"v2.5.5+builtin.openbao"}]}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        .and_then(allow_mock_http)
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
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        let response = "HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        .and_then(allow_mock_http)
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

#[cfg(feature = "transit-bytes")]
#[tokio::test]
async fn transit_byte_helpers_base64_encode_and_decode_payloads() {
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
                assert!(request.contains(r#""context":"YXBw""#));
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
        .and_then(allow_mock_http)
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
            &openbao::secrets::transit::TransitEncryptRequest::from_plaintext_bytes(b"secret")
                .and_then(|request| request.with_context_bytes(b"app"))
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let decrypted = transit
        .decrypt(
            "app-key",
            &openbao::secrets::transit::TransitDecryptRequest::new(encrypted.ciphertext)
                .with_context_bytes(b"app")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let plaintext = decrypted
        .plaintext_bytes()
        .unwrap_or_else(|error| panic!("{error}"));
    plaintext.with_secret(|bytes| assert_eq!(bytes, b"secret"));

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
                    assert!(request.contains(r#""signature_algorithm":"pss""#));
                    assert!(request.contains(r#""marshaling_algorithm":"jws""#));
                    assert!(request.contains(r#""salt_length":"hash""#));
                    r#"{"data":{"signature":"vault:v1:signature","publickey":"derived-public-key"}}"#
                }
                _ => {
                    assert!(
                        request
                            .starts_with("POST /v1/transit/verify/signing-key/sha2-256 HTTP/1.1")
                    );
                    assert!(request.contains(r#""signature":"vault:v1:signature""#));
                    assert!(request.contains(r#""marshaling_algorithm":"jws""#));
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
        .and_then(allow_mock_http)
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
            &openbao::secrets::transit::TransitSignRequest::jws(SecretString::from("cGF5bG9hZA=="))
                .with_prehashed(true)
                .with_signature_algorithm(openbao::secrets::transit::TransitSignatureAlgorithm::Pss)
                .with_salt_length(openbao::secrets::transit::TransitSaltLength::Hash),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(signature.signature.expose_secret(), "vault:v1:signature");
    assert_eq!(signature.public_key.as_deref(), Some("derived-public-key"));

    let verified = transit
        .verify(
            "signing-key",
            Some(openbao::secrets::transit::TransitHashAlgorithm::Sha2_256),
            &openbao::secrets::transit::TransitVerifyRequest::jws_with_signature(
                SecretString::from("cGF5bG9hZA=="),
                signature.signature,
            ),
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
        .and_then(allow_mock_http)
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
async fn transit_advanced_key_management_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..14 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match index {
                0 => {
                    assert!(request.starts_with("GET /v1/transit/wrapping_key HTTP/1.1"));
                    r#"{"data":{"public_key":"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/transit/keys/imported/import HTTP/1.1"));
                    assert!(request.contains(r#""ciphertext":"wrapped-key-blob""#));
                    assert!(request.contains(r#""type":"aes256-gcm96""#));
                    assert!(request.contains(r#""hash_function":"SHA256""#));
                    assert!(request.contains(r#""context":"YXBw""#));
                    "{}"
                }
                2 => {
                    assert!(
                        request
                            .starts_with("POST /v1/transit/keys/imported-public/import HTTP/1.1")
                    );
                    assert!(request.contains(r#""public_key":"-----BEGIN PUBLIC KEY-----""#));
                    assert!(request.contains(r#""type":"rsa-2048""#));
                    assert!(!request.contains(r#""ciphertext""#));
                    "{}"
                }
                3 => {
                    assert!(request.starts_with(
                        "POST /v1/transit/keys/imported-public/import_version HTTP/1.1"
                    ));
                    assert!(request.contains(r#""public_key":"-----BEGIN PUBLIC KEY-----""#));
                    assert!(request.contains(r#""version":3"#));
                    assert!(!request.contains(r#""ciphertext""#));
                    "{}"
                }
                4 => {
                    assert!(
                        request
                            .starts_with("POST /v1/transit/keys/imported/import_version HTTP/1.1")
                    );
                    assert!(request.contains(r#""ciphertext":"wrapped-version-blob""#));
                    assert!(request.contains(r#""version":2"#));
                    "{}"
                }
                5 => {
                    assert!(
                        request
                            .starts_with("DELETE /v1/transit/keys/imported/soft-delete HTTP/1.1")
                    );
                    "{}"
                }
                6 => {
                    assert!(request.starts_with(
                        "POST /v1/transit/keys/imported/soft-delete-restore HTTP/1.1"
                    ));
                    "{}"
                }
                7 => {
                    assert!(request.starts_with(
                        "GET /v1/transit/byok-export/destination/source/3?hash=SHA512 HTTP/1.1"
                    ));
                    r#"{"data":{"name":"source","keys":{"3":"wrapped-for-destination"}}}"#
                }
                8 => {
                    assert!(request.starts_with("POST /v1/transit/config/keys HTTP/1.1"));
                    assert!(request.contains(r#""disable_upsert":true"#));
                    r#"{"data":{"disable_upsert":true}}"#
                }
                9 => {
                    assert!(request.starts_with("GET /v1/transit/config/keys HTTP/1.1"));
                    r#"{"data":{"disable_upsert":true}}"#
                }
                10 => {
                    assert!(request.starts_with("POST /v1/transit/cache-config HTTP/1.1"));
                    assert!(request.contains(r#""size":128"#));
                    r#"{"data":{"size":128}}"#
                }
                11 => {
                    assert!(request.starts_with("GET /v1/transit/cache-config HTTP/1.1"));
                    r#"{"data":{"size":128}}"#
                }
                12 => {
                    assert!(request.starts_with("POST /v1/transit/keys/signing/csr HTTP/1.1"));
                    assert!(request.contains(r#""version":1"#));
                    r#"{"data":{"name":"signing","type":"rsa-2048","csr":"-----BEGIN CERTIFICATE REQUEST-----"}}"#
                }
                13 => {
                    assert!(
                        request
                            .starts_with("POST /v1/transit/keys/signing/set-certificate HTTP/1.1")
                    );
                    assert!(
                        request.contains(r#""certificate_chain":"-----BEGIN CERTIFICATE-----"#)
                    );
                    r#"{"data":{"name":"signing","type":"rsa-2048","certificate_chain":"-----BEGIN CERTIFICATE-----"}}"#
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));
    let transit = client
        .transit("transit")
        .unwrap_or_else(|error| panic!("{error}"));

    let wrapping_key = transit
        .wrapping_key()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        wrapping_key
            .public_key
            .starts_with("-----BEGIN PUBLIC KEY-----")
    );

    transit
        .import_key(
            "imported",
            &openbao::secrets::transit::TransitImportRequest::new(
                SecretString::from("wrapped-key-blob"),
                openbao::secrets::transit::TransitKeyType::Aes256Gcm96,
            )
            .unwrap_or_else(|error| panic!("{error}"))
            .with_hash_function(openbao::secrets::transit::TransitImportHashFunction::Sha256)
            .allow_rotation()
            .with_context(SecretString::from("YXBw"))
            .exportable()
            .allow_plaintext_backup()
            .with_auto_rotate_period("24h")
            .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    transit
        .import_key(
            "imported-public",
            &openbao::secrets::transit::TransitImportRequest::from_public_key(
                "-----BEGIN PUBLIC KEY-----",
                openbao::secrets::transit::TransitKeyType::Rsa2048,
            )
            .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    transit
        .import_key_version(
            "imported-public",
            &openbao::secrets::transit::TransitImportVersionRequest::from_public_key(
                "-----BEGIN PUBLIC KEY-----",
            )
            .unwrap_or_else(|error| panic!("{error}"))
            .with_version(3)
            .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    transit
        .import_key_version(
            "imported",
            &openbao::secrets::transit::TransitImportVersionRequest::new(SecretString::from(
                "wrapped-version-blob",
            ))
            .unwrap_or_else(|error| panic!("{error}"))
            .with_version(2)
            .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    transit
        .soft_delete_key("imported")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    transit
        .restore_soft_deleted_key("imported")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let byok = transit
        .byok_export(
            "destination",
            "source",
            Some(3),
            Some(openbao::secrets::transit::TransitImportHashFunction::Sha512),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        byok.keys
            .get("3")
            .map(SecretString::expose_secret)
            .unwrap_or_else(|| panic!("missing BYOK export version")),
        "wrapped-for-destination"
    );

    let global = transit
        .write_global_key_config(&openbao::secrets::transit::TransitGlobalKeyConfig {
            disable_upsert: Some(true),
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(global.disable_upsert, Some(true));
    let global = transit
        .read_global_key_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(global.disable_upsert, Some(true));

    let cache = transit
        .write_cache_config(
            &openbao::secrets::transit::TransitCacheConfig::new(128)
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(cache.size, 128);
    let cache = transit
        .read_cache_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(cache.size, 128);

    let csr = transit
        .generate_csr(
            "signing",
            &openbao::secrets::transit::TransitCsrRequest {
                version: Some(1),
                csr: None,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(csr.name, "signing");

    let certificate = transit
        .set_certificate(
            "signing",
            &openbao::secrets::transit::TransitSetCertificateRequest::new(
                "-----BEGIN CERTIFICATE-----",
            )
            .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(certificate.key_type, "rsa-2048");

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
        .and_then(allow_mock_http)
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
        .and_then(allow_mock_http)
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
        .and_then(allow_mock_http)
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
            "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
async fn database_connection_role_and_credentials_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..12 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/database/config/postgres HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""plugin_name":"postgresql-database-plugin""#));
                    assert!(request.contains(r#""password":"root-password""#));
                    assert!(request.contains(r#""allowed_roles":["readonly"]"#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("GET /v1/database/config/postgres HTTP/1.1"));
                    r#"{"data":{"allowed_roles":["readonly"],"connection_details":{"connection_url":"postgres://{{username}}:{{password}}@localhost/postgres","username":"openbao"},"plugin_name":"postgresql-database-plugin","plugin_version":"","root_credentials_rotate_statements":[]}}"#
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/database/config HTTP/1.1"));
                    r#"{"data":{"keys":["postgres"]}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/database/roles/readonly HTTP/1.1"));
                    assert!(request.contains(r#""db_name":"postgres""#));
                    assert!(request.contains(r#""creation_statements":["CREATE ROLE"#));
                    "{}"
                }
                4 => {
                    assert!(request.starts_with("GET /v1/database/roles/readonly HTTP/1.1"));
                    r#"{"data":{"db_name":"postgres","creation_statements":["CREATE ROLE \"{{name}}\""],"default_ttl":3600,"max_ttl":"24h","revocation_statements":[],"rollback_statements":[],"renew_statements":[]}}"#
                }
                5 => {
                    assert!(request.starts_with("LIST /v1/database/roles HTTP/1.1"));
                    r#"{"data":{"keys":["readonly"]}}"#
                }
                6 => {
                    assert!(request.starts_with("GET /v1/database/creds/readonly HTTP/1.1"));
                    r#"{"lease_id":"database/creds/readonly/lease","lease_duration":3600,"renewable":true,"data":{"username":"v-root-1","password":"generated-password"}}"#
                }
                7 => {
                    assert!(request.starts_with("POST /v1/database/static-roles/app HTTP/1.1"));
                    assert!(request.contains(r#""db_name":"postgres""#));
                    assert!(request.contains(r#""username":"app_user""#));
                    assert!(request.contains(r#""rotation_period":"1h""#));
                    "{}"
                }
                8 => {
                    assert!(request.starts_with("LIST /v1/database/static-roles HTTP/1.1"));
                    r#"{"data":{"keys":["app"]}}"#
                }
                9 => {
                    assert!(request.starts_with("GET /v1/database/static-creds/app HTTP/1.1"));
                    r#"{"data":{"username":"app_user","password":"static-password","last_openbao_rotation":"2026-05-30T00:00:00Z","rotation_period":3600,"ttl":300}}"#
                }
                10 => {
                    assert!(request.starts_with("POST /v1/database/rotate-role/app HTTP/1.1"));
                    "{}"
                }
                11 => {
                    assert!(request.starts_with("POST /v1/database/rotate-root/postgres HTTP/1.1"));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let database = client
        .database("database")
        .unwrap_or_else(|error| panic!("{error}"));

    database
        .configure_connection(
            "postgres",
            &openbao::secrets::database::DatabaseConnectionConfig {
                allowed_roles: vec!["readonly".to_owned()],
                connection_url: Some(SecretString::from(
                    "postgres://{{username}}:{{password}}@localhost/postgres",
                )),
                username: Some("openbao".to_owned()),
                password: Some(SecretString::from("root-password")),
                ..openbao::secrets::database::DatabaseConnectionConfig::new(
                    "postgresql-database-plugin",
                )
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let connection = database
        .read_connection("postgres")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(connection.plugin_name, "postgresql-database-plugin");
    let connections = database
        .list_connections()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(connections.keys, ["postgres"]);

    database
        .write_role(
            "readonly",
            &openbao::secrets::database::DatabaseRole::new("postgres")
                .with_creation_statement("CREATE ROLE \"{{name}}\""),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let role = database
        .read_role("readonly")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(role.default_ttl.as_deref(), Some("3600"));
    let roles = database
        .list_roles()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["readonly"]);

    let credentials = database
        .credentials("readonly")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(credentials.username, "v-root-1");
    assert_eq!(
        credentials
            .password
            .as_ref()
            .map(SecretString::expose_secret),
        Some("generated-password")
    );
    assert_eq!(
        credentials.lease_id.expose_secret(),
        "database/creds/readonly/lease"
    );

    database
        .write_static_role(
            "app",
            &openbao::secrets::database::DatabaseStaticRole {
                rotation_period: Some("1h".to_owned()),
                ..openbao::secrets::database::DatabaseStaticRole::new("postgres", "app_user")
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let static_roles = database
        .list_static_roles()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(static_roles.keys, ["app"]);
    let static_credentials = database
        .static_credentials("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        static_credentials.password.expose_secret(),
        "static-password"
    );
    database
        .rotate_static_role("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    database
        .rotate_root("postgres")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn rabbitmq_config_role_and_credentials_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let credential_password = ["rabbit", "-", "generated"].concat();
        for step in 0..7 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/rabbitmq/config/connection HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""connection_uri":"https://rabbit.example:15672""#));
                    assert!(request.contains(r#""username":"admin""#));
                    assert!(request.contains(r#""password":"rabbit-admin""#));
                    assert!(request.contains(r#""verify_connection":false"#));
                    "{}".to_owned()
                }
                1 => {
                    assert!(request.starts_with("POST /v1/rabbitmq/config/lease HTTP/1.1"));
                    assert!(request.contains(r#""ttl":1800"#));
                    assert!(request.contains(r#""max_ttl":3600"#));
                    "{}".to_owned()
                }
                2 => {
                    assert!(request.starts_with("POST /v1/rabbitmq/roles/worker HTTP/1.1"));
                    assert!(request.contains(r#""tags":"monitoring""#));
                    assert!(
                        request
                            .contains(r#""vhosts":"{\"/\":{\"write\":\".*\",\"read\":\".*\"}}""#)
                    );
                    "{}".to_owned()
                }
                3 => {
                    assert!(request.starts_with("GET /v1/rabbitmq/roles/worker HTTP/1.1"));
                    r#"{"data":{"tags":"monitoring","vhosts":"{\"/\":{\"write\":\".*\",\"read\":\".*\"}}","vhost_topics":"{\"/\":{\"amq.topic\":{\"write\":\".*\",\"read\":\".*\"}}"}}"#
                        .to_owned()
                }
                4 => {
                    assert!(
                        request
                            .starts_with("LIST /v1/rabbitmq/roles?after=worker&limit=10 HTTP/1.1")
                    );
                    r#"{"data":{"keys":["worker"]}}"#.to_owned()
                }
                5 => {
                    assert!(request.starts_with("GET /v1/rabbitmq/creds/worker HTTP/1.1"));
                    format!(
                        r#"{{"lease_id":"rabbitmq/creds/worker/lease","lease_duration":1800,"renewable":true,"data":{{"username":"root-worker","password":"{credential_password}"}}}}"#
                    )
                }
                6 => {
                    assert!(request.starts_with("DELETE /v1/rabbitmq/roles/worker HTTP/1.1"));
                    "{}".to_owned()
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let rabbitmq = client.rabbitmq().unwrap_or_else(|error| panic!("{error}"));

    rabbitmq
        .configure_connection(
            &openbao::secrets::rabbitmq::RabbitMqConnectionConfig::new(
                SecretString::from("https://rabbit.example:15672"),
                "admin",
                test_secret(&["rabbit", "-", "admin"]),
            )
            .with_verify_connection(false),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    rabbitmq
        .configure_lease(&openbao::secrets::rabbitmq::RabbitMqLeaseConfig::new(
            1800, 3600,
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    rabbitmq
        .write_role(
            "worker",
            &openbao::secrets::rabbitmq::RabbitMqRole::new()
                .with_tags("monitoring")
                .with_vhosts(r#"{"/":{"write":".*","read":".*"}}"#)
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let role = rabbitmq
        .read_role("worker")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(role.tags.as_deref(), Some("monitoring"));
    let roles = rabbitmq
        .list_roles_after(Some("worker"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["worker"]);
    let credentials = rabbitmq
        .credentials("worker")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(credentials.username, "root-worker");
    assert_eq!(
        credentials.password.expose_secret(),
        test_secret(&["rabbit", "-", "generated"]).expose_secret()
    );
    assert_eq!(
        credentials.lease_id.expose_secret(),
        "rabbitmq/creds/worker/lease"
    );

    rabbitmq
        .delete_role("worker")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn identity_entity_group_and_alias_lifecycle_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..18 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/identity/entity HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""name":"app-service""#));
                    assert!(request.contains(r#""policies":["app-read"]"#));
                    r#"{"data":{"id":"entity-id-1","name":"app-service"}}"#
                }
                1 => {
                    assert!(request.starts_with("GET /v1/identity/entity/id/entity-id-1 HTTP/1.1"));
                    r#"{"data":{"id":"entity-id-1","name":"app-service","metadata":{"team":"platform"},"policies":["app-read"],"direct_group_ids":["group-id-1"],"inherited_group_ids":[],"disabled":false}}"#
                }
                2 => {
                    assert!(
                        request.starts_with("POST /v1/identity/entity/name/app-service HTTP/1.1")
                    );
                    assert!(request.contains(r#""disabled":false"#));
                    r#"{"data":{"id":"entity-id-1","name":"app-service"}}"#
                }
                3 => {
                    assert!(request.starts_with("LIST /v1/identity/entity/name HTTP/1.1"));
                    r#"{"data":{"keys":["app-service"]}}"#
                }
                4 => {
                    assert!(request.starts_with("LIST /v1/identity/entity/id HTTP/1.1"));
                    r#"{"data":{"keys":["entity-id-1"]}}"#
                }
                5 => {
                    assert!(request.starts_with("POST /v1/identity/group HTTP/1.1"));
                    assert!(request.contains(r#""name":"app-group""#));
                    assert!(request.contains(r#""type":"internal""#));
                    assert!(request.contains(r#""member_entity_ids":["entity-id-1"]"#));
                    r#"{"data":{"id":"group-id-1","name":"app-group"}}"#
                }
                6 => {
                    assert!(request.starts_with("GET /v1/identity/group/id/group-id-1 HTTP/1.1"));
                    r#"{"data":{"id":"group-id-1","name":"app-group","type":"internal","policies":["app-read"],"member_entity_ids":["entity-id-1"],"member_group_ids":[],"parent_group_ids":[],"metadata":{"team":"platform"}}}"#
                }
                7 => {
                    assert!(request.starts_with("POST /v1/identity/group/name/app-group HTTP/1.1"));
                    r#"{"data":{"id":"group-id-1","name":"app-group"}}"#
                }
                8 => {
                    assert!(request.starts_with("LIST /v1/identity/group/name HTTP/1.1"));
                    r#"{"data":{"keys":["app-group"]}}"#
                }
                9 => {
                    assert!(request.starts_with("POST /v1/identity/entity-alias HTTP/1.1"));
                    assert!(request.contains(r#""name":"app-service""#));
                    assert!(request.contains(r#""canonical_id":"entity-id-1""#));
                    assert!(request.contains(r#""mount_accessor":"auth_userpass_accessor""#));
                    r#"{"data":{"id":"entity-alias-id-1"}}"#
                }
                10 => {
                    assert!(request.starts_with(
                        "GET /v1/identity/entity-alias/id/entity-alias-id-1 HTTP/1.1"
                    ));
                    r#"{"data":{"id":"entity-alias-id-1","name":"app-service","canonical_id":"entity-id-1","mount_accessor":"auth_userpass_accessor","mount_path":"auth/userpass/","mount_type":"userpass","custom_metadata":{"team":"platform"}}}"#
                }
                11 => {
                    assert!(request.starts_with("LIST /v1/identity/entity-alias/id HTTP/1.1"));
                    r#"{"data":{"keys":["entity-alias-id-1"]}}"#
                }
                12 => {
                    assert!(request.starts_with("POST /v1/identity/group-alias HTTP/1.1"));
                    assert!(request.contains(r#""name":"app-group""#));
                    assert!(request.contains(r#""canonical_id":"group-id-1""#));
                    r#"{"data":{"id":"group-alias-id-1"}}"#
                }
                13 => {
                    assert!(
                        request.starts_with(
                            "GET /v1/identity/group-alias/id/group-alias-id-1 HTTP/1.1"
                        )
                    );
                    r#"{"data":{"id":"group-alias-id-1","name":"app-group","canonical_id":"group-id-1","mount_accessor":"auth_userpass_accessor","mount_path":"auth/userpass/","mount_type":"userpass"}}"#
                }
                14 => {
                    assert!(request.starts_with("LIST /v1/identity/group-alias/id HTTP/1.1"));
                    r#"{"data":{"keys":["group-alias-id-1"]}}"#
                }
                15 => {
                    assert!(request.starts_with(
                        "DELETE /v1/identity/entity-alias/id/entity-alias-id-1 HTTP/1.1"
                    ));
                    "{}"
                }
                16 => {
                    assert!(request.starts_with(
                        "DELETE /v1/identity/group-alias/id/group-alias-id-1 HTTP/1.1"
                    ));
                    "{}"
                }
                17 => {
                    assert!(request.starts_with("POST /v1/identity/entity/batch-delete HTTP/1.1"));
                    assert!(request.contains(r#""entity_ids":["entity-id-1"]"#));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let identity = client.identity().unwrap_or_else(|error| panic!("{error}"));

    let entity = identity
        .write_entity(
            &openbao::secrets::identity::IdentityEntityRequest::named("app-service")
                .with_policy("app-read")
                .with_metadata("team", "platform"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(entity.id, "entity-id-1");
    let entity_info = identity
        .read_entity_by_id("entity-id-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(entity_info.name.as_deref(), Some("app-service"));
    identity
        .write_entity_by_name(
            "app-service",
            &openbao::secrets::identity::IdentityEntityRequest {
                disabled: Some(false),
                ..openbao::secrets::identity::IdentityEntityRequest::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let entity_names = identity
        .list_entity_names()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(entity_names.keys, ["app-service"]);
    let entity_ids = identity
        .list_entity_ids()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(entity_ids.keys, ["entity-id-1"]);

    let group = identity
        .write_group(
            &openbao::secrets::identity::IdentityGroupRequest::internal("app-group")
                .with_policy("app-read")
                .with_member_entity_id("entity-id-1")
                .with_metadata("team", "platform"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(group.id, "group-id-1");
    let group_info = identity
        .read_group_by_id("group-id-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(group_info.member_entity_ids, ["entity-id-1"]);
    identity
        .write_group_by_name(
            "app-group",
            &openbao::secrets::identity::IdentityGroupRequest::internal("app-group"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let group_names = identity
        .list_group_names()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(group_names.keys, ["app-group"]);

    let entity_alias = identity
        .write_entity_alias(
            &openbao::secrets::identity::IdentityEntityAliasRequest::new(
                "app-service",
                "entity-id-1",
                "auth_userpass_accessor",
            )
            .with_custom_metadata("team", "platform"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(entity_alias.id, "entity-alias-id-1");
    let alias_info = identity
        .read_entity_alias_by_id("entity-alias-id-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(alias_info.canonical_id.as_deref(), Some("entity-id-1"));
    let entity_aliases = identity
        .list_entity_alias_ids()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(entity_aliases.keys, ["entity-alias-id-1"]);

    let group_alias = identity
        .write_group_alias(&openbao::secrets::identity::IdentityGroupAliasRequest::new(
            "app-group",
            "group-id-1",
            "auth_userpass_accessor",
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(group_alias.id, "group-alias-id-1");
    let group_alias_info = identity
        .read_group_alias_by_id("group-alias-id-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(group_alias_info.canonical_id.as_deref(), Some("group-id-1"));
    let group_aliases = identity
        .list_group_alias_ids()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(group_aliases.keys, ["group-alias-id-1"]);

    identity
        .delete_entity_alias_by_id("entity-alias-id-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    identity
        .delete_group_alias_by_id("group-alias-id-1")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    identity
        .batch_delete_entities(
            &openbao::secrets::identity::IdentityEntityBatchDeleteRequest::new(["entity-id-1"]),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn identity_oidc_token_helpers_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..15 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/identity/oidc/config HTTP/1.1"));
                    assert!(request.contains(r#""issuer":"https://bao.example.com""#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("GET /v1/identity/oidc/config HTTP/1.1"));
                    r#"{"data":{"issuer":"https://bao.example.com"}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/identity/oidc/key/app-key HTTP/1.1"));
                    assert!(request.contains(r#""rotation_period":"12h""#));
                    assert!(request.contains(r#""verification_ttl":"24h""#));
                    assert!(request.contains(r#""allowed_client_ids":["app-client"]"#));
                    "{}"
                }
                3 => {
                    assert!(request.starts_with("GET /v1/identity/oidc/key/app-key HTTP/1.1"));
                    r#"{"data":{"algorithm":"RS256","rotation_period":43200,"verification_ttl":86400,"allowed_client_ids":["app-client"]}}"#
                }
                4 => {
                    assert!(request.starts_with("LIST /v1/identity/oidc/key HTTP/1.1"));
                    r#"{"data":{"keys":["app-key"]}}"#
                }
                5 => {
                    assert!(
                        request.starts_with("POST /v1/identity/oidc/key/app-key/rotate HTTP/1.1")
                    );
                    assert!(request.contains(r#""verification_ttl":"24h""#));
                    "{}"
                }
                6 => {
                    assert!(request.starts_with("POST /v1/identity/oidc/role/app-role HTTP/1.1"));
                    assert!(request.contains(r#""key":"app-key""#));
                    assert!(request.contains(r#""client_id":"app-client""#));
                    assert!(request.contains(r#""ttl":"1h""#));
                    "{}"
                }
                7 => {
                    assert!(request.starts_with("GET /v1/identity/oidc/role/app-role HTTP/1.1"));
                    r#"{"data":{"client_id":"app-client","key":"app-key","template":"","ttl":3600}}"#
                }
                8 => {
                    assert!(request.starts_with("LIST /v1/identity/oidc/role HTTP/1.1"));
                    r#"{"data":{"keys":["app-role"]}}"#
                }
                9 => {
                    assert!(request.starts_with("GET /v1/identity/oidc/token/app-role HTTP/1.1"));
                    r#"{"data":{"client_id":"app-client","token":"signed-id-token","ttl":3600}}"#
                }
                10 => {
                    assert!(request.starts_with("POST /v1/identity/oidc/introspect HTTP/1.1"));
                    assert!(request.contains(r#""token":"signed-id-token""#));
                    assert!(request.contains(r#""client_id":"app-client""#));
                    r#"{"active":true}"#
                }
                11 => {
                    assert!(request.starts_with(
                        "GET /v1/identity/oidc/.well-known/openid-configuration HTTP/1.1"
                    ));
                    r#"{"issuer":"https://bao.example.com","authorization_endpoint":"","token_endpoint":"","jwks_uri":"https://bao.example.com/.well-known/keys","response_types_supported":null,"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":null,"token_endpoint_auth_methods_supported":null,"claims_supported":null}"#
                }
                12 => {
                    assert!(request.starts_with("GET /v1/identity/oidc/.well-known/keys HTTP/1.1"));
                    r#"{"keys":[{"use":"sig","kty":"RSA","kid":"key-1","alg":"RS256","n":"modulus","e":"AQAB"}]}"#
                }
                13 => {
                    assert!(request.starts_with("DELETE /v1/identity/oidc/role/app-role HTTP/1.1"));
                    "{}"
                }
                14 => {
                    assert!(request.starts_with("DELETE /v1/identity/oidc/key/app-key HTTP/1.1"));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let identity = client.identity().unwrap_or_else(|error| panic!("{error}"));

    identity
        .write_oidc_config(&openbao::secrets::identity::IdentityOidcConfigRequest::new(
            "https://bao.example.com",
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let config = identity
        .read_oidc_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(config.issuer.as_deref(), Some("https://bao.example.com"));

    identity
        .write_oidc_key(
            "app-key",
            &openbao::secrets::identity::IdentityOidcKeyRequest::new()
                .with_rotation_period("12h")
                .with_verification_ttl("24h")
                .with_allowed_client_id("app-client")
                .with_algorithm("RS256"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let key = identity
        .read_oidc_key("app-key")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(key.allowed_client_ids, ["app-client"]);
    let keys = identity
        .list_oidc_keys()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(keys.keys, ["app-key"]);
    identity
        .rotate_oidc_key(
            "app-key",
            &openbao::secrets::identity::IdentityOidcKeyRotateRequest::new()
                .with_verification_ttl("24h"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    identity
        .write_oidc_role(
            "app-role",
            &openbao::secrets::identity::IdentityOidcRoleRequest::new("app-key")
                .with_client_id("app-client")
                .with_ttl("1h"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let role = identity
        .read_oidc_role("app-role")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(role.client_id.as_deref(), Some("app-client"));
    let roles = identity
        .list_oidc_roles()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["app-role"]);

    let token = identity
        .generate_oidc_token("app-role")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(token.client_id.as_deref(), Some("app-client"));
    assert_eq!(token.token.expose_secret(), "signed-id-token");
    let introspection = identity
        .introspect_oidc_token(
            &openbao::secrets::identity::IdentityOidcIntrospectRequest::new(token.token)
                .with_client_id("app-client"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(introspection.active);

    let discovery = identity
        .read_oidc_discovery()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        discovery
            .subject_types_supported
            .as_ref()
            .and_then(|values| values.first())
            .map(String::as_str),
        Some("public")
    );
    let jwks = identity
        .read_oidc_jwks()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(jwks.keys.len(), 1);

    identity
        .delete_oidc_role("app-role")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    identity
        .delete_oidc_key("app-key")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn identity_oidc_provider_helpers_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..19 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/identity/oidc/provider/app HTTP/1.1"));
                    assert!(request.contains(r#""issuer":"https://issuer.example.com""#));
                    assert!(request.contains(r#""allowed_client_ids":["app-client"]"#));
                    assert!(request.contains(r#""scopes_supported":["openid"]"#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("GET /v1/identity/oidc/provider/app HTTP/1.1"));
                    r#"{"data":{"issuer":"https://issuer.example.com","allowed_client_ids":["app-client"],"scopes_supported":["openid"]}}"#
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/identity/oidc/provider HTTP/1.1"));
                    r#"{"data":{"keys":["app"],"key_info":{"app":{"issuer":"https://issuer.example.com","allowed_client_ids":["app-client"],"scopes_supported":["openid"]}}}}"#
                }
                3 => {
                    assert!(request.starts_with(
                        "LIST /v1/identity/oidc/provider?client_id=app-client HTTP/1.1"
                    ));
                    r#"{"data":{"keys":["app"],"key_info":{"app":{"issuer":"https://issuer.example.com","allowed_client_ids":["app-client"],"scopes_supported":["openid"]}}}}"#
                }
                4 => {
                    assert!(request.starts_with("POST /v1/identity/oidc/scope/profile HTTP/1.1"));
                    assert!(request.contains(r#""description":"Profile claims""#));
                    assert!(
                        request.contains(r#""template":"{\"name\":\"{{identity.entity.name}}\"}""#)
                    );
                    "{}"
                }
                5 => {
                    assert!(request.starts_with("GET /v1/identity/oidc/scope/profile HTTP/1.1"));
                    r#"{"data":{"template":"{\"name\":\"{{identity.entity.name}}\"}","description":"Profile claims"}}"#
                }
                6 => {
                    assert!(request.starts_with("LIST /v1/identity/oidc/scope HTTP/1.1"));
                    r#"{"data":{"keys":["profile"]}}"#
                }
                7 => {
                    assert!(request.starts_with("POST /v1/identity/oidc/client/app HTTP/1.1"));
                    assert!(request.contains(r#""key":"app-key""#));
                    assert!(
                        request.contains(r#""redirect_uris":["https://app.example.com/callback"]"#)
                    );
                    assert!(request.contains(r#""assignments":["app-assignment"]"#));
                    assert!(request.contains(r#""client_type":"confidential""#));
                    assert!(request.contains(r#""id_token_ttl":"1h""#));
                    assert!(request.contains(r#""access_token_ttl":"30m""#));
                    "{}"
                }
                8 => {
                    assert!(request.starts_with("GET /v1/identity/oidc/client/app HTTP/1.1"));
                    r#"{"data":{"access_token_ttl":1800,"assignments":["app-assignment"],"client_id":"app-client","client_secret":"client-secret","client_type":"confidential","id_token_ttl":3600,"key":"app-key","redirect_uris":["https://app.example.com/callback"]}}"#
                }
                9 => {
                    assert!(request.starts_with("LIST /v1/identity/oidc/client HTTP/1.1"));
                    r#"{"data":{"keys":["app"],"key_info":{"app":{"access_token_ttl":1800,"assignments":["app-assignment"],"client_id":"app-client","client_type":"confidential","id_token_ttl":3600,"key":"app-key","redirect_uris":["https://app.example.com/callback"]}}}}"#
                }
                10 => {
                    assert!(
                        request.starts_with(
                            "POST /v1/identity/oidc/assignment/app-assignment HTTP/1.1"
                        )
                    );
                    assert!(request.contains(r#""entity_ids":["entity-id"]"#));
                    assert!(request.contains(r#""group_ids":["group-id"]"#));
                    "{}"
                }
                11 => {
                    assert!(
                        request.starts_with(
                            "GET /v1/identity/oidc/assignment/app-assignment HTTP/1.1"
                        )
                    );
                    r#"{"data":{"entity_ids":["entity-id"],"group_ids":["group-id"]}}"#
                }
                12 => {
                    assert!(request.starts_with("LIST /v1/identity/oidc/assignment HTTP/1.1"));
                    r#"{"data":{"keys":["app-assignment"]}}"#
                }
                13 => {
                    assert!(request.starts_with(
                        "GET /v1/identity/oidc/provider/app/.well-known/openid-configuration HTTP/1.1"
                    ));
                    r#"{"issuer":"https://issuer.example.com","authorization_endpoint":"https://issuer.example.com/authorize","token_endpoint":"https://issuer.example.com/token","userinfo_endpoint":"https://issuer.example.com/userinfo","jwks_uri":"https://issuer.example.com/.well-known/keys","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"scopes_supported":["openid"],"grant_types_supported":["authorization_code"],"token_endpoint_auth_methods_supported":["client_secret_basic"]}"#
                }
                14 => {
                    assert!(request.starts_with(
                        "GET /v1/identity/oidc/provider/app/.well-known/keys HTTP/1.1"
                    ));
                    r#"{"keys":[{"use":"sig","kty":"RSA","kid":"key-1","alg":"RS256","n":"modulus","e":"AQAB"}]}"#
                }
                15 => {
                    assert!(request.starts_with(
                        "DELETE /v1/identity/oidc/assignment/app-assignment HTTP/1.1"
                    ));
                    "{}"
                }
                16 => {
                    assert!(request.starts_with("DELETE /v1/identity/oidc/client/app HTTP/1.1"));
                    "{}"
                }
                17 => {
                    assert!(request.starts_with("DELETE /v1/identity/oidc/scope/profile HTTP/1.1"));
                    "{}"
                }
                18 => {
                    assert!(request.starts_with("DELETE /v1/identity/oidc/provider/app HTTP/1.1"));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let identity = client.identity().unwrap_or_else(|error| panic!("{error}"));

    identity
        .write_oidc_provider(
            "app",
            &openbao::secrets::identity::IdentityOidcProviderRequest::new()
                .with_issuer("https://issuer.example.com")
                .with_allowed_client_id("app-client")
                .with_scope_supported("openid"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let provider = identity
        .read_oidc_provider("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(provider.allowed_client_ids, ["app-client"]);
    assert_eq!(
        identity
            .list_oidc_providers()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["app"]
    );
    assert_eq!(
        identity
            .list_oidc_providers_for_client_id("app-client")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["app"]
    );

    identity
        .write_oidc_scope(
            "profile",
            &openbao::secrets::identity::IdentityOidcScopeRequest::new()
                .with_template(r#"{"name":"{{identity.entity.name}}"}"#)
                .with_description("Profile claims"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let scope = identity
        .read_oidc_scope("profile")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(scope.description.as_deref(), Some("Profile claims"));
    assert_eq!(
        identity
            .list_oidc_scopes()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["profile"]
    );

    identity
        .write_oidc_client(
            "app",
            &openbao::secrets::identity::IdentityOidcClientRequest::new()
                .with_key("app-key")
                .with_redirect_uri("https://app.example.com/callback")
                .with_assignment("app-assignment")
                .with_client_type(openbao::secrets::identity::IdentityOidcClientType::Confidential)
                .with_id_token_ttl("1h")
                .with_access_token_ttl("30m"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let oidc_client = identity
        .read_oidc_client("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(oidc_client.client_id.as_deref(), Some("app-client"));
    assert_eq!(
        oidc_client
            .client_secret
            .as_ref()
            .map(SecretString::expose_secret),
        Some("client-secret")
    );
    assert_eq!(
        identity
            .list_oidc_clients()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["app"]
    );

    identity
        .write_oidc_assignment(
            "app-assignment",
            &openbao::secrets::identity::IdentityOidcAssignmentRequest::new()
                .with_entity_id("entity-id")
                .with_group_id("group-id"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let assignment = identity
        .read_oidc_assignment("app-assignment")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(assignment.group_ids, ["group-id"]);
    assert_eq!(
        identity
            .list_oidc_assignments()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["app-assignment"]
    );

    let discovery = identity
        .read_oidc_provider_discovery("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        discovery.issuer.as_deref(),
        Some("https://issuer.example.com")
    );
    assert_eq!(
        identity
            .read_oidc_provider_jwks("app")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys
            .len(),
        1
    );

    identity
        .delete_oidc_assignment("app-assignment")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    identity
        .delete_oidc_client("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    identity
        .delete_oidc_scope("profile")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    identity
        .delete_oidc_provider("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn identity_mfa_helpers_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..23 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(
                        request.starts_with("POST /v1/identity/mfa/method/duo/duo-id HTTP/1.1")
                    );
                    assert!(request.contains(r#""method_name":"duo-main""#));
                    assert!(request.contains(r#""secret_key":"#));
                    assert!(request.contains(r#""integration_key":"#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("GET /v1/identity/mfa/method/duo/duo-id HTTP/1.1"));
                    r#"{"data":{"id":"duo-id","method_name":"duo-main","secret_key":"fixture-a","integration_key":"fixture-b","api_hostname":"api.example.com","type":"duo","use_passcode":true}}"#
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/identity/mfa/method/duo HTTP/1.1"));
                    r#"{"data":{"keys":["duo-id"]}}"#
                }
                3 => {
                    assert!(
                        request.starts_with("DELETE /v1/identity/mfa/method/duo/duo-id HTTP/1.1")
                    );
                    "{}"
                }
                4 => {
                    assert!(
                        request.starts_with("POST /v1/identity/mfa/method/okta/okta-id HTTP/1.1")
                    );
                    assert!(request.contains(r#""method_name":"okta-main""#));
                    assert!(request.contains(r#""api_token":"#));
                    "{}"
                }
                5 => {
                    assert!(
                        request.starts_with("GET /v1/identity/mfa/method/okta/okta-id HTTP/1.1")
                    );
                    r#"{"data":{"id":"okta-id","name":"okta-main","org_name":"dev-org","api_token":"fixture-c","type":"okta"}}"#
                }
                6 => {
                    assert!(request.starts_with("LIST /v1/identity/mfa/method/okta HTTP/1.1"));
                    r#"{"data":{"keys":["okta-id"]}}"#
                }
                7 => {
                    assert!(
                        request.starts_with("DELETE /v1/identity/mfa/method/okta/okta-id HTTP/1.1")
                    );
                    "{}"
                }
                8 => {
                    assert!(
                        request.starts_with("POST /v1/identity/mfa/method/pingid/ping-id HTTP/1.1")
                    );
                    assert!(request.contains(r#""method_name":"ping-main""#));
                    assert!(request.contains(r#""settings_file_base64":"#));
                    "{}"
                }
                9 => {
                    assert!(
                        request.starts_with("GET /v1/identity/mfa/method/pingid/ping-id HTTP/1.1")
                    );
                    r#"{"data":{"id":"ping-id","name":"ping-main","idp_url":"https://idp.example.com","admin_url":"https://admin.example.com","authenticator_url":"https://auth.example.com","org_alias":"org","use_signature":true,"type":"pingid"}}"#
                }
                10 => {
                    assert!(request.starts_with("LIST /v1/identity/mfa/method/pingid HTTP/1.1"));
                    r#"{"data":{"keys":["ping-id"]}}"#
                }
                11 => {
                    assert!(
                        request
                            .starts_with("DELETE /v1/identity/mfa/method/pingid/ping-id HTTP/1.1")
                    );
                    "{}"
                }
                12 => {
                    assert!(
                        request.starts_with("POST /v1/identity/mfa/method/totp/totp-id HTTP/1.1")
                    );
                    assert!(request.contains(r#""method_name":"totp-main""#));
                    assert!(request.contains(r#""issuer":"openbao""#));
                    "{}"
                }
                13 => {
                    assert!(
                        request.starts_with("GET /v1/identity/mfa/method/totp/totp-id HTTP/1.1")
                    );
                    r#"{"data":{"id":"totp-id","name":"totp-main","issuer":"openbao","period":30,"digits":6,"type":"totp"}}"#
                }
                14 => {
                    assert!(request.starts_with("LIST /v1/identity/mfa/method/totp HTTP/1.1"));
                    r#"{"data":{"keys":["totp-id"]}}"#
                }
                15 => {
                    assert!(
                        request.starts_with("POST /v1/identity/mfa/method/totp/generate HTTP/1.1")
                    );
                    assert!(request.contains(r#""method_id":"totp-id""#));
                    r#"{"data":{"barcode":"fixture-d","url":"otpauth://totp/example"}}"#
                }
                16 => {
                    assert!(
                        request.starts_with(
                            "POST /v1/identity/mfa/method/totp/admin-generate HTTP/1.1"
                        )
                    );
                    assert!(request.contains(r#""entity_id":"entity-id""#));
                    r#"{"data":{"barcode":"fixture-e","url":"otpauth://totp/admin"}}"#
                }
                17 => {
                    assert!(
                        request.starts_with(
                            "POST /v1/identity/mfa/method/totp/admin-destroy HTTP/1.1"
                        )
                    );
                    assert!(request.contains(r#""entity_id":"entity-id""#));
                    "{}"
                }
                18 => {
                    assert!(
                        request.starts_with("DELETE /v1/identity/mfa/method/totp/totp-id HTTP/1.1")
                    );
                    "{}"
                }
                19 => {
                    assert!(
                        request.starts_with("POST /v1/identity/mfa/login-enforcement/app HTTP/1.1")
                    );
                    assert!(request.contains(r#""mfa_method_ids":["totp-id"]"#));
                    assert!(request.contains(r#""auth_method_accessors":["auth-userpass"]"#));
                    "{}"
                }
                20 => {
                    assert!(
                        request.starts_with("GET /v1/identity/mfa/login-enforcement/app HTTP/1.1")
                    );
                    r#"{"data":{"id":"enforcement-id","name":"app","namespace_id":"root","mfa_method_ids":["totp-id"],"auth_method_accessors":["auth-userpass"],"auth_method_types":[],"identity_group_ids":[],"identity_entity_ids":[]}}"#
                }
                21 => {
                    assert!(
                        request.starts_with("LIST /v1/identity/mfa/login-enforcement HTTP/1.1")
                    );
                    r#"{"data":{"keys":["app"]}}"#
                }
                22 => {
                    assert!(
                        request
                            .starts_with("DELETE /v1/identity/mfa/login-enforcement/app HTTP/1.1")
                    );
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let identity = client.identity().unwrap_or_else(|error| panic!("{error}"));
    use openbao::secrets::identity::{
        IdentityMfaDuoMethodRequest, IdentityMfaLoginEnforcementRequest,
        IdentityMfaOktaMethodRequest, IdentityMfaPingIdMethodRequest, IdentityMfaTotpAdminRequest,
        IdentityMfaTotpGenerateRequest, IdentityMfaTotpMethodRequest,
    };

    identity
        .write_mfa_duo_method(
            "duo-id",
            &IdentityMfaDuoMethodRequest::new(
                "duo-main",
                test_secret(&["fixture-", "duo-a"]),
                test_secret(&["fixture-", "duo-b"]),
                "api.example.com",
            )
            .with_use_passcode(true),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let duo = identity
        .read_mfa_duo_method("duo-id")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(duo.method_name.as_deref(), Some("duo-main"));
    assert_eq!(
        identity
            .list_mfa_duo_methods()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["duo-id"]
    );
    identity
        .delete_mfa_duo_method("duo-id")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    identity
        .write_mfa_okta_method(
            "okta-id",
            &IdentityMfaOktaMethodRequest::new(
                "okta-main",
                "dev-org",
                test_secret(&["fixture-", "okta"]),
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let okta = identity
        .read_mfa_okta_method("okta-id")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(okta.method_name.as_deref(), Some("okta-main"));
    assert_eq!(
        identity
            .list_mfa_okta_methods()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["okta-id"]
    );
    identity
        .delete_mfa_okta_method("okta-id")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    identity
        .write_mfa_pingid_method(
            "ping-id",
            &IdentityMfaPingIdMethodRequest::new("ping-main", test_secret(&["fixture-", "ping"])),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let ping = identity
        .read_mfa_pingid_method("ping-id")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(ping.method_name.as_deref(), Some("ping-main"));
    assert_eq!(
        identity
            .list_mfa_pingid_methods()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["ping-id"]
    );
    identity
        .delete_mfa_pingid_method("ping-id")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    identity
        .write_mfa_totp_method(
            "totp-id",
            &IdentityMfaTotpMethodRequest::new("totp-main").with_issuer("openbao"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let totp = identity
        .read_mfa_totp_method("totp-id")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(totp.method_name.as_deref(), Some("totp-main"));
    assert_eq!(
        identity
            .list_mfa_totp_methods()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["totp-id"]
    );
    let generated = identity
        .generate_mfa_totp_secret(&IdentityMfaTotpGenerateRequest::new("totp-id"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(format!("{generated:?}").contains("<redacted>"));
    let admin_request = IdentityMfaTotpAdminRequest::new("totp-id", "entity-id");
    identity
        .admin_generate_mfa_totp_secret(&admin_request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    identity
        .admin_destroy_mfa_totp_secret(&admin_request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    identity
        .delete_mfa_totp_method("totp-id")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    identity
        .write_mfa_login_enforcement(
            "app",
            &IdentityMfaLoginEnforcementRequest::new()
                .with_mfa_method_id("totp-id")
                .with_auth_method_accessor("auth-userpass"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let enforcement = identity
        .read_mfa_login_enforcement("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(enforcement.mfa_method_ids, ["totp-id"]);
    assert_eq!(
        identity
            .list_mfa_login_enforcements()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["app"]
    );
    identity
        .delete_mfa_login_enforcement("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn ldap_config_roles_credentials_and_library_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let bindpass = ["bind", "-", "password"].concat();
        let static_password = ["static", "-", "password"].concat();
        let dynamic_password = ["dynamic", "-", "password"].concat();
        let checkout_password = ["checkout", "-", "password"].concat();

        for step in 0..18 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/ldap/config HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(
                        request.contains(r#""binddn":"cn=openbao,ou=Users,dc=example,dc=com""#)
                    );
                    assert!(request.contains(&format!(r#""bindpass":"{bindpass}""#)));
                    assert!(request.contains(r#""url":"ldaps://ldap.example.com:636""#));
                    "{}".to_owned()
                }
                1 => {
                    assert!(request.starts_with("GET /v1/ldap/config HTTP/1.1"));
                    format!(
                        r#"{{"data":{{"binddn":"cn=openbao,ou=Users,dc=example,dc=com","bindpass":"{bindpass}","url":"ldaps://ldap.example.com:636","schema":"openldap","connection_timeout":30,"request_timeout":"90s"}}}}"#
                    )
                }
                2 => {
                    assert!(request.starts_with("POST /v1/ldap/rotate-root HTTP/1.1"));
                    "{}".to_owned()
                }
                3 => {
                    assert!(request.starts_with("POST /v1/ldap/static-role/app HTTP/1.1"));
                    assert!(request.contains(r#""username":"app-user""#));
                    assert!(request.contains(r#""rotation_period":"24h""#));
                    "{}".to_owned()
                }
                4 => {
                    assert!(request.starts_with("GET /v1/ldap/static-role/app HTTP/1.1"));
                    r#"{"data":{"username":"app-user","dn":"uid=app-user,ou=Users,dc=example,dc=com","rotation_period":86400,"last_vault_rotation":"2026-06-01T00:00:00Z"}}"#
                        .to_owned()
                }
                5 => {
                    assert!(request.starts_with("LIST /v1/ldap/static-role HTTP/1.1"));
                    r#"{"data":{"keys":["app"]}}"#.to_owned()
                }
                6 => {
                    assert!(request.starts_with("GET /v1/ldap/static-cred/app HTTP/1.1"));
                    format!(
                        r#"{{"data":{{"username":"app-user","dn":"uid=app-user,ou=Users,dc=example,dc=com","password":"{static_password}","rotation_period":86400,"ttl":300}}}}"#
                    )
                }
                7 => {
                    assert!(request.starts_with("POST /v1/ldap/rotate-role/app HTTP/1.1"));
                    "{}".to_owned()
                }
                8 => {
                    assert!(request.starts_with("POST /v1/ldap/role/dynamic HTTP/1.1"));
                    assert!(request.contains(
                        r#""creation_ldif":"dn: cn={{.Username}},ou=Users,dc=example,dc=com""#
                    ));
                    assert!(request.contains(r#""default_ttl":"1h""#));
                    "{}".to_owned()
                }
                9 => {
                    assert!(request.starts_with("GET /v1/ldap/role/dynamic HTTP/1.1"));
                    r#"{"data":{"creation_ldif":"dn: cn={{.Username}},ou=Users,dc=example,dc=com","deletion_ldif":"dn: cn={{.Username}},ou=Users,dc=example,dc=com","rollback_ldif":"dn: cn={{.Username}},ou=Users,dc=example,dc=com","default_ttl":3600,"max_ttl":"24h"}}"#
                        .to_owned()
                }
                10 => {
                    assert!(request.starts_with("GET /v1/ldap/creds/dynamic HTTP/1.1"));
                    format!(
                        r#"{{"lease_id":"ldap/creds/dynamic/lease","lease_duration":3600,"renewable":true,"data":{{"username":"v-token-dynamic","password":"{dynamic_password}","distinguished_names":["cn=v-token-dynamic,ou=Users,dc=example,dc=com"]}}}}"#
                    )
                }
                11 => {
                    assert!(request.starts_with("POST /v1/ldap/library/accounts HTTP/1.1"));
                    assert!(request.contains(
                        r#""service_account_names":["svc-a@example.com","svc-b@example.com"]"#
                    ));
                    "{}".to_owned()
                }
                12 => {
                    assert!(request.starts_with("GET /v1/ldap/library/accounts HTTP/1.1"));
                    r#"{"data":{"service_account_names":["svc-a@example.com","svc-b@example.com"],"ttl":"10h","max_ttl":"20h","disable_check_in_enforcement":false}}"#
                        .to_owned()
                }
                13 => {
                    assert!(request.starts_with("LIST /v1/ldap/library HTTP/1.1"));
                    r#"{"data":{"keys":["accounts"]}}"#.to_owned()
                }
                14 => {
                    assert!(request.starts_with("GET /v1/ldap/library/accounts/status HTTP/1.1"));
                    r#"{"data":{"service_account_names":{"svc-a@example.com":{"checked_out":false},"svc-b@example.com":{"checked_out":true,"borrower_entity_id":"entity-id-1"}}}}"#
                        .to_owned()
                }
                15 => {
                    assert!(
                        request.starts_with("POST /v1/ldap/library/accounts/check-out HTTP/1.1")
                    );
                    assert!(request.contains(r#""ttl":"1h""#));
                    format!(
                        r#"{{"lease_id":"ldap/library/accounts/check-out/lease","lease_duration":3600,"renewable":true,"data":{{"service_account_name":"svc-a@example.com","password":"{checkout_password}"}}}}"#
                    )
                }
                16 => {
                    assert!(
                        request.starts_with("POST /v1/ldap/library/accounts/check-in HTTP/1.1")
                    );
                    assert!(request.contains(r#""service_account_names":["svc-a@example.com"]"#));
                    r#"{"data":{"check_ins":["svc-a@example.com"]}}"#.to_owned()
                }
                17 => {
                    assert!(
                        request
                            .starts_with("POST /v1/ldap/library/manage/accounts/check-in HTTP/1.1")
                    );
                    assert!(request.contains(r#""service_account_names":["svc-b@example.com"]"#));
                    r#"{"data":{"check_ins":["svc-b@example.com"]}}"#.to_owned()
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let ldap = client.ldap().unwrap_or_else(|error| panic!("{error}"));

    ldap.write_config(
        &openbao::secrets::ldap::LdapConfig::new(
            "cn=openbao,ou=Users,dc=example,dc=com",
            test_secret(&["bind", "-", "password"]),
        )
        .with_url("ldaps://ldap.example.com:636")
        .with_schema("openldap"),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let config = ldap
        .read_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(config.schema.as_deref(), Some("openldap"));
    ldap.rotate_root()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    ldap.write_static_role(
        "app",
        &openbao::secrets::ldap::LdapStaticRole {
            dn: Some("uid=app-user,ou=Users,dc=example,dc=com".to_owned()),
            ..openbao::secrets::ldap::LdapStaticRole::new("app-user")
                .with_rotation_period("24h")
                .unwrap_or_else(|error| panic!("{error}"))
        },
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let static_role = ldap
        .read_static_role("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(static_role.username, "app-user");
    let static_roles = ldap
        .list_static_roles()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(static_roles.keys, ["app"]);
    let static_creds = ldap
        .static_credentials("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        static_creds.password.expose_secret(),
        test_secret(&["static", "-", "password"]).expose_secret()
    );
    ldap.rotate_static_role("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    ldap.write_dynamic_role(
        "dynamic",
        &openbao::secrets::ldap::LdapDynamicRole::new(
            "dn: cn={{.Username}},ou=Users,dc=example,dc=com",
            "dn: cn={{.Username}},ou=Users,dc=example,dc=com",
        )
        .with_default_ttl("1h")
        .unwrap_or_else(|error| panic!("{error}")),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let dynamic_role = ldap
        .read_dynamic_role("dynamic")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(dynamic_role.default_ttl.as_deref(), Some("3600"));
    let dynamic_creds = ldap
        .dynamic_credentials("dynamic")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        dynamic_creds.password.expose_secret(),
        test_secret(&["dynamic", "-", "password"]).expose_secret()
    );

    ldap.write_library_set(
        "accounts",
        &openbao::secrets::ldap::LdapLibrarySet::new(["svc-a@example.com", "svc-b@example.com"])
            .with_ttl("10h")
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let library = ldap
        .read_library_set("accounts")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(library.service_account_names.len(), 2);
    let libraries = ldap
        .list_library_sets()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(libraries.keys, ["accounts"]);
    let status = ldap
        .library_status("accounts")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        status
            .service_account_names
            .contains_key("svc-a@example.com")
    );

    let checkout = ldap
        .check_out(
            "accounts",
            &openbao::secrets::ldap::LdapCheckOutRequest::new()
                .with_ttl("1h")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        checkout.password.expose_secret(),
        test_secret(&["checkout", "-", "password"]).expose_secret()
    );
    let check_in = ldap
        .check_in(
            "accounts",
            &openbao::secrets::ldap::LdapCheckInRequest::new(["svc-a@example.com"]),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(check_in.check_ins, ["svc-a@example.com"]);
    let force_check_in = ldap
        .force_check_in(
            "accounts",
            &openbao::secrets::ldap::LdapCheckInRequest::new(["svc-b@example.com"]),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(force_check_in.check_ins, ["svc-b@example.com"]);

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
                    r#"{"sealed":false,"n":1,"t":1,"progress":0,"version":"2.5.5"}"#
                }
                3 => {
                    assert!(request.starts_with("GET /v1/sys/health HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    r#"{"initialized":true,"sealed":false,"standby":false,"version":"2.5.5"}"#
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
        .and_then(allow_mock_http)
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        .and_then(allow_mock_http)
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
async fn kubernetes_secrets_config_role_and_creds_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..8 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let (status, body) = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/kubernetes/config HTTP/1.1"));
                    assert!(request.contains(r#""service_account_jwt":"manager-jwt""#));
                    ("204 No Content", "{}".to_owned())
                }
                1 => {
                    assert!(request.starts_with("GET /v1/kubernetes/config HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"kubernetes_host":"https://kubernetes.default.svc","kubernetes_ca_cert":"pem","disable_local_ca_jwt":true}}"#
                            .to_owned(),
                    )
                }
                2 => {
                    assert!(request.starts_with("POST /v1/kubernetes/roles/web HTTP/1.1"));
                    assert!(request.contains(r#""allowed_kubernetes_namespaces":["prod"]"#));
                    assert!(request.contains(r#""service_account_name":"default""#));
                    assert!(request.contains(r#""token_default_ttl":"30m""#));
                    ("204 No Content", "{}".to_owned())
                }
                3 => {
                    assert!(request.starts_with("GET /v1/kubernetes/roles/web HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"name":"web","allowed_kubernetes_namespaces":["prod"],"service_account_name":"default","token_default_ttl":1800,"token_max_ttl":"24h"}}"#
                            .to_owned(),
                    )
                }
                4 => {
                    assert!(
                        request.starts_with("LIST /v1/kubernetes/roles?after=w&limit=10 HTTP/1.1")
                    );
                    ("200 OK", r#"{"data":{"keys":["web"]}}"#.to_owned())
                }
                5 => {
                    assert!(request.starts_with("POST /v1/kubernetes/creds/web HTTP/1.1"));
                    assert!(request.contains(r#""kubernetes_namespace":"prod""#));
                    assert!(request.contains(r#""ttl":"15m""#));
                    (
                        "200 OK",
                        format!(
                            r#"{{"lease_id":"{}","lease_duration":900,"renewable":false,"data":{{"service_account_name":"default","service_account_namespace":"prod","service_account_token":"{}{}"}}}}"#,
                            "kubernetes/creds/web/lease", "service-", "account-token"
                        ),
                    )
                }
                6 => {
                    assert!(request.starts_with("DELETE /v1/kubernetes/roles/web HTTP/1.1"));
                    ("204 No Content", "{}".to_owned())
                }
                7 => {
                    assert!(request.starts_with("DELETE /v1/kubernetes/config HTTP/1.1"));
                    ("204 No Content", "{}".to_owned())
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let kubernetes = client
        .kubernetes_secrets()
        .unwrap_or_else(|error| panic!("{error}"));

    kubernetes
        .write_config(&openbao::secrets::kubernetes::KubernetesSecretsConfig {
            kubernetes_host: Some("https://kubernetes.default.svc".to_owned()),
            service_account_jwt: Some(test_secret(&["manager-", "jwt"])),
            disable_local_ca_jwt: Some(true),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let config = kubernetes
        .read_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        config.kubernetes_host.as_deref(),
        Some("https://kubernetes.default.svc")
    );
    assert!(!format!("{config:?}").contains("manager-jwt"));

    let role = openbao::secrets::kubernetes::KubernetesSecretsRole::for_service_account("default")
        .with_allowed_namespace("prod")
        .with_token_default_ttl("30m")
        .unwrap_or_else(|error| panic!("{error}"));
    kubernetes
        .write_role("web", &role)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let role = kubernetes
        .read_role("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(role.name.as_deref(), Some("web"));
    assert_eq!(role.token_default_ttl.as_deref(), Some("1800"));
    let roles = kubernetes
        .list_roles_after(Some("w"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["web"]);

    let request = openbao::secrets::kubernetes::KubernetesCredentialsRequest::new()
        .with_namespace("prod")
        .with_ttl("15m")
        .unwrap_or_else(|error| panic!("{error}"));
    let credentials = kubernetes
        .credentials("web", &request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(credentials.service_account_namespace, "prod");
    assert_eq!(
        credentials.service_account_token.expose_secret(),
        &["service-", "account-token"].concat()
    );
    let debug = format!("{credentials:?}");
    assert!(!debug.contains(&["service-", "account-token"].concat()));
    assert!(!debug.contains("kubernetes/creds/web/lease"));

    kubernetes
        .delete_role("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    kubernetes
        .delete_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn jwt_login_sends_documented_path_and_secret_jwt() {
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
        assert!(request.starts_with("POST /v1/auth/jwt/login HTTP/1.1"));
        assert!(request.contains(r#""role":"web""#));
        assert!(request.contains(r#""jwt":"signed-jwt""#));
        let body = r#"{"auth":{"client_token":"jwt-token","accessor":"jwt-accessor","policies":["default"],"metadata":{"role":"web"},"lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let (client, login) = client
        .login_jwt(Some("web"), SecretString::from("signed-jwt"))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(login.accessor.expose_secret(), "jwt-accessor");
    assert_eq!(
        login.metadata.get("role").map(SecretString::expose_secret),
        Some("web")
    );
    assert_eq!(client.base_url().as_str(), format!("http://{addr}/"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "oidc-get-callback-acknowledged")]
#[tokio::test]
async fn acknowledged_oidc_callback_uses_documented_sensitive_query_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with(
            "GET /v1/auth/jwt/oidc/callback?state=session%2Fstate&code=authorization-code&client_nonce=session-nonce HTTP/1.1"
        ));
        let body = r#"{"auth":{"client_token":"oidc-token","accessor":"oidc-accessor","policies":["default"],"lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));
    let jwt = client.jwt().unwrap_or_else(|error| panic!("{error}"));
    let callback = openbao::auth::jwt::OidcCallbackRequest::with_code(
        "session/state",
        SecretString::from("authorization-code"),
    )
    .with_client_nonce("session-nonce");

    let (_client, login) = jwt
        .oidc_callback(&callback)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(login.accessor.expose_secret(), "oidc-accessor");

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn jwt_admin_config_and_role_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..5 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 4096];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/auth/jwt/config HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""jwks_url":"https://issuer.example/jwks.json""#));
                    assert!(request.contains(r#""oidc_client_secret":"client-secret""#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("GET /v1/auth/jwt/config HTTP/1.1"));
                    r#"{"data":{"jwks_url":"https://issuer.example/jwks.json","bound_issuer":"https://issuer.example"}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/auth/jwt/role/web HTTP/1.1"));
                    assert!(request.contains(r#""role_type":"jwt""#));
                    assert!(request.contains(r#""bound_audiences":["openbao"]"#));
                    assert!(request.contains(r#""user_claim":"sub""#));
                    assert!(request.contains(r#""token_policies":["web"]"#));
                    "{}"
                }
                3 => {
                    assert!(request.starts_with("LIST /v1/auth/jwt/role HTTP/1.1"));
                    r#"{"data":{"keys":["web"]}}"#
                }
                4 => {
                    assert!(request.starts_with("DELETE /v1/auth/jwt/role/web HTTP/1.1"));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let admin = client.jwt_admin().unwrap_or_else(|error| panic!("{error}"));

    admin
        .configure(&openbao::auth::jwt::JwtConfig {
            jwks_url: Some("https://issuer.example/jwks.json".to_owned()),
            bound_issuer: Some("https://issuer.example".to_owned()),
            oidc_client_secret: Some(SecretString::from("client-secret")),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let config = admin
        .read_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        config.bound_issuer.as_deref(),
        Some("https://issuer.example")
    );
    admin
        .write_role(
            "web",
            &openbao::auth::jwt::JwtRole {
                role_type: Some("jwt".to_owned()),
                bound_audiences: vec!["openbao".to_owned()],
                token_policies: vec!["web".to_owned()],
                ..openbao::auth::jwt::JwtRole::new("sub")
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let roles = admin
        .list_roles()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["web"]);
    admin
        .delete_role("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let (client, login) = client
        .login_userpass("alice", test_secret(&["p", "-value"]))
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
        .and_then(allow_mock_http)
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
            &openbao::auth::userpass::UserpassUserRequest::new(test_secret(&["p", "-value"]))
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
        .update_password("alice", &test_secret(&["new", "-p", "-value"]))
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
async fn radius_login_sends_documented_path_and_secret_password() {
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
        assert!(request.starts_with("POST /v1/auth/radius/login/alice HTTP/1.1"));
        assert!(request.contains(r#""password":"p-value""#));
        let body = r#"{"auth":{"client_token":"radius-token","accessor":"radius-accessor","policies":["default"],"metadata":{"username":"alice"},"lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let (client, login) = client
        .login_radius("alice", test_secret(&["p", "-value"]))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(login.accessor.expose_secret(), "radius-accessor");
    assert_eq!(
        login.metadata.get("username").map(String::as_str),
        Some("alice")
    );
    assert_eq!(client.base_url().as_str(), format!("http://{addr}/"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn radius_admin_config_and_user_lifecycle_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..5 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body =
                match step {
                    0 => {
                        assert!(request.starts_with("POST /v1/auth/radius/config HTTP/1.1"));
                        assert!(request.contains("x-vault-token: root-token"));
                        assert!(request.contains(r#""host":"radius.example.com""#));
                        assert!(request.contains(r#""secret":"shared-secret""#));
                        assert!(request.contains(r#""port":1812"#));
                        assert!(request.contains(r#""token_policies":["web"]"#));
                        "{}"
                    }
                    1 => {
                        assert!(request.starts_with("POST /v1/auth/radius/users/alice HTTP/1.1"));
                        assert!(request.contains(r#""policies":"dev,prod""#));
                        "{}"
                    }
                    2 => {
                        assert!(request.starts_with("GET /v1/auth/radius/users/alice HTTP/1.1"));
                        r#"{"data":{"policies":"dev,prod"}}"#
                    }
                    3 => {
                        assert!(request.starts_with(
                            "LIST /v1/auth/radius/users?after=alice&limit=10 HTTP/1.1"
                        ));
                        r#"{"data":{"keys":["bob"]}}"#
                    }
                    4 => {
                        assert!(request.starts_with("DELETE /v1/auth/radius/users/alice HTTP/1.1"));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let admin = client
        .radius_admin()
        .unwrap_or_else(|error| panic!("{error}"));

    admin
        .configure(
            &openbao::auth::radius::RadiusConfig::new(
                "radius.example.com",
                test_secret(&["shared", "-secret"]),
            )
            .with_port(1812)
            .with_token_policy("web"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .write_user(
            "alice",
            &openbao::auth::radius::RadiusUserRequest::new("dev").with_policy("prod"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let user = admin
        .read_user("alice")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(user.policies, "dev,prod");
    let users = admin
        .list_users_page(Some("alice"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(users.keys, ["bob"]);
    admin
        .delete_user("alice")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn ldap_auth_login_sends_documented_path_and_secret_password() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("POST /v1/auth/ldap/login/alice HTTP/1.1"));
        assert!(request.contains(r#""password":"p-value""#));
        let body = r#"{"auth":{"client_token":"ldap-token","accessor":"ldap-accessor","policies":["default"],"metadata":{"username":"alice"},"lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let (client, login) = client
        .login_ldap("alice", test_secret(&["p", "-value"]))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        login.accessor.as_ref().map(SecretString::expose_secret),
        Some("ldap-accessor")
    );
    assert_eq!(
        login.metadata.get("username").map(String::as_str),
        Some("alice")
    );
    assert_eq!(client.base_url().as_str(), format!("http://{addr}/"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn ldap_auth_admin_config_group_and_user_lifecycle_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..10 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/auth/ldap/config HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""url":"ldaps://ldap.example.com:636""#));
                    assert!(request.contains(r#""binddn":"cn=openbao,dc=example,dc=com""#));
                    assert!(request.contains(r#""bindpass":"bind-pass""#));
                    assert!(request.contains(r#""token_policies":["web"]"#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("GET /v1/auth/ldap/config HTTP/1.1"));
                    r#"{"data":{"url":"ldaps://ldap.example.com:636","binddn":"cn=openbao,dc=example,dc=com","bindpass":"","connection_timeout":30,"tls_min_version":"tls12"}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/auth/ldap/groups/admins HTTP/1.1"));
                    assert!(request.contains(r#""policies":"admin,default""#));
                    "{}"
                }
                3 => {
                    assert!(request.starts_with("GET /v1/auth/ldap/groups/admins HTTP/1.1"));
                    r#"{"data":{"policies":["admin","default"]}}"#
                }
                4 => {
                    assert!(request.starts_with("LIST /v1/auth/ldap/groups HTTP/1.1"));
                    r#"{"data":{"keys":["admins"]}}"#
                }
                5 => {
                    assert!(request.starts_with("POST /v1/auth/ldap/users/alice HTTP/1.1"));
                    assert!(request.contains(r#""policies":"dev""#));
                    assert!(request.contains(r#""groups":"admins""#));
                    "{}"
                }
                6 => {
                    assert!(request.starts_with("GET /v1/auth/ldap/users/alice HTTP/1.1"));
                    r#"{"data":{"policies":["dev"],"groups":"admins"}}"#
                }
                7 => {
                    assert!(request.starts_with("LIST /v1/auth/ldap/users HTTP/1.1"));
                    r#"{"data":{"keys":["alice"]}}"#
                }
                8 => {
                    assert!(request.starts_with("DELETE /v1/auth/ldap/users/alice HTTP/1.1"));
                    "{}"
                }
                9 => {
                    assert!(request.starts_with("DELETE /v1/auth/ldap/groups/admins HTTP/1.1"));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let admin = client
        .ldap_auth_admin()
        .unwrap_or_else(|error| panic!("{error}"));

    admin
        .configure(
            &openbao::auth::ldap::LdapAuthConfig::new()
                .with_url("ldaps://ldap.example.com:636")
                .with_bind(
                    "cn=openbao,dc=example,dc=com",
                    test_secret(&["bind", "-pass"]),
                )
                .with_token_policy("web"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let config = admin
        .read_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(config.connection_timeout.as_deref(), Some("30"));

    admin
        .write_group(
            "admins",
            &openbao::auth::ldap::LdapAuthMappingRequest::new("admin").with_policy("default"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let group = admin
        .read_group("admins")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(group.policies, ["admin", "default"]);
    let groups = admin
        .list_groups()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(groups.keys, ["admins"]);

    admin
        .write_user(
            "alice",
            &openbao::auth::ldap::LdapAuthMappingRequest::new("dev").with_group("admins"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let user = admin
        .read_user("alice")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(user.policies, ["dev"]);
    assert_eq!(user.groups.as_deref(), Some("admins"));
    let users = admin
        .list_users()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(users.keys, ["alice"]);
    admin
        .delete_user("alice")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_group("admins")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn kerberos_auth_login_sends_documented_negotiate_header() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("POST /v1/auth/kerberos/login HTTP/1.1"));
        assert!(request.contains("authorization: Negotiate spnego-token"));
        let body = r#"{"auth":{"client_token":"kerberos-token","accessor":"kerberos-accessor","policies":["default"],"metadata":{"username":"alice"},"lease_duration":3600,"renewable":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

    let (client, login) = client
        .login_kerberos(test_secret(&["spnego", "-token"]))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        login.accessor.as_ref().map(SecretString::expose_secret),
        Some("kerberos-accessor")
    );
    assert_eq!(
        login.metadata.get("username").map(String::as_str),
        Some("alice")
    );
    assert_eq!(client.base_url().as_str(), format!("http://{addr}/"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn kerberos_auth_admin_config_ldap_and_group_lifecycle_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..8 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/auth/kerberos/config HTTP/1.1"));
                    assert!(request.contains("x-vault-token: root-token"));
                    assert!(request.contains(r#""keytab":"keytab-base64""#));
                    assert!(request.contains(r#""service_account":"openbao_svc""#));
                    "{}"
                }
                1 => {
                    assert!(request.starts_with("GET /v1/auth/kerberos/config HTTP/1.1"));
                    r#"{"data":{"service_account":"openbao_svc","remove_instance_name":false,"add_group_aliases":true}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/auth/kerberos/config/ldap HTTP/1.1"));
                    assert!(request.contains(r#""url":"ldaps://ldap.example.com:636""#));
                    assert!(request.contains(r#""binddn":"cn=openbao,dc=example,dc=com""#));
                    assert!(request.contains(r#""bindpass":"bind-pass""#));
                    assert!(request.contains(r#""token_policies":["web"]"#));
                    "{}"
                }
                3 => {
                    assert!(request.starts_with("GET /v1/auth/kerberos/config/ldap HTTP/1.1"));
                    r#"{"data":{"url":"ldaps://ldap.example.com:636","binddn":"cn=openbao,dc=example,dc=com","bindpass":"","token_ttl":30,"tls_min_version":"tls12"}}"#
                }
                4 => {
                    assert!(request.starts_with("POST /v1/auth/kerberos/groups/admins HTTP/1.1"));
                    assert!(request.contains(r#""policies":"admin,default""#));
                    "{}"
                }
                5 => {
                    assert!(request.starts_with("GET /v1/auth/kerberos/groups/admins HTTP/1.1"));
                    r#"{"data":{"policies":["admin","default"]}}"#
                }
                6 => {
                    assert!(request.starts_with(
                        "LIST /v1/auth/kerberos/groups?after=admins&limit=10 HTTP/1.1"
                    ));
                    r#"{"data":{"keys":["engineers"]}}"#
                }
                7 => {
                    assert!(request.starts_with("DELETE /v1/auth/kerberos/groups/admins HTTP/1.1"));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let admin = client
        .kerberos_auth_admin()
        .unwrap_or_else(|error| panic!("{error}"));

    admin
        .configure(
            &openbao::auth::kerberos::KerberosConfig::new(
                "openbao_svc",
                test_secret(&["keytab", "-base64"]),
            )
            .add_group_aliases(true),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let config = admin
        .read_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(config.service_account, "openbao_svc");
    assert!(config.keytab.is_none());

    admin
        .configure_ldap(
            &openbao::auth::kerberos::KerberosLdapConfig::new()
                .with_url("ldaps://ldap.example.com:636")
                .with_bind(
                    "cn=openbao,dc=example,dc=com",
                    test_secret(&["bind", "-pass"]),
                )
                .with_token_policy("web"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let ldap_config = admin
        .read_ldap_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(ldap_config.token_ttl.as_deref(), Some("30"));

    admin
        .write_group(
            "admins",
            &openbao::auth::kerberos::KerberosGroupRequest::new("admin").with_policy("default"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let group = admin
        .read_group("admins")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(group.policies, ["admin", "default"]);
    let groups = admin
        .list_groups_page(Some("admins"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(groups.keys, ["engineers"]);
    admin
        .delete_group("admins")
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
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
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
        .and_then(allow_mock_http)
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
        .and_then(allow_mock_http)
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
async fn pki_named_issuer_issue_and_sign_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..2 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/pki/issuer/root-x1/issue/web HTTP/1.1"));
                    assert!(request.contains(r#""common_name":"issuer-api.example.com""#));
                    r#"{"data":{"certificate":"issuer-issued-cert","serial_number":"01:04"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/pki/issuer/root-x1/sign/web HTTP/1.1"));
                    assert!(request.contains(r#""csr":"-----BEGIN CERTIFICATE REQUEST-----""#));
                    r#"{"data":{"certificate":"issuer-signed-cert","serial_number":"01:05"}}"#
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let issuer_issued = pki
        .issue_with_issuer(
            "root-x1",
            "web",
            &openbao::secrets::pki::PkiIssueRequest {
                common_name: "issuer-api.example.com".to_owned(),
                ttl: Some("24h".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer_issued.serial_number.as_deref(), Some("01:04"));

    let issuer_signed = pki
        .sign_with_issuer(
            "root-x1",
            "web",
            &openbao::secrets::pki::PkiSignRequest {
                csr: "-----BEGIN CERTIFICATE REQUEST-----".to_owned(),
                common_name: Some("issuer-api.example.com".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer_signed.serial_number.as_deref(), Some("01:05"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_named_issuer_issue_sign_validate_paths_before_request() {
    let config = OpenBaoConfig::new("http://127.0.0.1:9")
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let issue_error = match pki
        .issue_with_issuer("../issuer", "web", &Default::default())
        .await
    {
        Ok(_) => panic!("invalid issuer path unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(issue_error, Error::InvalidPath(_)));

    let sign_error = match pki
        .sign_with_issuer("root-x1", "../role", &Default::default())
        .await
    {
        Ok(_) => panic!("invalid role path unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(matches!(sign_error, Error::InvalidPath(_)));
}

#[tokio::test]
async fn transit_export_helpers_reject_zero_versions_before_request() {
    let config =
        OpenBaoConfig::new("https://127.0.0.1:9940").unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let transit = client
        .transit("transit")
        .unwrap_or_else(|error| panic!("{error}"));

    assert!(
        transit
            .byok_export("destination", "source", Some(0), None)
            .await
            .is_err()
    );
    assert!(
        transit
            .export_key(
                openbao::secrets::transit::TransitExportKeyType::EncryptionKey,
                "source",
                Some(0),
            )
            .await
            .is_err()
    );
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
        .and_then(allow_mock_http)
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
async fn pki_authority_lifecycle_extensions_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..5 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/pki/keys/generate/internal HTTP/1.1"));
                    assert!(request.contains(r#""key_name":"root-key-2026""#));
                    assert!(request.contains(r#""key_type":"rsa""#));
                    r#"{"data":{"key_id":"key-1","key_name":"root-key-2026","key_type":"rsa","key_bits":4096}}"#
                }
                1 => {
                    assert!(
                        request.starts_with("POST /v1/pki/issuers/generate/root/existing HTTP/1.1")
                    );
                    assert!(request.contains(r#""key_ref":"key-1""#));
                    assert!(request.contains(r#""issuer_name":"root-x1""#));
                    r#"{"data":{"certificate":"issuer-root-cert","issuer_id":"issuer-1","issuer_name":"root-x1","key_id":"key-1"}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/pki/root/rotate/internal HTTP/1.1"));
                    assert!(request.contains(r#""issuer_name":"next""#));
                    r#"{"data":{"certificate":"rotated-root-cert","issuer_id":"issuer-2","issuer_name":"next","key_id":"key-2"}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/pki/root/replace HTTP/1.1"));
                    assert!(request.contains(r#""default":"issuer-2""#));
                    r#"{"data":{"default":"issuer-2","default_follows_latest_issuer":false}}"#
                }
                4 => {
                    assert!(request.starts_with(
                        "POST /v1/pki/issuers/generate/intermediate/exported HTTP/1.1"
                    ));
                    assert!(request.contains(r#""common_name":"intermediate.example.com""#));
                    r#"{"data":{"csr":"issuer-intermediate-csr","private_key":"issuer-intermediate-key","private_key_type":"rsa","key_id":"key-3"}}"#
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let key = pki
        .generate_key(
            openbao::secrets::pki::PkiKeyGenerationType::Internal,
            &openbao::secrets::pki::PkiGenerateKeyRequest {
                key_name: Some("root-key-2026".to_owned()),
                key_type: Some("rsa".to_owned()),
                key_bits: Some(4096),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(key.key_id.as_deref(), Some("key-1"));
    assert_eq!(key.key_bits, Some(4096));

    let issuer_root = pki
        .generate_issuer_root(
            openbao::secrets::pki::PkiKeyGenerationType::Existing,
            &openbao::secrets::pki::PkiGenerateRootRequest {
                common_name: "root.example.com".to_owned(),
                issuer_name: Some("root-x1".to_owned()),
                key_ref: Some("key-1".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer_root.issuer_id.as_deref(), Some("issuer-1"));

    let rotated = pki
        .rotate_root(
            openbao::secrets::pki::PkiKeyGenerationType::Internal,
            &openbao::secrets::pki::PkiGenerateRootRequest {
                common_name: "rotated.example.com".to_owned(),
                issuer_name: Some("next".to_owned()),
                key_name: Some("rotated-root-key".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(rotated.issuer_name.as_deref(), Some("next"));

    let replaced = pki
        .replace_root(&openbao::secrets::pki::PkiIssuersConfig {
            default: Some("issuer-2".to_owned()),
            default_follows_latest_issuer: Some(false),
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(replaced.default.as_deref(), Some("issuer-2"));

    let intermediate = pki
        .generate_issuer_intermediate(
            openbao::secrets::pki::PkiKeyGenerationType::Exported,
            &openbao::secrets::pki::PkiGenerateIntermediateRequest {
                common_name: "intermediate.example.com".to_owned(),
                key_name: Some("intermediate-key".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(intermediate.csr.as_deref(), Some("issuer-intermediate-csr"));
    assert_eq!(
        intermediate
            .private_key
            .as_ref()
            .map(SecretString::expose_secret),
        Some("issuer-intermediate-key")
    );

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "operator-ops")]
#[tokio::test]
async fn pki_delete_root_is_operator_gated_and_uses_documented_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("DELETE /v1/pki/root HTTP/1.1"));
        assert!(request.contains("x-vault-token: root-token"));
        let body = "{}";
        let response = format!(
            "HTTP/1.1 204 No Content\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    pki.delete_root(openbao::secrets::pki::PkiRootDeletion::confirm())
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "operator-ops")]
#[tokio::test]
async fn pki_sign_verbatim_helpers_are_operator_gated_and_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..4 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/pki/sign-verbatim HTTP/1.1"));
                    assert!(request.contains(r#""csr":"-----BEGIN CERTIFICATE REQUEST-----""#));
                    r#"{"data":{"certificate":"verbatim-default","serial_number":"20:01"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/pki/sign-verbatim/web HTTP/1.1"));
                    r#"{"data":{"certificate":"verbatim-role","serial_number":"20:02"}}"#
                }
                2 => {
                    assert!(
                        request.starts_with("POST /v1/pki/issuer/root-x1/sign-verbatim HTTP/1.1")
                    );
                    r#"{"data":{"certificate":"verbatim-issuer","serial_number":"20:03"}}"#
                }
                3 => {
                    assert!(
                        request
                            .starts_with("POST /v1/pki/issuer/root-x1/sign-verbatim/web HTTP/1.1")
                    );
                    r#"{"data":{"certificate":"verbatim-issuer-role","serial_number":"20:04"}}"#
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));
    let request =
        openbao::secrets::pki::PkiSignVerbatimRequest::new("-----BEGIN CERTIFICATE REQUEST-----");

    let default = pki
        .sign_verbatim(&request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(default.serial_number.as_deref(), Some("20:01"));

    let role = pki
        .sign_verbatim_at_role("web", &request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(role.serial_number.as_deref(), Some("20:02"));

    let issuer = pki
        .sign_verbatim_with_issuer("root-x1", &request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer.serial_number.as_deref(), Some("20:03"));

    let issuer_role = pki
        .sign_verbatim_with_issuer_at_role("root-x1", "web", &request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer_role.serial_number.as_deref(), Some("20:04"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_default_issuer_and_key_config_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..4 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/pki/config/issuers HTTP/1.1"));
                    r#"{"data":{"default":"issuer-1","default_follows_latest_issuer":"false"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/pki/config/issuers HTTP/1.1"));
                    assert!(request.contains(r#""default":"issuer-2""#));
                    assert!(request.contains(r#""default_follows_latest_issuer":true"#));
                    "{}"
                }
                2 => {
                    assert!(request.starts_with("GET /v1/pki/config/keys HTTP/1.1"));
                    r#"{"data":{"default":"key-1"}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/pki/config/keys HTTP/1.1"));
                    assert!(request.contains(r#""default":"key-2""#));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let issuers = pki
        .read_issuers_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuers.default.as_deref(), Some("issuer-1"));
    assert_eq!(issuers.default_follows_latest_issuer, Some(false));
    pki.write_issuers_config(&openbao::secrets::pki::PkiIssuersConfig {
        default: Some("issuer-2".to_owned()),
        default_follows_latest_issuer: Some(true),
    })
    .await
    .unwrap_or_else(|error| panic!("{error}"));

    let keys = pki
        .read_keys_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(keys.default.as_deref(), Some("key-1"));
    pki.write_keys_config(&openbao::secrets::pki::PkiKeysConfig {
        default: Some("key-2".to_owned()),
    })
    .await
    .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_cluster_auto_tidy_and_revoke_with_key_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..5 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/pki/config/cluster HTTP/1.1"));
                    r#"{"data":{"path":"https://bao.example.com/v1/pki","aia_path":"https://aia.example.com/pki"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/pki/config/cluster HTTP/1.1"));
                    assert!(request.contains(r#""path":"https://bao.example.com/v1/pki""#));
                    "{}"
                }
                2 => {
                    assert!(request.starts_with("GET /v1/pki/config/auto-tidy HTTP/1.1"));
                    r#"{"data":{"enabled":true,"interval_duration":43200,"safety_buffer":259200,"pause_duration":"0s","page_size":50,"tidy_revoked_certs":true}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/pki/config/auto-tidy HTTP/1.1"));
                    assert!(request.contains(r#""enabled":true"#));
                    assert!(request.contains(r#""interval_duration":"12h""#));
                    "{}"
                }
                4 => {
                    assert!(request.starts_with("POST /v1/pki/revoke-with-key HTTP/1.1"));
                    assert!(request.contains(r#""serial_number":"01:02""#));
                    assert!(
                        request.contains(r#""private_key":"-----BEGIN TEST PRIVATE KEY-----""#)
                    );
                    r#"{"data":{"revocation_time":1893456001,"revocation_time_rfc3339":"2030-01-01T00:00:01Z"}}"#
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let cluster = pki
        .read_cluster_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        cluster.path.as_deref(),
        Some("https://bao.example.com/v1/pki")
    );

    pki.write_cluster_config(&openbao::secrets::pki::PkiClusterConfig {
        path: Some("https://bao.example.com/v1/pki".to_owned()),
        aia_path: Some("https://aia.example.com/pki".to_owned()),
    })
    .await
    .unwrap_or_else(|error| panic!("{error}"));

    let auto_tidy = pki
        .read_auto_tidy_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(auto_tidy.interval_duration.as_deref(), Some("43200"));
    assert_eq!(auto_tidy.safety_buffer.as_deref(), Some("259200"));

    pki.write_auto_tidy_config(&openbao::secrets::pki::PkiAutoTidyConfig {
        enabled: Some(true),
        interval_duration: Some("12h".to_owned()),
        safety_buffer: Some("72h".to_owned()),
        tidy_revoked_certs: Some(true),
        ..Default::default()
    })
    .await
    .unwrap_or_else(|error| panic!("{error}"));

    let revoked = pki
        .revoke_with_key(&openbao::secrets::pki::PkiRevokeWithKeyRequest::new(
            "01:02",
            SecretString::from("-----BEGIN TEST PRIVATE KEY-----"),
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(revoked.revocation_time, Some(1_893_456_001));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn pki_specialized_flows_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..13 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(
                        request
                            .starts_with("POST /v1/pki/issuer/root-x1/sign-intermediate HTTP/1.1")
                    );
                    assert!(request.contains(r#""csr":"intermediate-csr""#));
                    r#"{"data":{"certificate":"issuer-signed-intermediate","serial_number":"30:01"}}"#
                }
                1 => {
                    assert!(request.starts_with("POST /v1/pki/crl/rotate-delta HTTP/1.1"));
                    r#"{"data":{"success":true}}"#
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/pki/certs/revoked HTTP/1.1"));
                    r#"{"data":{"keys":["30:01"]}}"#
                }
                3 => {
                    assert!(request.starts_with("LIST /v1/pki/certs/revocation-queue HTTP/1.1"));
                    r#"{"data":{"keys":["30:02"],"key_info":{"30:02":1893456002}}}"#
                }
                4 => {
                    assert!(request.starts_with(
                        "LIST /v1/pki/certs/detailed?after=30%3A01&limit=10 HTTP/1.1"
                    ));
                    r#"{"data":{"keys":["30:03"],"key_info":{"30:03":1893456003}}}"#
                }
                5 => {
                    assert!(
                        request.starts_with("POST /v1/pki/issuer/root-x1/resign-crls HTTP/1.1")
                    );
                    r#"{"data":{"crl":"-----BEGIN X509 CRL-----","serial_number":"30:04"}}"#
                }
                6 => {
                    assert!(request.starts_with("POST /v1/pki/cel/roles/web-cel HTTP/1.1"));
                    assert!(request.contains(r#""expression":"subject.common_name.endsWith"#));
                    "{}"
                }
                7 => {
                    assert!(request.starts_with("GET /v1/pki/cel/roles/web-cel HTTP/1.1"));
                    r#"{"data":{"expression":"subject.common_name.endsWith(\".example.com\")","description":"web CEL role","issuer_ref":"root-x1"}}"#
                }
                8 => {
                    assert!(request.starts_with("LIST /v1/pki/cel/roles HTTP/1.1"));
                    r#"{"data":{"keys":["web-cel"]}}"#
                }
                9 => {
                    assert!(request.starts_with("PATCH /v1/pki/cel/roles/web-cel HTTP/1.1"));
                    assert!(request.contains("application/merge-patch+json"));
                    r#"{"data":{"expression":"subject.common_name.endsWith(\".example.com\")","description":"patched"}}"#
                }
                10 => {
                    assert!(request.starts_with("POST /v1/pki/cel/issue/web-cel HTTP/1.1"));
                    assert!(request.contains(r#""common_name":"api.example.com""#));
                    r#"{"data":{"certificate":"cel-issued","serial_number":"30:05"}}"#
                }
                11 => {
                    assert!(request.starts_with("POST /v1/pki/cel/sign/web-cel HTTP/1.1"));
                    assert!(request.contains(r#""csr":"-----BEGIN CERTIFICATE REQUEST-----""#));
                    r#"{"data":{"certificate":"cel-signed","serial_number":"30:06"}}"#
                }
                12 => {
                    assert!(request.starts_with("DELETE /v1/pki/cel/roles/web-cel HTTP/1.1"));
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let intermediate = pki
        .sign_intermediate_with_issuer(
            "root-x1",
            &openbao::secrets::pki::PkiSignIntermediateRequest {
                csr: "intermediate-csr".to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(intermediate.serial_number.as_deref(), Some("30:01"));

    assert!(
        pki.rotate_delta_crl()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .success
    );
    assert_eq!(
        pki.list_revoked_certificates()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["30:01"]
    );
    assert_eq!(
        pki.list_revocation_queue()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["30:02"]
    );
    assert_eq!(
        pki.list_certificates_detailed(Some("30:01"), Some(10))
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["30:03"]
    );
    assert_eq!(
        pki.resign_crls("root-x1")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .serial_number
            .as_deref(),
        Some("30:04")
    );

    let cel_role = openbao::secrets::pki::PkiCelRoleRequest {
        expression: Some("subject.common_name.endsWith(\".example.com\")".to_owned()),
        description: Some("web CEL role".to_owned()),
    };
    pki.write_cel_role("web-cel", &cel_role)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let read = pki
        .read_cel_role("web-cel")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        read.extra
            .get("issuer_ref")
            .and_then(|value| value.as_str()),
        Some("root-x1")
    );
    assert_eq!(
        pki.list_cel_roles()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .keys,
        ["web-cel"]
    );
    assert_eq!(
        pki.patch_cel_role(
            "web-cel",
            &openbao::secrets::pki::PkiCelRoleRequest {
                description: Some("patched".to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .description
        .as_deref(),
        Some("patched")
    );
    assert_eq!(
        pki.cel_issue(
            "web-cel",
            &openbao::secrets::pki::PkiIssueRequest::new("api.example.com"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .serial_number
        .as_deref(),
        Some("30:05")
    );
    assert_eq!(
        pki.cel_sign(
            "web-cel",
            &openbao::secrets::pki::PkiSignRequest {
                csr: "-----BEGIN CERTIFICATE REQUEST-----".to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .serial_number
        .as_deref(),
        Some("30:06")
    );
    pki.delete_cel_role("web-cel")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "operator-ops")]
#[tokio::test]
async fn pki_specialized_operator_flows_are_gated_and_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..4 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("POST /v1/pki/root/sign-self-issued HTTP/1.1"));
                    assert!(request.contains(r#""certificate":"self-issued-cert""#));
                    r#"{"data":{"certificate":"signed-self-issued","serial_number":"31:01"}}"#
                }
                1 => {
                    assert!(
                        request
                            .starts_with("POST /v1/pki/issuer/root-x1/sign-self-issued HTTP/1.1")
                    );
                    r#"{"data":{"certificate":"issuer-signed-self-issued","serial_number":"31:02"}}"#
                }
                2 => {
                    assert!(request.starts_with("POST /v1/pki/intermediate/cross-sign HTTP/1.1"));
                    assert!(request.contains(r#""csr":"cross-sign-csr""#));
                    r#"{"data":{"certificate":"cross-signed","serial_number":"31:03"}}"#
                }
                3 => {
                    assert!(
                        request.starts_with(
                            "POST /v1/pki/issuer/root-x1/sign-revocation-list HTTP/1.1"
                        )
                    );
                    assert!(request.contains(r#""serial_number":"31:03""#));
                    r#"{"data":{"crl":"-----BEGIN X509 CRL-----","serial_number":"31:04"}}"#
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

    let self_issued = openbao::secrets::pki::PkiSignSelfIssuedRequest {
        certificate: "self-issued-cert".to_owned(),
        issuer_name: Some("self-issued".to_owned()),
    };
    assert_eq!(
        pki.sign_self_issued(&self_issued)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .serial_number
            .as_deref(),
        Some("31:01")
    );
    assert_eq!(
        pki.sign_self_issued_with_issuer("root-x1", &self_issued)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .serial_number
            .as_deref(),
        Some("31:02")
    );

    assert_eq!(
        pki.cross_sign_intermediate(&openbao::secrets::pki::PkiSignIntermediateRequest {
            csr: "cross-sign-csr".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .serial_number
        .as_deref(),
        Some("31:03")
    );

    assert_eq!(
        pki.sign_revocation_list(
            "root-x1",
            &openbao::secrets::pki::PkiSignRevocationListRequest {
                crl_number: Some(7),
                revoked_certs: vec![openbao::secrets::pki::PkiRevokedCertificateEntry {
                    serial_number: "31:03".to_owned(),
                    revocation_time: 1_893_456_031,
                }],
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .serial_number
        .as_deref(),
        Some("31:04")
    );

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
        .and_then(allow_mock_http)
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
async fn approle_admin_role_and_secret_id_lifecycle_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..14 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let (status, body) = if request.starts_with("LIST /v1/auth/approle/role HTTP/1.1") {
                ("200 OK", r#"{"data":{"keys":["web"]}}"#.to_owned())
            } else if request.starts_with("POST /v1/auth/approle/role/web/role-id HTTP/1.1") {
                (
                    "200 OK",
                    format!(r#"{{"data":{{"role_id":"{}{}"}}}}"#, "custom-", "role"),
                )
            } else if request.starts_with("GET /v1/auth/approle/role/web/role-id HTTP/1.1") {
                (
                    "200 OK",
                    format!(r#"{{"data":{{"role_id":"{}{}"}}}}"#, "role-", "id"),
                )
            } else if request
                .starts_with("POST /v1/auth/approle/role/web/secret-id/lookup HTTP/1.1")
            {
                (
                    "200 OK",
                    format!(
                        r#"{{"data":{{"cidr_list":[],"metadata":{{"env":"dev"}},"secret_id_accessor":"{}{}","secret_id_num_uses":1,"secret_id_ttl":600,"token_bound_cidrs":[]}}}}"#,
                        "accessor-", "id"
                    ),
                )
            } else if request
                .starts_with("POST /v1/auth/approle/role/web/secret-id/destroy HTTP/1.1")
            {
                ("200 OK", "{}".to_owned())
            } else if request.starts_with("LIST /v1/auth/approle/role/web/secret-id HTTP/1.1") {
                (
                    "200 OK",
                    format!(r#"{{"data":{{"keys":["{}{}"]}}}}"#, "accessor-", "id"),
                )
            } else if request
                .starts_with("POST /v1/auth/approle/role/web/secret-id-accessor/lookup HTTP/1.1")
            {
                (
                    "200 OK",
                    format!(
                        r#"{{"data":{{"metadata":{{}},"secret_id_accessor":"{}{}","secret_id_num_uses":1,"secret_id_ttl":600}}}}"#,
                        "accessor-", "id"
                    ),
                )
            } else if request
                .starts_with("POST /v1/auth/approle/role/web/secret-id-accessor/destroy HTTP/1.1")
            {
                ("200 OK", "{}".to_owned())
            } else if request
                .starts_with("POST /v1/auth/approle/role/web/custom-secret-id HTTP/1.1")
            {
                (
                    "200 OK",
                    format!(
                        r#"{{"data":{{"secret_id":"{}{}","secret_id_accessor":"{}{}","secret_id_ttl":0,"secret_id_num_uses":0}}}}"#,
                        "custom-", "secret", "custom-", "accessor"
                    ),
                )
            } else if request.starts_with("POST /v1/auth/approle/tidy/secret-id HTTP/1.1") {
                ("200 OK", r#"{"warnings":["tidy started"]}"#.to_owned())
            } else if request.starts_with("DELETE /v1/auth/approle/role/web HTTP/1.1") {
                ("200 OK", "{}".to_owned())
            } else if request.starts_with("POST /v1/auth/approle/role/web/secret-id HTTP/1.1") {
                (
                    "200 OK",
                    format!(
                        r#"{{"data":{{"secret_id":"{}{}","secret_id_accessor":"{}{}","secret_id_ttl":600,"secret_id_num_uses":1}}}}"#,
                        "secret-", "id", "accessor-", "id"
                    ),
                )
            } else if request.starts_with("POST /v1/auth/approle/role/web HTTP/1.1") {
                ("200 OK", "{}".to_owned())
            } else if request.starts_with("GET /v1/auth/approle/role/web HTTP/1.1") {
                (
                    "200 OK",
                    r#"{"data":{"token_ttl":600,"token_policies":["web"],"bind_secret_id":true}}"#
                        .to_owned(),
                )
            } else {
                let summary = request.lines().next().unwrap_or("unknown request");
                (
                    "500 Internal Server Error",
                    format!(r#"{{"errors":["unexpected request: {summary}"]}}"#),
                )
            };
            requests.push(request);
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
        requests
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .and_then(|client| client.try_with_token(test_secret(&["root-", "token"])))
        .unwrap_or_else(|error| panic!("{error}"));
    let admin = client
        .approle_admin()
        .unwrap_or_else(|error| panic!("{error}"));

    let roles = admin
        .list_roles()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.keys, ["web"]);

    let role = openbao::auth::approle::AppRoleRoleRequest::new()
        .with_token_policy("web")
        .with_token_ttl("10m")
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .write_role("web", &role)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let role = admin
        .read_role("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(role.token_ttl.as_deref(), Some("600"));
    assert_eq!(role.token_policies, ["web"]);

    let role_id = admin
        .read_role_id("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(role_id.role_id.expose_secret(), &["role-", "id"].concat());
    assert!(!format!("{role_id:?}").contains(&["role-", "id"].concat()));

    let role_id = admin
        .write_role_id("web", &test_secret(&["custom-", "role"]))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        role_id.role_id.expose_secret(),
        &["custom-", "role"].concat()
    );

    let secret_request = openbao::auth::approle::AppRoleSecretIdRequest {
        metadata: Some(r#"{"env":"dev"}"#.to_owned()),
        ..Default::default()
    };
    let secret = admin
        .generate_secret_id("web", &secret_request)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        secret.secret_id.expose_secret(),
        &["secret-", "id"].concat()
    );
    assert!(!format!("{secret:?}").contains(&["secret-", "id"].concat()));

    let accessors = admin
        .list_secret_id_accessors("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        accessors.keys[0].expose_secret(),
        &["accessor-", "id"].concat()
    );

    let info = admin
        .lookup_secret_id("web", &test_secret(&["secret-", "id"]))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(info.metadata.get("env").map(String::as_str), Some("dev"));
    assert!(!format!("{info:?}").contains(&["accessor-", "id"].concat()));

    admin
        .destroy_secret_id("web", &test_secret(&["secret-", "id"]))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let _info = admin
        .lookup_secret_id_accessor("web", &test_secret(&["accessor-", "id"]))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .destroy_secret_id_accessor("web", &test_secret(&["accessor-", "id"]))
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let custom = openbao::auth::approle::AppRoleCustomSecretIdRequest::new(test_secret(&[
        "custom-", "secret",
    ]));
    let custom = admin
        .create_custom_secret_id("web", &custom)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        custom.secret_id.expose_secret(),
        &["custom-", "secret"].concat()
    );

    admin
        .tidy_secret_ids()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_role("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let requests = server.join().unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(requests.len(), 14);
    assert!(requests.iter().any(|request| {
        request.starts_with("POST /v1/auth/approle/role/web HTTP/1.1")
            && request.contains(r#""token_policies":["web"]"#)
            && request.contains(r#""token_ttl":"10m""#)
    }));
    assert!(requests.iter().any(|request| {
        request.starts_with("POST /v1/auth/approle/role/web/role-id HTTP/1.1")
            && request.contains(&format!(r#""role_id":"{}{}""#, "custom-", "role"))
    }));
    assert!(requests.iter().any(|request| {
        request.starts_with("POST /v1/auth/approle/role/web/secret-id HTTP/1.1")
            && request.contains(r#""metadata":"{\"env\":\"dev\"}""#)
    }));
    assert!(requests.iter().any(|request| {
        request.starts_with("POST /v1/auth/approle/role/web/secret-id/lookup HTTP/1.1")
            && request.contains(&format!(r#""secret_id":"{}{}""#, "secret-", "id"))
    }));
    assert!(requests.iter().any(|request| {
        request.starts_with("POST /v1/auth/approle/role/web/secret-id-accessor/lookup HTTP/1.1")
            && request.contains(&format!(
                r#""secret_id_accessor":"{}{}""#,
                "accessor-", "id"
            ))
    }));
    assert!(requests.iter().any(|request| {
        request.starts_with("POST /v1/auth/approle/role/web/custom-secret-id HTTP/1.1")
            && request.contains(&format!(r#""secret_id":"{}{}""#, "custom-", "secret"))
    }));
}

#[tokio::test]
async fn approle_delegated_role_properties_use_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for step in 0..27 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/auth/approle/role/web/policies HTTP/1.1"));
                    r#"{"data":{"policies":["web","ops"]}}"#
                }
                1 => {
                    assert!(
                        request.starts_with("POST /v1/auth/approle/role/web/policies HTTP/1.1")
                    );
                    assert!(request.contains(r#""token_policies":["web","ops"]"#));
                    "{}"
                }
                2 => {
                    assert!(
                        request.starts_with("DELETE /v1/auth/approle/role/web/policies HTTP/1.1")
                    );
                    "{}"
                }
                3 => {
                    assert!(
                        request.starts_with(
                            "GET /v1/auth/approle/role/web/secret-id-num-uses HTTP/1.1"
                        )
                    );
                    r#"{"data":{"secret_id_num_uses":7}}"#
                }
                4 => {
                    assert!(
                        request.starts_with(
                            "POST /v1/auth/approle/role/web/secret-id-num-uses HTTP/1.1"
                        )
                    );
                    assert!(request.contains(r#""secret_id_num_uses":9"#));
                    "{}"
                }
                5 => {
                    assert!(request.starts_with(
                        "DELETE /v1/auth/approle/role/web/secret-id-num-uses HTTP/1.1"
                    ));
                    "{}"
                }
                6 => {
                    assert!(
                        request.starts_with("GET /v1/auth/approle/role/web/secret-id-ttl HTTP/1.1")
                    );
                    r#"{"data":{"secret_id_ttl":600}}"#
                }
                7 => {
                    assert!(
                        request
                            .starts_with("POST /v1/auth/approle/role/web/secret-id-ttl HTTP/1.1")
                    );
                    assert!(request.contains(r#""secret_id_ttl":"15m""#));
                    "{}"
                }
                8 => {
                    assert!(
                        request
                            .starts_with("DELETE /v1/auth/approle/role/web/secret-id-ttl HTTP/1.1")
                    );
                    "{}"
                }
                9 => {
                    assert!(
                        request.starts_with("GET /v1/auth/approle/role/web/token-ttl HTTP/1.1")
                    );
                    r#"{"data":{"token_ttl":"10m"}}"#
                }
                10 => {
                    assert!(
                        request.starts_with("POST /v1/auth/approle/role/web/token-ttl HTTP/1.1")
                    );
                    assert!(request.contains(r#""token_ttl":"20m""#));
                    "{}"
                }
                11 => {
                    assert!(
                        request.starts_with("DELETE /v1/auth/approle/role/web/token-ttl HTTP/1.1")
                    );
                    "{}"
                }
                12 => {
                    assert!(
                        request.starts_with("GET /v1/auth/approle/role/web/token-max-ttl HTTP/1.1")
                    );
                    r#"{"data":{"token_max_ttl":"1h"}}"#
                }
                13 => {
                    assert!(
                        request
                            .starts_with("POST /v1/auth/approle/role/web/token-max-ttl HTTP/1.1")
                    );
                    assert!(request.contains(r#""token_max_ttl":"2h""#));
                    "{}"
                }
                14 => {
                    assert!(
                        request
                            .starts_with("DELETE /v1/auth/approle/role/web/token-max-ttl HTTP/1.1")
                    );
                    "{}"
                }
                15 => {
                    assert!(
                        request
                            .starts_with("GET /v1/auth/approle/role/web/bind-secret-id HTTP/1.1")
                    );
                    r#"{"data":{"bind_secret_id":true}}"#
                }
                16 => {
                    assert!(
                        request
                            .starts_with("POST /v1/auth/approle/role/web/bind-secret-id HTTP/1.1")
                    );
                    assert!(request.contains(r#""bind_secret_id":false"#));
                    "{}"
                }
                17 => {
                    assert!(
                        request.starts_with(
                            "DELETE /v1/auth/approle/role/web/bind-secret-id HTTP/1.1"
                        )
                    );
                    "{}"
                }
                18 => {
                    assert!(request.starts_with(
                        "GET /v1/auth/approle/role/web/secret-id-bound-cidrs HTTP/1.1"
                    ));
                    r#"{"data":{"secret_id_bound_cidrs":["192.0.2.0/24"]}}"#
                }
                19 => {
                    assert!(request.starts_with(
                        "POST /v1/auth/approle/role/web/secret-id-bound-cidrs HTTP/1.1"
                    ));
                    assert!(request.contains(r#""secret_id_bound_cidrs":["192.0.2.0/24"]"#));
                    "{}"
                }
                20 => {
                    assert!(request.starts_with(
                        "DELETE /v1/auth/approle/role/web/secret-id-bound-cidrs HTTP/1.1"
                    ));
                    "{}"
                }
                21 => {
                    assert!(
                        request.starts_with(
                            "GET /v1/auth/approle/role/web/token-bound-cidrs HTTP/1.1"
                        )
                    );
                    r#"{"data":{"token_bound_cidrs":["198.51.100.0/24"]}}"#
                }
                22 => {
                    assert!(
                        request.starts_with(
                            "POST /v1/auth/approle/role/web/token-bound-cidrs HTTP/1.1"
                        )
                    );
                    assert!(request.contains(r#""token_bound_cidrs":["198.51.100.0/24"]"#));
                    "{}"
                }
                23 => {
                    assert!(request.starts_with(
                        "DELETE /v1/auth/approle/role/web/token-bound-cidrs HTTP/1.1"
                    ));
                    "{}"
                }
                24 => {
                    assert!(request.starts_with("GET /v1/auth/approle/role/web/period HTTP/1.1"));
                    r#"{"data":{"period":"24h"}}"#
                }
                25 => {
                    assert!(request.starts_with("POST /v1/auth/approle/role/web/period HTTP/1.1"));
                    assert!(request.contains(r#""period":"30m""#));
                    "{}"
                }
                26 => {
                    assert!(
                        request.starts_with("DELETE /v1/auth/approle/role/web/period HTTP/1.1")
                    );
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .and_then(|client| client.try_with_token(test_secret(&["root-", "token"])))
        .unwrap_or_else(|error| panic!("{error}"));
    let admin = client
        .approle_admin()
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        admin
            .read_token_policies("web")
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        ["web", "ops"]
    );
    admin
        .write_token_policies("web", ["web", "ops"])
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_token_policies("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        admin
            .read_secret_id_num_uses("web")
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        7
    );
    admin
        .write_secret_id_num_uses("web", 9)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_secret_id_num_uses("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        admin
            .read_secret_id_ttl("web")
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        "600"
    );
    admin
        .write_secret_id_ttl("web", "15m")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_secret_id_ttl("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        admin
            .read_token_ttl("web")
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        "10m"
    );
    admin
        .write_token_ttl("web", "20m")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_token_ttl("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        admin
            .read_token_max_ttl("web")
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        "1h"
    );
    admin
        .write_token_max_ttl("web", "2h")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_token_max_ttl("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert!(
        admin
            .read_bind_secret_id("web")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
    );
    admin
        .write_bind_secret_id("web", false)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_bind_secret_id("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        admin
            .read_secret_id_bound_cidrs("web")
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        ["192.0.2.0/24"]
    );
    admin
        .write_secret_id_bound_cidrs("web", ["192.0.2.0/24"])
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_secret_id_bound_cidrs("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        admin
            .read_token_bound_cidrs("web")
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        ["198.51.100.0/24"]
    );
    admin
        .write_token_bound_cidrs("web", ["198.51.100.0/24"])
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_token_bound_cidrs("web")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(
        admin
            .read_token_period("web")
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        "24h"
    );
    admin
        .write_token_period("web", "30m")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    admin
        .delete_token_period("web")
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
        .and_then(allow_mock_http)
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
                    assert!(request.contains(r#""pem_bundle":"-----BEGIN TEST PRIVATE KEY-----"#));
                    r#"{"data":{"imported_issuers":["issuer-2"],"imported_keys":["key-2"],"existing_issuers":[],"existing_keys":[],"mapping":{"issuer-2":"key-2"}}}"#
                }
                3 => {
                    assert!(request.starts_with("POST /v1/pki/issuers/import/bundle HTTP/1.1"));
                    assert!(request.contains(r#""pem_bundle":"-----BEGIN TEST PRIVATE KEY-----"#));
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
                    assert!(request.contains(r#""pem_bundle":"-----BEGIN TEST PRIVATE KEY-----"#));
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
        .and_then(allow_mock_http)
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

    let private_bundle = SecretString::from(
        "-----BEGIN TEST PRIVATE KEY-----\nsecret\n-----END TEST PRIVATE KEY-----",
    );
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

#[tokio::test]
async fn totp_key_and_code_lifecycle_uses_documented_paths() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..6 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let (status, body) = match index {
                0 => {
                    assert!(request.starts_with("POST /v1/totp/keys/app HTTP/1.1"));
                    assert!(request.contains(r#""url":"otpauth://totp/app?value=imported""#));
                    (
                        "200 OK",
                        r#"{"data":{"barcode":"png-data","url":"otpauth://totp/app?value=generated"}}"#
                            .to_owned(),
                    )
                }
                1 => {
                    assert!(request.starts_with("GET /v1/totp/keys/app HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"account_name":"app","algorithm":"SHA256","digits":6,"issuer":"OpenBao","period":30}}"#
                            .to_owned(),
                    )
                }
                2 => {
                    assert!(request.starts_with("LIST /v1/totp/keys?after=app&limit=10 HTTP/1.1"));
                    ("200 OK", r#"{"data":{"keys":["app"]}}"#.to_owned())
                }
                3 => {
                    assert!(request.starts_with("GET /v1/totp/code/app HTTP/1.1"));
                    (
                        "200 OK",
                        format!(r#"{{"data":{{"code":"{}{}"}}}}"#, "123", "456"),
                    )
                }
                4 => {
                    assert!(request.starts_with("POST /v1/totp/code/app HTTP/1.1"));
                    assert!(request.contains(&format!(r#""code":"{}{}""#, "654", "321")));
                    ("200 OK", r#"{"data":{"valid":true}}"#.to_owned())
                }
                5 => {
                    assert!(request.starts_with("DELETE /v1/totp/keys/app HTTP/1.1"));
                    ("204 No Content", "{}".to_owned())
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let totp = client
        .totp("totp")
        .unwrap_or_else(|error| panic!("{error}"));

    let created = totp
        .create_key(
            "app",
            &openbao::secrets::totp::TotpKeyCreateRequest::from_url(test_secret(&[
                "otpauth://totp/app?",
                "value=imported",
            ])),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(created.barcode.is_some());
    assert!(created.url.is_some());

    let info = totp
        .read_key("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(info.account_name.as_deref(), Some("app"));

    let keys = totp
        .list_keys_after(Some("app"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(keys.keys, ["app"]);

    let generated = totp
        .generate_code("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(generated.code.expose_secret(), &["123", "456"].concat());

    let validated = totp
        .validate_code(
            "app",
            &openbao::secrets::totp::TotpValidateRequest::new(test_secret(&["654", "321"])),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(validated.valid);

    totp.delete_key("app")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn ssh_role_otp_and_ca_paths_are_documented() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..18 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let (status, body) = match index {
                0 => {
                    assert!(request.starts_with("POST /v1/ssh/roles/otp-role HTTP/1.1"));
                    assert!(request.contains(r#""key_type":"otp""#));
                    assert!(request.contains(r#""default_user":"alice""#));
                    ("204 No Content", "{}".to_owned())
                }
                1 => {
                    assert!(
                        request.starts_with("LIST /v1/ssh/roles?after=otp-role&limit=10 HTTP/1.1")
                    );
                    ("200 OK", r#"{"data":{"keys":["otp-role"]}}"#.to_owned())
                }
                2 => {
                    assert!(request.starts_with("POST /v1/ssh/lookup HTTP/1.1"));
                    assert!(request.contains(r#""ip":"127.0.0.1""#));
                    ("200 OK", r#"{"data":{"roles":["otp-role"]}}"#.to_owned())
                }
                3 => {
                    assert!(request.starts_with("POST /v1/ssh/creds/otp-role HTTP/1.1"));
                    assert!(request.contains(r#""username":"alice""#));
                    assert!(request.contains(r#""ip":"127.0.0.1""#));
                    (
                        "200 OK",
                        format!(
                            r#"{{"data":{{"ip":"127.0.0.1","key":"{}{}","key_type":"otp","port":22,"username":"alice"}}}}"#,
                            "otp-", "secret"
                        ),
                    )
                }
                4 => {
                    assert!(request.starts_with("GET /v1/ssh/config/issuers HTTP/1.1"));
                    ("200 OK", r#"{"data":{"default":"issuer-1"}}"#.to_owned())
                }
                5 => {
                    assert!(request.starts_with("POST /v1/ssh/config/issuers HTTP/1.1"));
                    assert!(request.contains(r#""default":"issuer-2""#));
                    ("200 OK", r#"{"data":{"default":"issuer-2"}}"#.to_owned())
                }
                6 => {
                    assert!(request.starts_with("POST /v1/ssh/config/ca HTTP/1.1"));
                    assert!(request.contains(&format!(
                        r#""private_key":"{}{}""#,
                        "ssh-ca-private-", "key"
                    )));
                    assert!(request.contains(r#""public_key":"ssh-rsa AAAA ca""#));
                    (
                        "200 OK",
                        r#"{"data":{"issuer_id":"issuer-1","issuer_name":"default","public_key":"ssh-rsa AAAA ca\n"}}"#
                            .to_owned(),
                    )
                }
                7 => {
                    assert!(
                        request
                            .starts_with("LIST /v1/ssh/issuers?after=issuer-1&limit=10 HTTP/1.1")
                    );
                    (
                        "200 OK",
                        r#"{"data":{"keys":["issuer-1"],"key_info":{"issuer-1":{"issuer_name":"default","is_default":true,"public_key":"ssh-rsa AAAA ca\n"}}}}"#
                            .to_owned(),
                    )
                }
                8 => {
                    assert!(request.starts_with("POST /v1/ssh/issuers/import/imported HTTP/1.1"));
                    assert!(request.contains(r#""generate_signing_key":true"#));
                    assert!(request.contains(r#""key_type":"rsa""#));
                    assert!(request.contains(r#""set_default":true"#));
                    (
                        "200 OK",
                        r#"{"data":{"issuer_id":"issuer-2","issuer_name":"imported","public_key":"ssh-rsa AAAA imported\n"}}"#
                            .to_owned(),
                    )
                }
                9 => {
                    assert!(request.starts_with("GET /v1/ssh/issuer/default HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"issuer_id":"issuer-2","issuer_name":"imported","public_key":"ssh-rsa AAAA imported\n"}}"#
                            .to_owned(),
                    )
                }
                10 => {
                    assert!(request.starts_with("PATCH /v1/ssh/issuer/default HTTP/1.1"));
                    assert!(request.contains(r#""issuer_name":"renamed""#));
                    (
                        "200 OK",
                        r#"{"data":{"issuer_id":"issuer-2","issuer_name":"renamed","public_key":"ssh-rsa AAAA imported\n"}}"#
                            .to_owned(),
                    )
                }
                11 => {
                    assert!(request.starts_with("GET /v1/ssh/config/ca HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"issuer_id":"issuer-2","issuer_name":"renamed","public_key":"ssh-rsa AAAA imported\n"}}"#
                            .to_owned(),
                    )
                }
                12 => {
                    assert!(request.starts_with("POST /v1/ssh/sign/ca-role HTTP/1.1"));
                    assert!(request.contains(r#""public_key":"ssh-rsa AAAA test""#));
                    (
                        "200 OK",
                        r#"{"data":{"issuer_id":"issuer-2","serial_number":"abc","signed_key":"ssh-rsa-cert-v01 cert\n"}}"#
                            .to_owned(),
                    )
                }
                13 => {
                    assert!(request.starts_with("POST /v1/ssh/issue/ca-role HTTP/1.1"));
                    assert!(request.contains(r#""key_type":"rsa""#));
                    (
                        "200 OK",
                        format!(
                            r#"{{"data":{{"issuer_id":"issuer-2","serial_number":"def","signed_key":"ssh-rsa-cert-v01 cert\n","private_key":"{}{}","private_key_type":"rsa"}}}}"#,
                            "private-", "key"
                        ),
                    )
                }
                14 => {
                    assert!(request.starts_with("POST /v1/ssh/verify HTTP/1.1"));
                    assert!(request.contains(&format!(r#""otp":"{}{}""#, "otp-", "secret")));
                    (
                        "200 OK",
                        r#"{"data":{"ip":"127.0.0.1","username":"alice"}}"#.to_owned(),
                    )
                }
                15 => {
                    assert!(request.starts_with("DELETE /v1/ssh/issuer/renamed HTTP/1.1"));
                    ("204 No Content", "{}".to_owned())
                }
                16 => {
                    assert!(request.starts_with("DELETE /v1/ssh/config/ca HTTP/1.1"));
                    ("204 No Content", "{}".to_owned())
                }
                17 => {
                    assert!(request.starts_with("DELETE /v1/ssh/roles/otp-role HTTP/1.1"));
                    ("204 No Content", "{}".to_owned())
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));
    let ssh = client.ssh("ssh").unwrap_or_else(|error| panic!("{error}"));
    let ip = "127.0.0.1"
        .parse()
        .unwrap_or_else(|error| panic!("{error}"));

    ssh.write_role(
        "otp-role",
        &openbao::secrets::ssh::SshRoleRequest::otp("alice", "127.0.0.1/32"),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));

    let roles = ssh
        .list_roles_after(Some("otp-role"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(roles.roles, ["otp-role"]);

    let lookup = ssh
        .lookup_roles_by_ip(ip)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(lookup.roles, ["otp-role"]);

    let credentials = ssh
        .credentials(
            "otp-role",
            &openbao::secrets::ssh::SshCredentialsRequest::new(ip).with_username("alice"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        credentials.key.expose_secret(),
        &["otp-", "secret"].concat()
    );

    let issuer_config = ssh
        .read_issuer_config()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer_config.default_issuer, "issuer-1");

    let issuer_config = ssh
        .write_issuer_config(&openbao::secrets::ssh::SshIssuerConfigRequest::new(
            "issuer-2",
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer_config.default_issuer, "issuer-2");

    let default_issuer = ssh
        .submit_default_ca(&openbao::secrets::ssh::SshCaSubmitRequest::from_key_pair(
            test_secret(&["ssh-ca-private-", "key"]),
            "ssh-rsa AAAA ca",
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(default_issuer.issuer_id.as_deref(), Some("issuer-1"));

    let issuers = ssh
        .list_issuers_after(Some("issuer-1"), Some(10))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuers.keys, ["issuer-1"]);
    assert_eq!(
        issuers
            .key_info
            .get("issuer-1")
            .and_then(|issuer| issuer.issuer_name.as_deref()),
        Some("default")
    );

    let generated_issuer = ssh
        .submit_issuer(
            Some("imported"),
            &openbao::secrets::ssh::SshCaSubmitRequest::generate()
                .with_key_type("rsa")
                .with_set_default(true),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(generated_issuer.issuer_id.as_deref(), Some("issuer-2"));

    let issuer = ssh
        .read_issuer("default")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer.issuer_name.as_deref(), Some("imported"));

    let issuer = ssh
        .update_issuer(
            "default",
            &openbao::secrets::ssh::SshIssuerUpdateRequest::new("renamed"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(issuer.issuer_name.as_deref(), Some("renamed"));

    let ca_public_key = ssh
        .read_ca_public_key()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(ca_public_key.issuer_name.as_deref(), Some("renamed"));

    let signed = ssh
        .sign(
            "ca-role",
            &openbao::secrets::ssh::SshSignRequest::new("ssh-rsa AAAA test")
                .with_valid_principals("alice"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(signed.issuer_id.as_deref(), Some("issuer-2"));

    let issued = ssh
        .issue(
            "ca-role",
            &openbao::secrets::ssh::SshIssueRequest::new(
                openbao::secrets::ssh::SshIssueKeyType::Rsa,
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        issued.private_key.expose_secret(),
        &["private-", "key"].concat()
    );

    let verified = ssh
        .verify(&openbao::secrets::ssh::SshVerifyRequest::new(
            credentials.key,
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(verified.username, "alice");

    ssh.delete_issuer("renamed")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    ssh.delete_ca_information()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    ssh.delete_role("otp-role")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn admin_bootstrap_runs_idempotent_steps_before_token_issue() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..12 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let (status, body) = match index {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/mounts/secret HTTP/1.1"));
                    (
                        "404 Not Found",
                        r#"{"errors":["missing mount"]}"#.to_owned(),
                    )
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/mounts/secret HTTP/1.1"));
                    assert!(request.contains(r#""type":"kv""#));
                    assert!(request.contains(r#""version":"2""#));
                    ("204 No Content", "{}".to_owned())
                }
                2 => {
                    assert!(request.starts_with("GET /v1/sys/mounts/secret HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"type":"kv","description":"application secrets","config":{},"options":{"version":"2"}}}"#
                            .to_owned(),
                    )
                }
                3 => {
                    assert!(request.starts_with("GET /v1/sys/mounts/transit HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"type":"transit","description":"existing transit","config":{},"options":null}}"#
                            .to_owned(),
                    )
                }
                4 => {
                    assert!(request.starts_with("GET /v1/sys/policy/app-read HTTP/1.1"));
                    (
                        "404 Not Found",
                        r#"{"errors":["missing policy"]}"#.to_owned(),
                    )
                }
                5 => {
                    assert!(request.starts_with("POST /v1/sys/policy/app-read HTTP/1.1"));
                    assert!(request.contains("secret/data/app"));
                    ("204 No Content", "{}".to_owned())
                }
                6 => {
                    assert!(request.starts_with("GET /v1/sys/policy/app-read HTTP/1.1"));
                    let rules = "path \"secret/data/app/*\" {\n  capabilities = [\"read\"]\n}\npath \"secret/metadata/app/*\" {\n  capabilities = [\"list\"]\n}\n";
                    (
                        "200 OK",
                        serde_json::json!({"name":"app-read","rules":rules}).to_string(),
                    )
                }
                7 => {
                    assert!(request.starts_with("GET /v1/transit/keys/app-key HTTP/1.1"));
                    ("404 Not Found", r#"{"errors":["missing key"]}"#.to_owned())
                }
                8 => {
                    assert!(request.starts_with("POST /v1/transit/keys/app-key HTTP/1.1"));
                    ("204 No Content", "{}".to_owned())
                }
                9 => {
                    assert!(request.starts_with("GET /v1/secret/data/app/config HTTP/1.1"));
                    (
                        "404 Not Found",
                        r#"{"errors":["missing secret"]}"#.to_owned(),
                    )
                }
                10 => {
                    assert!(request.starts_with("POST /v1/secret/data/app/config HTTP/1.1"));
                    assert!(request.contains(r#""options":{"cas":0}"#));
                    assert!(
                        request.contains(&format!(r#""API_KEY":"{}{}""#, "runtime-", "secret"))
                    );
                    (
                        "200 OK",
                        r#"{"data":{"created_time":"now","version":1}}"#.to_owned(),
                    )
                }
                11 => {
                    assert!(request.starts_with("POST /v1/auth/token/create HTTP/1.1"));
                    assert!(request.contains(r#""policies":["app-read"]"#));
                    assert!(request.contains(r#""no_default_policy":true"#));
                    (
                        "200 OK",
                        format!(
                            r#"{{"auth":{{"client_token":"{}{}","accessor":"{}{}","policies":["app-read"],"token_policies":["app-read"],"lease_duration":3600,"renewable":true}}}}"#,
                            "token-", "secret", "accessor-", "secret"
                        ),
                    )
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));

    let mut policy = openbao::AclPolicyBuilder::new();
    policy
        .allow_kv2_read_prefix("secret", "app")
        .unwrap_or_else(|error| panic!("{error}"));

    let mut secret_values = std::collections::BTreeMap::new();
    secret_values.insert(
        "API_KEY".to_owned(),
        SecretString::from(["runtime-", "secret"].concat()),
    );

    let mut bootstrap = openbao::bootstrap::AdminBootstrap::new();
    bootstrap
        .ensure_kv2_mount("secret", Some("application secrets"))
        .and_then(|builder| builder.ensure_transit_mount("transit", None))
        .and_then(|builder| builder.ensure_policy("app-read", &policy))
        .and_then(|builder| {
            builder.ensure_transit_key(
                "transit",
                "app-key",
                openbao::secrets::transit::TransitCreateKeyRequest::default(),
            )
        })
        .and_then(|builder| builder.ensure_kv2_secret_values("secret", "app/config", secret_values))
        .and_then(|builder| {
            builder.issue_service_token(
                "app",
                openbao::auth::token::TokenCreateRequest {
                    policies: vec!["app-read".to_owned()],
                    no_default_policy: Some(true),
                    ttl: Some("1h".to_owned()),
                    ..Default::default()
                },
            )
        })
        .unwrap_or_else(|error| panic!("{error}"));

    let report = bootstrap
        .run(&client)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(report.steps.len(), 6);
    assert_eq!(report.issued_tokens.len(), 1);
    assert_eq!(
        report.issued_tokens[0].auth.client_token.expose_secret(),
        &["token-", "secret"].concat()
    );
    assert_eq!(
        report.steps[0].status,
        openbao::bootstrap::BootstrapStepStatus::Created
    );
    assert_eq!(
        report.steps[1].status,
        openbao::bootstrap::BootstrapStepStatus::Unchanged
    );
    assert_eq!(
        report.steps[5].status,
        openbao::bootstrap::BootstrapStepStatus::Issued
    );

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn admin_bootstrap_preview_is_read_only() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let request = read_http_request(&mut stream);
        assert!(request.starts_with("GET /v1/sys/mounts/secret HTTP/1.1"));
        assert!(!request.starts_with("POST "));
        let body = r#"{"data":{"type":"kv","description":"application secrets","options":{"version":"2"}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));

    let mut bootstrap = openbao::bootstrap::AdminBootstrap::new();
    bootstrap
        .ensure_kv2_mount("secret", Some("application secrets"))
        .and_then(|builder| {
            builder.issue_service_token(
                "app",
                openbao::auth::token::TokenCreateRequest {
                    policies: vec!["app-read".to_owned()],
                    no_default_policy: Some(true),
                    ..Default::default()
                },
            )
        })
        .unwrap_or_else(|error| panic!("{error}"));

    let preview = bootstrap
        .preview(&client)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(preview.steps.len(), 2);
    assert_eq!(
        preview.steps[0].status,
        openbao::bootstrap::BootstrapPreviewStatus::Unchanged
    );
    assert_eq!(
        preview.steps[1].status,
        openbao::bootstrap::BootstrapPreviewStatus::WouldIssue
    );
    assert!(!preview.is_converged());

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[tokio::test]
async fn admin_bootstrap_can_provision_approle_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..7 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let (status, body) = match index {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/auth HTTP/1.1"));
                    ("200 OK", r#"{"data":{}}"#.to_owned())
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/auth/approle HTTP/1.1"));
                    assert!(request.contains(r#""type":"approle""#));
                    assert!(request.contains(r#""description":"machine auth""#));
                    ("204 No Content", "{}".to_owned())
                }
                2 => {
                    assert!(request.starts_with("GET /v1/sys/auth HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"approle/":{"type":"approle","description":"machine auth"}}}"#
                            .to_owned(),
                    )
                }
                3 => {
                    assert!(request.starts_with("GET /v1/auth/approle/role/web HTTP/1.1"));
                    ("404 Not Found", r#"{"errors":["missing role"]}"#.to_owned())
                }
                4 => {
                    assert!(request.starts_with("POST /v1/auth/approle/role/web HTTP/1.1"));
                    assert!(request.contains(r#""bind_secret_id":true"#));
                    assert!(request.contains(r#""token_policies":["web"]"#));
                    ("204 No Content", "{}".to_owned())
                }
                5 => {
                    assert!(request.starts_with("GET /v1/auth/approle/role/web HTTP/1.1"));
                    (
                        "200 OK",
                        r#"{"data":{"bind_secret_id":true,"token_policies":["web"]}}"#.to_owned(),
                    )
                }
                6 => {
                    assert!(
                        request.starts_with("POST /v1/auth/approle/role/web/secret-id HTTP/1.1")
                    );
                    assert!(request.contains(r#""ttl":"10m""#));
                    (
                        "200 OK",
                        format!(
                            r#"{{"data":{{"secret_id":"{}{}","secret_id_accessor":"{}{}","secret_id_ttl":600,"secret_id_num_uses":0}}}}"#,
                            "secret-", "id", "secret-", "accessor"
                        ),
                    )
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("root-token"));

    let role = openbao::auth::approle::AppRoleRoleRequest {
        bind_secret_id: Some(true),
        ..openbao::auth::approle::AppRoleRoleRequest::new()
    }
    .with_token_policy("web");
    let secret_id = openbao::auth::approle::AppRoleSecretIdRequest::new()
        .with_ttl("10m")
        .unwrap_or_else(|error| panic!("{error}"));
    let mut bootstrap = openbao::bootstrap::AdminBootstrap::new();
    bootstrap
        .ensure_approle_auth_method("approle", Some("machine auth"))
        .and_then(|builder| builder.ensure_approle_role("approle", "web", role))
        .and_then(|builder| {
            builder.issue_approle_secret_id("web-login", "approle", "web", secret_id)
        })
        .unwrap_or_else(|error| panic!("{error}"));

    let report = bootstrap
        .run(&client)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert_eq!(report.steps.len(), 3);
    assert_eq!(
        report.steps[0].status,
        openbao::bootstrap::BootstrapStepStatus::Created
    );
    assert_eq!(
        report.steps[1].status,
        openbao::bootstrap::BootstrapStepStatus::Created
    );
    assert_eq!(
        report.steps[2].status,
        openbao::bootstrap::BootstrapStepStatus::Issued
    );
    assert_eq!(report.issued_approle_secret_ids.len(), 1);
    assert_eq!(
        report.issued_approle_secret_ids[0]
            .secret_id
            .secret_id
            .expose_secret(),
        &["secret-", "id"].concat()
    );
    assert!(!format!("{report:?}").contains(&["secret-", "id"].concat()));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "operator-ops")]
#[tokio::test]
async fn raw_storage_helpers_use_documented_paths_and_redact_values() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..4 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match index {
                0 => {
                    assert!(request.starts_with(
                        "GET /v1/sys/raw/logical/foo?compressed=false&encoding=base64 HTTP/1.1"
                    ));
                    format!(r#"{{"value":"{}{}"}}"#, "raw-", "read-value")
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/raw/logical/foo HTTP/1.1"));
                    assert!(request.contains(&format!(r#""value":"{}{}""#, "raw-", "write-value")));
                    assert!(request.contains(r#""compression_type":"gzip""#));
                    assert!(request.contains(r#""encoding":"base64""#));
                    "{}".to_owned()
                }
                2 => {
                    assert!(request.starts_with("GET /v1/sys/raw/logical?list=true HTTP/1.1"));
                    r#"{"data":{"keys":["foo","bar/"]}}"#.to_owned()
                }
                3 => {
                    assert!(request.starts_with("DELETE /v1/sys/raw/logical/foo HTTP/1.1"));
                    "{}".to_owned()
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let read = client
        .sys()
        .raw_read(
            "logical/foo",
            &openbao::sys::RawReadOptions::new()
                .with_compressed(false)
                .with_encoding(openbao::sys::RawEncoding::Base64),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(read.value.expose_secret(), "raw-read-value");
    assert!(!format!("{read:?}").contains("raw-read-value"));

    let write = openbao::sys::RawWriteRequest::new(test_secret(&["raw-", "write-value"]))
        .with_compression(openbao::sys::RawCompression::Gzip)
        .with_encoding(openbao::sys::RawEncoding::Base64);
    assert!(!format!("{write:?}").contains("raw-write-value"));
    client
        .sys()
        .raw_write("logical/foo", &write)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let list = client
        .sys()
        .raw_list("logical")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(list.keys, ["foo", "bar/"]);

    client
        .sys()
        .raw_delete("logical/foo")
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "operator-ops")]
#[tokio::test]
async fn pprof_helpers_use_documented_paths_and_capped_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));

    let server = thread::spawn(move || {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match index {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/pprof/heap HTTP/1.1"));
                    b"heap-profile".to_vec()
                }
                1 => {
                    assert!(request.starts_with("GET /v1/sys/pprof/profile?seconds=2 HTTP/1.1"));
                    b"cpu-profile".to_vec()
                }
                2 => {
                    assert!(request.starts_with("GET /v1/sys/pprof/goroutine?debug=2 HTTP/1.1"));
                    b"goroutine stack trace".to_vec()
                }
                _ => unreachable!(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                String::from_utf8_lossy(&body)
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let config = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(SecretString::from("test-token"));

    let heap = client
        .sys()
        .pprof(openbao::sys::PprofProfile::Heap, &Default::default())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    heap.with_secret(|bytes| assert_eq!(bytes, b"heap-profile"));

    let cpu = client
        .sys()
        .pprof(
            openbao::sys::PprofProfile::Profile,
            &openbao::sys::PprofOptions::new().with_seconds(2),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    cpu.with_secret(|bytes| assert_eq!(bytes, b"cpu-profile"));

    let goroutine = client
        .sys()
        .pprof(
            openbao::sys::PprofProfile::Goroutine,
            &openbao::sys::PprofOptions::new().with_debug(2),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    goroutine.with_secret(|bytes| assert_eq!(bytes, b"goroutine stack trace"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "operator-ops")]
#[tokio::test]
async fn operator_ops_use_documented_paths_and_redact_material() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));
    let rekey_operation_id = test_operation_id();
    let rotate_operation_id = test_operation_id();
    let server_rekey_operation_id = rekey_operation_id.clone();
    let server_rotate_operation_id = rotate_operation_id.clone();

    let server = thread::spawn(move || {
        for index in 0..12 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut buffer = [0_u8; 8192];
            let bytes = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&buffer[..bytes]);
            let body = match index {
                0 => {
                    assert!(request.starts_with("POST /v1/sys/init HTTP/1.1"));
                    assert!(request.contains(r#""secret_shares":1"#));
                    format!(
                        r#"{{"keys":["{}{}"],"keys_base64":["{}{}"],"root_token":"{}{}"}}"#,
                        "unseal-", "share", "base64-", "share", "root-", "token"
                    )
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/unseal HTTP/1.1"));
                    assert!(request.contains(&format!(r#""key":"{}{}""#, "unseal-", "share")));
                    r#"{"sealed":false,"n":1,"t":1,"progress":0,"version":"2.5.5"}"#.to_owned()
                }
                2 => {
                    assert!(request.starts_with("PUT /v1/sys/seal HTTP/1.1"));
                    "{}".to_owned()
                }
                3 => {
                    assert!(request.starts_with("POST /v1/sys/rotate/keyring HTTP/1.1"));
                    "{}".to_owned()
                }
                4 => {
                    assert!(request.starts_with("GET /v1/sys/rekey/init HTTP/1.1"));
                    r#"{"started":false}"#.to_owned()
                }
                5 => {
                    assert!(request.starts_with("POST /v1/sys/rekey/init HTTP/1.1"));
                    assert!(request.contains(r#""secret_shares":1"#));
                    format!(
                        r#"{{"started":true,"nonce":"{}","t":1,"n":1,"progress":0,"required":1}}"#,
                        server_rekey_operation_id
                    )
                }
                6 => {
                    assert!(request.starts_with("POST /v1/sys/rekey/update HTTP/1.1"));
                    assert!(request.contains(&format!(r#""key":"{}{}""#, "unseal-", "share")));
                    format!(
                        r#"{{"complete":true,"keys":["{}{}"],"keys_base64":["{}{}"],"nonce":"{}"}}"#,
                        "new-", "share", "new-base64-", "share", server_rekey_operation_id
                    )
                }
                7 => {
                    assert!(request.starts_with("DELETE /v1/sys/rekey/init HTTP/1.1"));
                    "{}".to_owned()
                }
                8 => {
                    assert!(request.starts_with("GET /v1/sys/rotate/root/init HTTP/1.1"));
                    r#"{"started":false}"#.to_owned()
                }
                9 => {
                    assert!(request.starts_with("POST /v1/sys/rotate/root/init HTTP/1.1"));
                    format!(
                        r#"{{"started":true,"nonce":"{}","t":1,"n":1,"progress":0,"required":1}}"#,
                        server_rotate_operation_id
                    )
                }
                10 => {
                    assert!(request.starts_with("POST /v1/sys/rotate/root/update HTTP/1.1"));
                    assert!(request.contains(&format!(r#""key":"{}{}""#, "unseal-", "share")));
                    format!(
                        r#"{{"complete":true,"keys":["{}{}"],"keys_base64":["{}{}"],"nonce":"{}"}}"#,
                        "rotated-", "share", "rotated-base64-", "share", server_rotate_operation_id
                    )
                }
                11 => {
                    assert!(request.starts_with("DELETE /v1/sys/rotate/root/init HTTP/1.1"));
                    "{}".to_owned()
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

    let unauthenticated = OpenBaoConfig::new(format!("http://{addr}"))
        .and_then(allow_mock_http)
        .and_then(Client::from_config)
        .unwrap_or_else(|error| panic!("{error}"));

    let init = unauthenticated
        .sys()
        .operator_init(&openbao::sys::OperatorInitRequest {
            secret_shares: Some(1),
            secret_threshold: Some(1),
            ..Default::default()
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(init.keys.len(), 1);
    assert!(!format!("{init:?}").contains(&["root-", "token"].concat()));

    let unseal = unauthenticated
        .sys()
        .operator_unseal(&openbao::sys::OperatorUnsealRequest::new(
            init.keys[0].clone(),
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!unseal.sealed);

    let authenticated = unauthenticated.with_token(SecretString::from(["root-", "token"].concat()));
    authenticated
        .sys()
        .operator_seal()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    authenticated
        .sys()
        .operator_rotate_keyring()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let status = authenticated
        .sys()
        .operator_rekey_status()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!status.started);

    authenticated
        .sys()
        .operator_rekey_start(
            &openbao::sys::OperatorKeySharesRequest::new(1, 1)
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let rekey = authenticated
        .sys()
        .operator_rekey_update(&openbao::sys::OperatorKeyShareUpdateRequest::new(
            SecretString::from(["unseal-", "share"].concat()),
            rekey_operation_id,
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(rekey.complete);
    assert!(!format!("{rekey:?}").contains(&["new-", "share"].concat()));
    authenticated
        .sys()
        .operator_rekey_cancel()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    let rotate_status = authenticated
        .sys()
        .operator_rotate_status(openbao::sys::OperatorRotateTarget::Root)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!rotate_status.started);
    authenticated
        .sys()
        .operator_rotate_start(
            openbao::sys::OperatorRotateTarget::Root,
            &openbao::sys::OperatorKeySharesRequest::new(1, 1)
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let rotate = authenticated
        .sys()
        .operator_rotate_update(
            openbao::sys::OperatorRotateTarget::Root,
            &openbao::sys::OperatorKeyShareUpdateRequest::new(
                SecretString::from(["unseal-", "share"].concat()),
                rotate_operation_id,
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(rotate.complete);
    authenticated
        .sys()
        .operator_rotate_cancel(openbao::sys::OperatorRotateTarget::Root)
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}

#[cfg(feature = "operator-ops")]
#[tokio::test]
async fn system_0_14_operator_helpers_use_documented_paths_and_redact_material() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));
    let root_nonce = test_operation_id();
    let recovery_nonce = test_operation_id();
    let rekey_nonce = test_operation_id();
    let verify_nonce = test_operation_id();
    let server_root_nonce = root_nonce.clone();
    let server_recovery_nonce = recovery_nonce.clone();
    let server_rekey_nonce = rekey_nonce.clone();
    let server_verify_nonce = verify_nonce.clone();

    let server = thread::spawn(move || {
        for step in 0..18 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let request = read_http_request(&mut stream);
            let body = match step {
                0 => {
                    assert!(request.starts_with("GET /v1/sys/generate-root/attempt HTTP/1.1"));
                    r#"{"started":false}"#.to_owned()
                }
                1 => {
                    assert!(request.starts_with("POST /v1/sys/generate-root/attempt HTTP/1.1"));
                    format!(
                        r#"{{"started":true,"nonce":"{}","progress":0,"required":1,"otp":"{}{}","otp_length":24,"complete":false}}"#,
                        server_root_nonce, "root-", "otp"
                    )
                }
                2 => {
                    assert!(request.starts_with("POST /v1/sys/generate-root/update HTTP/1.1"));
                    assert!(request.contains(&format!(r#""nonce":"{}""#, server_root_nonce)));
                    assert!(request.contains(r#""key":"root-share""#));
                    format!(
                        r#"{{"started":true,"nonce":"{}","progress":1,"required":1,"encoded_token":"{}{}","complete":true}}"#,
                        server_root_nonce, "encoded-", "root"
                    )
                }
                3 => {
                    assert!(request.starts_with("POST /v1/sys/decode-token HTTP/1.1"));
                    assert!(request.contains(r#""encoded_token":"encoded-root""#));
                    assert!(request.contains(r#""otp":"root-otp""#));
                    r#"{"data":{"token":"decoded-root-token"}}"#.to_owned()
                }
                4 => {
                    assert!(request.starts_with("DELETE /v1/sys/generate-root/attempt HTTP/1.1"));
                    "{}".to_owned()
                }
                5 => {
                    assert!(
                        request.starts_with("GET /v1/sys/generate-recovery-token/attempt HTTP/1.1")
                    );
                    r#"{"started":false}"#.to_owned()
                }
                6 => {
                    assert!(
                        request
                            .starts_with("POST /v1/sys/generate-recovery-token/attempt HTTP/1.1")
                    );
                    assert!(request.contains(r#""pgp_key":"pgp-public-key""#));
                    format!(
                        r#"{{"started":true,"nonce":"{}","progress":0,"required":1,"otp":"{}{}","otp_length":24,"complete":false}}"#,
                        server_recovery_nonce, "recovery-", "otp"
                    )
                }
                7 => {
                    assert!(
                        request.starts_with("POST /v1/sys/generate-recovery-token/update HTTP/1.1")
                    );
                    assert!(request.contains(&format!(r#""nonce":"{}""#, server_recovery_nonce)));
                    assert!(request.contains(r#""key":"recovery-share""#));
                    format!(
                        r#"{{"started":true,"nonce":"{}","progress":1,"required":1,"encoded_token":"{}{}","complete":true}}"#,
                        server_recovery_nonce, "encoded-", "recovery"
                    )
                }
                8 => {
                    assert!(
                        request
                            .starts_with("DELETE /v1/sys/generate-recovery-token/attempt HTTP/1.1")
                    );
                    "{}".to_owned()
                }
                9 => {
                    assert!(request.starts_with("GET /v1/sys/rekey-recovery-key/init HTTP/1.1"));
                    r#"{"started":false}"#.to_owned()
                }
                10 => {
                    assert!(request.starts_with("POST /v1/sys/rekey-recovery-key/init HTTP/1.1"));
                    assert!(request.contains(r#""secret_shares":1"#));
                    format!(
                        r#"{{"started":true,"nonce":"{}","t":1,"n":1,"progress":0,"required":1,"backup":true}}"#,
                        server_rekey_nonce
                    )
                }
                11 => {
                    assert!(request.starts_with("POST /v1/sys/rekey-recovery-key/update HTTP/1.1"));
                    assert!(request.contains(&format!(r#""nonce":"{}""#, server_rekey_nonce)));
                    assert!(request.contains(r#""key":"current-recovery-share""#));
                    format!(
                        r#"{{"complete":true,"keys":["{}{}"],"keys_base64":["{}{}"],"nonce":"{}","backup":true,"verification_required":true,"verification_nonce":"{}"}}"#,
                        "new-recovery-",
                        "share",
                        "new-recovery-base64-",
                        "share",
                        server_rekey_nonce,
                        server_verify_nonce
                    )
                }
                12 => {
                    assert!(request.starts_with("GET /v1/sys/rekey/recovery-key-backup HTTP/1.1"));
                    r#"{"nonce":"backup-nonce","keys":{"fingerprint":"encrypted-share"}}"#
                        .to_owned()
                }
                13 => {
                    assert!(
                        request.starts_with("DELETE /v1/sys/rekey/recovery-key-backup HTTP/1.1")
                    );
                    "{}".to_owned()
                }
                14 => {
                    assert!(request.starts_with("GET /v1/sys/rekey-recovery-key/verify HTTP/1.1"));
                    format!(
                        r#"{{"nonce":"{}","t":1,"n":1,"progress":0}}"#,
                        server_verify_nonce
                    )
                }
                15 => {
                    assert!(
                        request.starts_with("DELETE /v1/sys/rekey-recovery-key/verify HTTP/1.1")
                    );
                    format!(
                        r#"{{"nonce":"{}","t":1,"n":1,"progress":0}}"#,
                        server_verify_nonce
                    )
                }
                16 => {
                    assert!(request.starts_with("POST /v1/sys/rekey-recovery-key/verify HTTP/1.1"));
                    assert!(request.contains(&format!(r#""nonce":"{}""#, server_verify_nonce)));
                    assert!(request.contains(r#""key":"new-recovery-share""#));
                    format!(r#"{{"nonce":"{}","complete":true}}"#, server_verify_nonce)
                }
                17 => {
                    assert!(request.starts_with("GET /v1/sys/in-flight-req HTTP/1.1"));
                    r#"{"request-id":{"start_time":"2026-06-04T12:00:00Z","client_remote_address":"127.0.0.1:9940","request_path":"/v1/secret/data/app","request_method":"GET","client_token_accessor":"token-accessor"}}"#.to_owned()
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
        .and_then(allow_mock_http)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .unwrap_or_else(|error| panic!("{error}"))
        .with_token(test_secret(&["root-", "token"]));
    let sys = client.sys();

    assert!(
        !sys.operator_generate_root_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .started
    );
    let root_start = sys
        .operator_generate_root_start(&openbao::sys::OperatorTokenGenerationStartRequest::new())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        root_start.otp.as_ref().map(SecretString::expose_secret),
        Some("root-otp")
    );
    assert!(!format!("{root_start:?}").contains("root-otp"));
    let root_update = sys
        .operator_generate_root_update(&openbao::sys::OperatorKeyShareUpdateRequest::new(
            SecretString::from("root-share"),
            root_nonce,
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        root_update
            .encoded_token
            .as_ref()
            .map(SecretString::expose_secret),
        Some("encoded-root")
    );
    assert!(!format!("{root_update:?}").contains("encoded-root"));
    let decoded = sys
        .operator_decode_token(&openbao::sys::DecodeTokenRequest::new(
            root_update
                .encoded_token
                .clone()
                .unwrap_or_else(|| panic!("missing encoded token")),
            SecretString::from("root-otp"),
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(decoded.token.expose_secret(), "decoded-root-token");
    assert!(!format!("{decoded:?}").contains("decoded-root-token"));
    sys.operator_generate_root_cancel()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert!(
        !sys.operator_generate_recovery_token_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .started
    );
    let recovery_start = sys
        .operator_generate_recovery_token_start(
            &openbao::sys::OperatorTokenGenerationStartRequest::new()
                .with_pgp_key("pgp-public-key"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        recovery_start.otp.as_ref().map(SecretString::expose_secret),
        Some("recovery-otp")
    );
    let recovery_update = sys
        .operator_generate_recovery_token_update(&openbao::sys::OperatorKeyShareUpdateRequest::new(
            SecretString::from("recovery-share"),
            recovery_nonce,
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        recovery_update
            .encoded_token
            .as_ref()
            .map(SecretString::expose_secret),
        Some("encoded-recovery")
    );
    sys.operator_generate_recovery_token_cancel()
        .await
        .unwrap_or_else(|error| panic!("{error}"));

    assert!(
        !sys.operator_rekey_recovery_key_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .started
    );
    sys.operator_rekey_recovery_key_start(
        &openbao::sys::OperatorKeySharesRequest::new(1, 1)
            .unwrap_or_else(|error| panic!("{error}")),
    )
    .await
    .unwrap_or_else(|error| panic!("{error}"));
    let rekey = sys
        .operator_rekey_recovery_key_update(&openbao::sys::OperatorKeyShareUpdateRequest::new(
            SecretString::from("current-recovery-share"),
            rekey_nonce,
        ))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(rekey.complete);
    assert!(!format!("{rekey:?}").contains("new-recovery-share"));
    let backup = sys
        .operator_rekey_recovery_key_backup()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        backup.keys["fingerprint"].expose_secret(),
        "encrypted-share"
    );
    assert!(!format!("{backup:?}").contains("encrypted-share"));
    sys.operator_rekey_recovery_key_delete_backup()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        sys.operator_rekey_recovery_key_verify_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .progress,
        Some(0)
    );
    assert_eq!(
        sys.operator_rekey_recovery_key_verify_cancel()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .progress,
        Some(0)
    );
    let verify = sys
        .operator_rekey_recovery_key_verify_update(
            &openbao::sys::OperatorKeyShareUpdateRequest::new(
                SecretString::from("new-recovery-share"),
                verify_nonce,
            ),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(verify.complete);

    let in_flight = sys
        .in_flight_requests()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        in_flight.0["request-id"]
            .accessor
            .as_ref()
            .map(SecretString::expose_secret),
        Some("token-accessor")
    );
    assert!(!format!("{:?}", in_flight.0["request-id"]).contains("token-accessor"));

    server.join().unwrap_or_else(|error| panic!("{error:?}"));
}
