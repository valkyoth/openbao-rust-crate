//! Secret-exclusion regression for the optional tracing integration.

#![cfg(all(
    feature = "tracing",
    feature = "transit",
    feature = "transit-bytes",
    feature = "sensitive-http-test-only"
))]
#![allow(clippy::panic)]

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread,
};

use openbao::{Client, OpenBaoConfig, SecretString};

#[derive(Clone)]
struct CapturingSubscriber {
    output: Arc<Mutex<String>>,
    next_span: Arc<AtomicU64>,
}

struct CapturingVisitor<'a>(&'a Mutex<String>);

impl tracing::field::Visit for CapturingVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        let mut output = self.0.lock().unwrap_or_else(|error| error.into_inner());
        use core::fmt::Write as _;
        let _ = write!(output, "{}={value:?};", field.name());
    }
}

impl tracing::Subscriber for CapturingSubscriber {
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        {
            let mut output = self
                .output
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            output.push_str(attributes.metadata().name());
            output.push(';');
        }
        attributes
            .values()
            .record(&mut CapturingVisitor(&self.output));
        tracing::span::Id::from_u64(self.next_span.fetch_add(1, Ordering::SeqCst) + 1)
    }

    fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut CapturingVisitor(&self.output));
    }

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        {
            let mut output = self
                .output
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            output.push_str(event.metadata().name());
            output.push(';');
        }
        event.record(&mut CapturingVisitor(&self.output));
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[tokio::test(flavor = "current_thread")]
async fn typed_transit_tracing_excludes_secret_material() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));
    let server = thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut request = [0_u8; 4096];
            let read = stream
                .read(&mut request)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&request[..read]);
            let body = if index == 0 {
                assert!(request.contains(r#""plaintext":"dHJhY2Utc2VjcmV0LXJhdw==""#));
                r#"{"data":{"ciphertext":"vault:v1:trace-ciphertext","key_version":1}}"#
            } else {
                assert!(request.contains(r#""ciphertext":"vault:v1:trace-ciphertext""#));
                r#"{"data":{"plaintext":"dHJhY2Utc2VjcmV0LXJhdw=="}}"#
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap_or_else(|error| panic!("{error}"));
        }
    });

    let output = Arc::new(Mutex::new(String::new()));
    let subscriber = CapturingSubscriber {
        output: output.clone(),
        next_span: Arc::new(AtomicU64::new(0)),
    };
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let config = OpenBaoConfig::new(format!("http://{address}"))
        .and_then(OpenBaoConfig::allow_sensitive_local_http_for_tests)
        .unwrap_or_else(|error| panic!("{error}"));
    let client = Client::from_config(config)
        .and_then(|client| client.try_with_token(SecretString::from("trace-test-token")))
        .unwrap_or_else(|error| panic!("{error}"));
    let transit = client
        .transit("transit")
        .unwrap_or_else(|error| panic!("{error}"));
    let encrypted = transit
        .encrypt(
            "trace-key-identifier",
            &openbao::secrets::transit::TransitEncryptRequest::from_plaintext_bytes(
                b"trace-secret-raw",
            )
            .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let decrypted = transit
        .decrypt(
            "trace-key-identifier",
            &openbao::secrets::transit::TransitDecryptRequest::new(encrypted.ciphertext),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    drop(decrypted);
    server.join().unwrap_or_else(|error| panic!("{error:?}"));

    let captured = output
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    assert!(captured.contains("openbao.request"));
    assert!(captured.contains("OpenBao request"));
    assert!(captured.contains("OpenBao response"));
    for secret in [
        "trace-secret-raw",
        "dHJhY2Utc2VjcmV0LXJhdw==",
        "vault:v1:trace-ciphertext",
        "trace-test-token",
        "trace-key-identifier",
    ] {
        assert!(!captured.contains(secret), "tracing exposed {secret}");
    }
}
