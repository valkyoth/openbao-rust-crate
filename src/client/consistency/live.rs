//! Staged TLS transport test beneath the public promotion gate, never a public bypass.

use super::*;
use crate::consistency::ConsistencyFallback;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    addresses: [String; 3],
    ca_pem: String,
    token: SecretString,
}

fn checked<T, E>(result: core::result::Result<T, E>) -> T {
    #[allow(clippy::panic)]
    result.unwrap_or_else(|_| panic!("staged consistency TLS assertion failed"))
}

fn client(fixture: &Fixture, address: &str) -> Client<Authenticated> {
    let url = checked(Url::parse(address));
    assert!(url.scheme() == "https" && url.host_str() == Some("127.0.0.1"));
    assert!(url.username().is_empty() && url.password().is_none());
    assert!(url.path() == "/" && url.query().is_none() && url.fragment().is_none());
    let config = checked(OpenBaoConfig::new(address));
    let config = checked(
        config.only_root_certificates(vec![checked(Certificate::from_pem(
            fixture.ca_pem.as_bytes(),
        ))]),
    );
    let config = checked(config.timeout(Duration::from_secs(5)));
    checked(checked(Client::from_config(config)).try_with_token(fixture.token.clone()))
}

async fn context(client: &Client<Authenticated>) -> ConsistencyContext<'_> {
    ConsistencyContext {
        client,
        cluster: checked(discover_cluster(client).await),
        identity: Arc::new(()),
    }
}

fn future_index(context: &ConsistencyContext<'_>) -> ScopedConsistencyIndex {
    let value = json!({"cluster": context.cluster.expose_secret(), "value": u64::MAX.to_string()});
    let encoded =
        checked(base64_ng::STANDARD.encode_secret(checked(serde_json::to_vec(&value)).as_slice()));
    let text = checked(encoded.try_into_exposed_string());
    ScopedConsistencyIndex {
        index: checked(ConsistencyIndex::from_encoded(SecretString::from(
            text.into_exposed_unprotected_string_caller_must_zeroize(),
        ))),
        identity: Arc::clone(&context.identity),
    }
}

#[tokio::test]
#[ignore = "requires disposable three-node TLS fixture and bounded stdin credentials"]
async fn staged_consistency_tls() {
    // Deserialize the token directly to secret storage; never echo parser errors.
    let fixture: Fixture = checked(serde_json::from_reader(std::io::stdin().lock().take(65536)));
    for (number, address) in fixture.addresses.iter().enumerate() {
        let client = client(&fixture, address);
        let context = context(&client).await;
        let path = format!("fixture-kv/data/sdk-{number}");
        let payload = json!({"data": {"marker": "sdk-initial"}, "options": {"cas": 0}});
        let written: ConsistencyResponse<Value> = checked(
            context
                .execute(
                    Method::POST,
                    &path,
                    Some(&payload),
                    None,
                    ConsistencyPolicy::ForwardActiveNode,
                )
                .await,
        );
        assert!(written.response["data"]["version"] == 1);
        let index = checked(written.index.ok_or(()));
        let read: ConsistencyResponse<Value> = checked(
            context
                .execute::<_, ()>(
                    Method::GET,
                    &path,
                    None,
                    Some(&index),
                    ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
                )
                .await,
        );
        assert!(read.response["data"]["data"]["marker"] == "sdk-initial");

        let other = ConsistencyContext {
            client: &client,
            cluster: context.cluster.clone(),
            identity: Arc::new(()),
        };
        assert!(matches!(
            other
                .execute::<Value, ()>(
                    Method::GET,
                    &path,
                    None,
                    Some(&index),
                    ConsistencyPolicy::Fail
                )
                .await,
            Err(Error::InvalidParameter(_))
        ));

        // Addresses are ordered active then standbys by the verified harness.
        if number == 0 {
            continue;
        }
        let future = future_index(&context);
        let update = json!({"data": {"marker": "must-not-write"}});
        let rejected = context
            .execute::<Value, _>(
                Method::POST,
                &path,
                Some(&update),
                Some(&future),
                ConsistencyPolicy::Fail,
            )
            .await;
        assert!(matches!(
            rejected,
            Err(Error::Api {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            })
        ));
        let start = std::time::Instant::now();
        let rejected = context
            .execute::<Value, ()>(
                Method::GET,
                &path,
                None,
                Some(&future),
                ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
            )
            .await;
        assert!(matches!(
            rejected,
            Err(Error::Api {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            })
        ));
        assert!(start.elapsed() >= Duration::from_millis(150));
        let read: ConsistencyResponse<Value> = checked(
            context
                .execute::<_, ()>(
                    Method::GET,
                    &path,
                    None,
                    Some(&future),
                    ConsistencyPolicy::AwaitState(ConsistencyFallback::ForwardActiveNode),
                )
                .await,
        );
        assert!(read.response["data"]["metadata"]["version"] == 1);
        assert!(read.response["data"]["data"]["marker"] == "sdk-initial");
    }
}

fn line(limit: usize) -> SecretVec {
    let mut writer = BoundedSecretWriter::new(limit);
    let mut input = std::io::stdin().lock();
    loop {
        let mut byte = [0];
        checked(input.read_exact(&mut byte));
        if byte[0] == b'\n' {
            return writer.into_secret();
        }
        checked(writer.try_extend(&byte));
    }
}

fn command(expected: &str) {
    assert!(line(64).with_secret(|bytes| bytes == expected.as_bytes()));
}

fn event(name: &str) {
    let mut output = std::io::stdout().lock();
    checked(writeln!(output, "CONSISTENCY:{name}"));
    checked(output.flush());
}

#[tokio::test]
#[ignore = "requires coordinated controlled-lag TLS relay and private stdin protocol"]
async fn staged_consistency_lag_tls() {
    let fixture: Fixture = checked(line(65536).with_secret(|bytes| serde_json::from_slice(bytes)));
    let base = client(&fixture, &fixture.addresses[0]);
    let configured = checked(base.config.clone().timeout(Duration::from_secs(15)));
    let base =
        checked(checked(Client::from_config(configured)).try_with_token(fixture.token.clone()));
    let ctx = context(&base).await;
    let path = "fixture-kv/data/sdk-lag";
    let first = json!({"data": {"marker": "initial"}, "options": {"cas": 0}});
    let write: ConsistencyResponse<Value> = checked(
        ctx.execute(
            Method::POST,
            path,
            Some(&first),
            None,
            ConsistencyPolicy::ForwardActiveNode,
        )
        .await,
    );
    assert!(write.response["data"]["version"] == 1);
    let first_index = checked(write.index.ok_or(()));
    let read: ConsistencyResponse<Value> = checked(
        ctx.execute::<_, ()>(
            Method::GET,
            path,
            None,
            Some(&first_index),
            ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
        )
        .await,
    );
    assert!(read.response["data"]["data"]["marker"] == "initial");
    event("scope-ready");
    command("scope");
    let namespace = checked(base.config.clone().namespace("fixture-peer"));
    let namespace =
        checked(checked(Client::from_config(namespace)).try_with_token(fixture.token.clone()));
    let other = context(&namespace).await;
    assert!(matches!(
        other
            .execute::<Value, ()>(
                Method::GET,
                path,
                None,
                Some(&first_index),
                ConsistencyPolicy::Fail
            )
            .await,
        Err(Error::InvalidParameter(_))
    ));
    event("partition-ready");
    command("partitioned");

    let second = json!({"data": {"marker": "lagged"}, "options": {"cas": 1}});
    let write: ConsistencyResponse<Value> = checked(
        ctx.execute(
            Method::POST,
            path,
            Some(&second),
            None,
            ConsistencyPolicy::ForwardActiveNode,
        )
        .await,
    );
    assert!(write.response["data"]["version"] == 2);
    let index = checked(write.index.ok_or(()));
    let stale: ConsistencyResponse<Value> = checked(
        ctx.execute::<_, ()>(Method::GET, path, None, None, ConsistencyPolicy::Fail)
            .await,
    );
    assert!(stale.response["data"]["data"]["marker"] == "initial");
    for method in [Method::GET, Method::POST] {
        let rejected = ctx
            .execute::<Value, _>(
                method.clone(),
                path,
                if method == Method::POST {
                    Some(&second)
                } else {
                    None
                },
                Some(&index),
                ConsistencyPolicy::Fail,
            )
            .await;
        assert!(matches!(
            rejected,
            Err(Error::Api {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            })
        ));
    }

    let future = future_index(&ctx);
    {
        let pending = ctx.execute::<Value, _>(
            Method::POST,
            "fixture-kv/data/sdk-cancel",
            Some(&second),
            Some(&future),
            ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
        );
        tokio::pin!(pending);
        let completed = tokio::select! {
            _ = &mut pending => true,
            () = tokio::time::sleep(Duration::from_millis(300)) => false,
        };
        assert!(!completed, "cancel request completed before observation");
        event("cancel-ready");
        // The harness confirms upstream TLS transmission before allowing drop.
        command("cancel");
    }
    let short = checked(base.config.clone().timeout(Duration::from_millis(300)));
    let short = checked(checked(Client::from_config(short)).try_with_token(fixture.token.clone()));
    let short_ctx = context(&short).await;
    let future = future_index(&short_ctx);
    let timeout = short_ctx
        .execute::<Value, _>(
            Method::POST,
            "fixture-kv/data/sdk-timeout",
            Some(&second),
            Some(&future),
            ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
        )
        .await;
    assert!(matches!(
        timeout,
        Err(Error::Transport("request timed out"))
    ));
    event("recovery-ready");
    command("await");
    let read: ConsistencyResponse<Value> = checked(
        ctx.execute::<_, ()>(
            Method::GET,
            path,
            None,
            Some(&index),
            ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
        )
        .await,
    );
    assert!(read.response["data"]["data"]["marker"] == "lagged");
    assert!(read.response["data"]["metadata"]["version"] == 2);
    event("isolation-ready");
    command("switched");
    assert!(matches!(
        ctx.execute::<Value, ()>(
            Method::GET,
            path,
            None,
            Some(&index),
            ConsistencyPolicy::Fail
        )
        .await,
        Err(Error::OpenBaoCompatibilityProbe(
            "consistency cluster changed"
        ))
    ));
    event("complete");
}
