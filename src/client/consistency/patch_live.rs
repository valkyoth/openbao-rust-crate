//! Strict public-API checks in an isolated exact-patch candidate build.

use super::live::{checked, command, event, future_index, line};
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
    let config = checked(config.timeout(Duration::from_secs(15))).compatibility_policy(checked(
        crate::OpenBaoCompatibilityPolicy::exact(OpenBaoVersion::new(2, 7, 1)),
    ));
    checked(checked(Client::from_config(config)).try_with_token(fixture.token.clone()))
}

async fn context(client: &Client<Authenticated>) -> ConsistencyContext<'_> {
    let report = checked(client.compatibility_report().await);
    assert!(report.status() == OpenBaoCompatibilityStatus::Verified);
    assert!(report.detected_version() == Some(OpenBaoVersion::new(2, 7, 1)));
    assert!(report.profile_version() == Some(OpenBaoVersion::new(2, 7, 1)));
    checked(client.consistency().await)
}

#[tokio::test]
#[ignore = "requires exact patch candidate, three Raft nodes, TLS and private stdin"]
async fn public_consistency_tls() {
    let fixture: Fixture = checked(serde_json::from_reader(std::io::stdin().lock().take(65536)));
    for (number, address) in fixture.addresses.iter().enumerate() {
        let client = client(&fixture, address);
        let ctx = context(&client).await;
        let path = format!("fixture-kv/data/sdk-{number}");
        let write: ConsistencyResponse<Value> = checked(
            ctx.request_json(
                Method::POST,
                &path,
                Some(&json!({"data": {"marker": "sdk-initial"}, "options": {"cas": 0}})),
                None,
                ConsistencyPolicy::ForwardActiveNode,
            )
            .await,
        );
        assert!(write.response["data"]["version"] == 1);
        let index = checked(write.index.ok_or(()));
        let read: ConsistencyResponse<Value> = checked(
            ctx.request_json::<_, ()>(
                Method::GET,
                &path,
                None,
                Some(&index),
                ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
            )
            .await,
        );
        assert!(read.response["data"]["data"]["marker"] == "sdk-initial");
        let other = context(&client).await;
        assert!(matches!(
            other
                .request_json::<Value, ()>(
                    Method::GET,
                    &path,
                    None,
                    Some(&index),
                    ConsistencyPolicy::Fail,
                )
                .await,
            Err(Error::InvalidParameter(_))
        ));
        if number > 0 {
            // Synthetic metadata is fixture-only; public callers cannot create
            // arbitrary scoped indices. Requests still use the public method.
            let future = future_index(&ctx);
            assert!(matches!(
                ctx.request_json::<Value, ()>(
                    Method::GET,
                    &path,
                    None,
                    Some(&future),
                    ConsistencyPolicy::Fail,
                )
                .await,
                Err(Error::Api {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    ..
                })
            ));
        }
    }
}

#[tokio::test]
#[ignore = "requires coordinated exact-patch candidate, controlled lag and TLS relay"]
async fn public_consistency_lag_tls() {
    let fixture: Fixture = checked(line(65536).with_secret(|bytes| serde_json::from_slice(bytes)));
    assert!(
        fixture
            .addresses
            .iter()
            .all(|address| address == &fixture.addresses[0])
    );
    let base = client(&fixture, &fixture.addresses[0]);
    let ctx = context(&base).await;
    let path = "fixture-kv/data/sdk-lag";
    let first = json!({"data": {"marker": "initial"}, "options": {"cas": 0}});
    let write: ConsistencyResponse<Value> = checked(
        ctx.request_json(
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
        ctx.request_json::<_, ()>(
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
    let config = checked(base.config.clone().namespace("fixture-peer"));
    let peer = checked(checked(Client::from_config(config)).try_with_token(fixture.token.clone()));
    let other = context(&peer).await;
    assert!(matches!(
        other
            .request_json::<Value, ()>(
                Method::GET,
                path,
                None,
                Some(&first_index),
                ConsistencyPolicy::Fail,
            )
            .await,
        Err(Error::InvalidParameter(_))
    ));
    event("partition-ready");
    command("partitioned");
    let second = json!({"data": {"marker": "lagged"}, "options": {"cas": 1}});
    let write: ConsistencyResponse<Value> = checked(
        ctx.request_json(
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
        ctx.request_json::<_, ()>(Method::GET, path, None, None, ConsistencyPolicy::Fail)
            .await,
    );
    assert!(stale.response["data"]["data"]["marker"] == "initial");
    for method in [Method::GET, Method::POST] {
        let body = (method == Method::POST).then_some(&second);
        let result = ctx
            .request_json::<Value, _>(method, path, body, Some(&index), ConsistencyPolicy::Fail)
            .await;
        assert!(matches!(
            result,
            Err(Error::Api {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            })
        ));
    }
    // Never-observable synthetic metadata keeps cancellation/timeout outcomes
    // distinct from a subsequent recovery that could commit an in-flight write.
    let future = future_index(&ctx);
    {
        let pending = ctx.request_json::<Value, _>(
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
        command("cancel");
    }
    let config = checked(base.config.clone().timeout(Duration::from_millis(300)));
    let short = checked(checked(Client::from_config(config)).try_with_token(fixture.token.clone()));
    let short_ctx = context(&short).await;
    let future = future_index(&short_ctx);
    assert!(matches!(
        short_ctx
            .request_json::<Value, _>(
                Method::POST,
                "fixture-kv/data/sdk-timeout",
                Some(&second),
                Some(&future),
                ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
            )
            .await,
        Err(Error::Transport("request timed out"))
    ));
    event("recovery-ready");
    command("await");
    let read: ConsistencyResponse<Value> = checked(
        ctx.request_json::<_, ()>(
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
        ctx.request_json::<Value, ()>(
            Method::GET,
            path,
            None,
            Some(&index),
            ConsistencyPolicy::Fail,
        )
        .await,
        Err(Error::OpenBaoCompatibilityProbe(
            "consistency cluster changed"
        ))
    ));
    event("complete");
}
