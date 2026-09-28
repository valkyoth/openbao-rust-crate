# OpenBao 2.7.0 Consistency Controls

Status: checkpoint 08a implements bounded header types; 08b adds staged scoped
transport. No profile promotion or live multi-node guarantee is claimed.

## Tagged Contract

Reviewed exact source commit `ca305a02daa68b203325daa1b25c18d7a252d4b3`:

- `api/index.go`: a standard Base64 JSON object with `cluster` and `value`.
  The value is storage-provider-specific and must remain opaque.
- `internal/http/index.go`: at most one index header. A different cluster's
  index is silently ignored, rather than rejected by the server. The source
  explicitly notes that the index is not currently namespace-aware.
- `api/client.go` and `internal/http/index.go`: policy values are `fail`,
  `forward-active-node`, or `await-state`. Await-state can be followed by a
  second separate header containing fail or forwarding. Comma-joining is not
  equivalent. A lone await-state inherits the listener's fallback configuration.
- `website/content/docs/concepts/consistency.mdx`: writes may return an index;
  its absence on a read is not an error. An inconsistent request using fail gets
  HTTP 429 with Retry-After. Await-state uses a server-configured maximum wait,
  not a per-request timeout header.
- `internal/http/index.go` treats errors checking whether an index has been seen
  as seen. This requires explicit review when documenting eventual guarantees;
  header support alone is not proof of linearizability under all failures.

## 08a Types

The non-default `consistency` feature enables the existing base64-ng dependency
without enabling a secrets engine. `ConsistencyIndex` accepts an explicit
SecretString or captures one response-header occurrence. It caps encoded input
at 4096 bytes before decoding or copying a header. The JSON schema requires
cluster and value strings, rejects duplicate/unknown fields and trailing data,
and bounds cluster/value to 256/2048 visible ASCII bytes. These are conservative
SDK limits, not claims about every future storage provider's output.

Encoded and decoded SDK storage uses sanitizing secret types. Debug and errors
do not echo metadata. Explicit HTTP-header conversion marks the value sensitive,
but dependency-owned header allocations and JSON parser scratch retain the
usual memory-cleanup limitations. The index is not an authentication credential.
Matching a cluster string is not proof of cluster provenance or namespace scope.

`ConsistencyPolicy` only emits fixed ordered values. Await-state always has an
explicit typed fallback; it does not silently depend on listener defaults.
These values alone do not enable retries, background tracking or transport.
No numeric ordering, maximum-index merge, or arrival-order state tracker is added.

Tests cover encoding round trips, header sensitivity, redaction, duplicate
headers, missing/duplicate/unknown JSON fields, type errors, non-ASCII/control
bytes, malformed Base64, exact and exceeded limits, and every policy mapping.
Minimal consistency-only builds are checked independently of optional engines.

## 08b Scoped Transport

`Client::consistency().await` creates an independent context borrowing an immutable
authenticated client. It checks the effective compatibility report and discovers
cluster identity through bounded TLS health decoding without sending credentials.
Only a verified exact/automatic reviewed profile can qualify; assumed, rolling
range, historical and unknown-newer fallback profiles fail closed. The additional
routable-profile gate still blocks 2.7.0 until checkpoint 10.

`ConsistencyContext::request_json` is an advanced interface requiring both raw-API
acknowledgement features. Engine-specific body validation remains caller-owned,
as with the existing raw and wrapping APIs. It accepts no arbitrary headers.
Every request rechecks the profile, context ownership and current cluster health
before sending credentials. Health must identify an initialized, unsealed 2.7.0
server and the context's original nonempty cluster. The policy's ordered header
occurrences are appended separately, not joined or overwritten. Existing token,
namespace, encrypted-transport, sanitizing-body and response-size controls apply.

`ConsistencyResponse<T>` preserves the full JSON response and optional scoped
index; it does not change ordinary response structs. Captured indices carry an
unforgeable in-process context identity. Even another context on the same client
cannot reuse them. Unscoped parsing types cannot be imported into this transport.
Missing response indices are accepted; malformed, duplicate or wrong-cluster
indices fail. No global latest-index tracker, ordering, merge, retry or background
task is added. HTTP 429 returns a redacted API error, including for writes.

Cluster preflight and the target operation each use the client request timeout,
not a combined deadline. Cancellation or a response-decoding error after a write
does not establish rollback or make replay safe. A preflight cannot atomically
bind a subsequent operation to a cluster: a load balancer spanning clusters, or a
restored cluster retaining its identity, remains outside this guarantee. Use a
trusted endpoint serving one cluster. SDK context scoping does not repair the
server's lack of namespace scoping or its index-check error semantics.

Regression tests exercise the production transport helper beneath the promotion
gate against local mocks, not a public 2.7 routing bypass. They cover capture and
reuse, separate await/fallback headers, namespace/token handling, context rejection,
changed cluster and invalid health, invalid response metadata/JSON, body limits,
serialization errors, sanitizing-body cleanup, 429 without replay, and timeout and
cancellation after transport begins. Public methods remain tested to reject all
currently active profiles. The private mock setup does not constitute live proof.

## Remaining Checkpoint 08

08c requires a constrained multi-node TLS fixture with read-enabled standby
behavior, stale-index failure, await success/deadline, forwarding, cluster and
namespace isolation, 429 behavior, cancellation and explicit non-idempotent
no-retry checks. Single-node success or Python-only tests cannot establish public
SDK dispatch or replication guarantees. Record limitations rather than silently
skipping cases. Checkpoint 10 still owns routable profile promotion.
