# OpenBao 2.7.0 Consistency Controls

Status: checkpoint 08a implements bounded header types only. No client transport
integration, profile promotion or live multi-node guarantee is claimed.

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
These values do not enable retries, background tracking, redirection or transport.
No numeric ordering, maximum-index merge, or arrival-order state tracker is added.

Tests cover encoding round trips, header sensitivity, redaction, duplicate
headers, missing/duplicate/unknown JSON fields, type errors, non-ASCII/control
bytes, malformed Base64, exact and exceeded limits, and every policy mapping.
Minimal consistency-only builds are checked independently of optional engines.

## Remaining Checkpoint 08

08b must provide explicit request/response metadata through a scoped context,
without changing ordinary response structs or maintaining a global latest index.
Capture is not yet client-bound: the transport API must bind captured metadata to
the originating client configuration, namespace, and verified cluster identity.
An index from another context must not silently proceed as an unconstrained read.
Initial cluster discovery, restored clusters and namespace changes require tests.
Raw advanced APIs remain caller-owned; parsing types must not imply those paths
enforce the future scoped-context contract.

Every opt-in transport path must check the effective reviewed profile before
sending these headers. Active historical, assumed, rolling-intersection and
newer-server fallback profiles remain unsupported until the normal promotion.
Reserved-header conflicts, repeated/malformed response headers and read responses
without indices need deterministic behavior. Client request timeout bounds the
whole request; server await-state timeout and forwarding are separate semantics.
Keep write retries disabled even on 429, and never interpret timeout as rollback.

08c requires a constrained multi-node TLS fixture with read-enabled standby
behavior, stale-index failure, await success/deadline, forwarding, cluster and
namespace isolation, 429 behavior, cancellation and explicit non-idempotent
no-retry checks. Single-node success or Python-only tests cannot establish public
SDK dispatch or replication guarantees. Record limitations rather than silently
skipping cases. Checkpoint 10 still owns routable profile promotion.
