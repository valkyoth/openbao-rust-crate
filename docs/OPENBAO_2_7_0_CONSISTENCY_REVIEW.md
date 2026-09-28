# OpenBao 2.7.0 Consistency Controls

Status: checkpoint 08a implements bounded header types; 08b adds staged scoped
transport. Checkpoint 08c has retained server-protocol, staged SDK TLS, and
controlled-lag server evidence, plus coordinated SDK lag/cancellation evidence.
Live cross-cluster isolation is verified in the coordinated SDK report. No profile promotion or general
consistency guarantee is claimed.

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

## Checkpoint 08c Verification

08c starts with `scripts/openbao_2_7_consistency.py`, a staged three-node Raft
server-protocol fixture. A successful live run is retained in
`compat/onboarding/2.7.0/consistency-protocol-tls.json` and independently digest-pinned
by `scripts/verify_openbao_2_7_consistency.py`. It verifies three voting
members, one active and two unsealed standbys, signed-image provenance, TLS 1.3,
certificate/protocol rejection, loopback-only publication, isolated networking,
resource limits and cleanup. Storage is disposable bounded tmpfs, root-owned with
mode 0770 so the existing `100:0` server identity can write through its primary
group without using unsupported Podman tmpfs uid/gid options. Other users have no
directory access. A real write
index must become readable from both standbys. Separately, a synthetic valid Raft
index beyond reachable state exercises fail/await/forward handling and rejection
of a write without advancing KV2's version. Those synthetic checks are **not**
controlled replication-lag evidence. The report marks both live SDK verification
and controlled-lag verification false and never promotes routing.

Run from the repository with:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_consistency.py
```

The fixture uses up to three 1 GiB container memory limits and keeps disposable
credentials out of command arguments, logs and retained evidence. Python-managed
credential copies are not claimed to be sanitizing allocations. Offline tests
also enforce a 30-second init/join/unseal socket timeout while ordinary protocol
requests retain five seconds; no automatic ceremony retries are added. Tests
cover header occurrence handling, bounds, node configuration, network address
validation, protocol assertions, failure diagnostics and cleanup on partial setup.
The indexed standby-read loop permits bounded setup retries only for the two
exact KV v2 initialization errors in the pinned server's `kv/upgrade.go`.
These errors do not count as successful consistency checks: each standby must
still return HTTP 200 with the expected value. Other HTTP 400 responses remain
fatal, and persistent initialization exhausts the existing 120-attempt bound.
The retained report's source hashes and limited claims are checked in CI, with
regression tests rejecting input mutation, omission and stronger claims.
No pre-existing single-node report substitutes for this run.

### Staged SDK TLS Test

`src/client/consistency/live.rs` adds an ignored unit test calling the production
transport beneath the profile gate. It never enables a public bypass. The separate
`scripts/openbao_2_7_consistency_sdk.py` runner repeats the constrained three-node
setup and server-protocol checks before running that test as the invoking user
with supplementary groups and capabilities removed. Credentials travel through
stdin, not arguments or environment variables. Child output is suppressed, execution
is bounded, and failure/cancellation kills and reaps the child before container
cleanup. The runner checks that the exact test exists, since libtest otherwise
returns success for a filter matching no tests.

Build as the ordinary repository user:

```sh
cargo test --locked --no-default-features --features consistency,rustls-tls --lib --no-run
```

Use the absolute path of the `target/debug/deps/openbao-...` executable printed by
Cargo (not a different build or a shell wrapper):

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_consistency_sdk.py --test-binary /absolute/path/to/target/debug/deps/openbao-HASH
```

The test covers TLS-root-restricted SDK transport, index capture/reuse, rejection
of an index from another context, separate await/fallback values, 429 on an
inconsistent write without a KV version change, wait expiry, and forwarding.
Its successful live run is retained in
`compat/onboarding/2.7.0/consistency-sdk-tls.json` and independently digest-pinned
by `scripts/verify_openbao_2_7_consistency_sdk.py`. The captured executable digest
was checked against the locally built binary. Reports bind all Rust source files, build metadata and
the selected executable digest, but these are local trusted-workspace evidence,
not reproducible-build attestations. The separate coordinated report below covers
SDK lag/cancellation and live cross-cluster isolation.

### Controlled Lag Fixture

The successful live run is retained in
`compat/onboarding/2.7.0/consistency-lag-tls.json`, independently digest-pinned by
`scripts/verify_openbao_2_7_consistency_lag.py`. Regression tests reject changed or
omitted source hashes, altered wait windows, and stronger SDK or routing claims.

`scripts/openbao_2_7_consistency_lag.py` creates a separate disposable three-node
cluster and repeats the server-protocol baseline. It pins one labeled standby's
network namespace, rejects the host namespace, and uses protected `nsenter`/`nft`
tools to install a private temporary table dropping only TCP port 8201 inside
that namespace. The host firewall is not changed, HTTPS port 8200 remains
available, and the other two nodes retain a Raft quorum. Removal is attempted
before the namespace FD is closed; all containers and the network are cleaned
up on success, assertion failure or interruption. No broad flush command is used.

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_consistency_lag.py
```

The test requires observing the old KV2 value after a new committed write, 429
for its real index, an inconsistent write rejected without a version change,
await expiry while isolated, and an awaited read returning the new value after
the filter is removed. Expiry still uses the original 250 ms listener. Recovery
uses a second loopback-published TLS 1.3 listener with a 10-second server wait
and a 15-second client socket timeout, allowing for TCP/Raft retry latency after
packet loss. Both listeners undergo certificate/protocol rejection and matching
cluster identity checks. The same recovery request must return HTTP 200 with
the updated value; it is not retried or forwarded. Recovery timeout or HTTP 429
is a failure, not accepted evidence.
This report remains server-protocol-only: it does not establish SDK behavior
under controlled lag, live SDK cancellation, or public profile promotion.
The previously retained protocol and SDK reports are unchanged.

### SDK Lag Test Infrastructure

`scripts/consistency_tls_relay.py` prepares a private TLS relay for the remaining
SDK lag and cancellation checks. A captured index is context-bound; moving it
from a leader client to a separate standby client would invalidate the test.
The relay instead provides one immutable loopback TLS endpoint for the same
cluster. Unindexed writes go to the active node; reads and indexed writes go to
the selected standby. Both hops require certificate-verified TLS 1.3.

The relay accepts only fixed test paths and bounded bodies/metadata, preserves
separate policy header occurrences, rejects ambiguous request framing, requires
the disposable fixture credential for data operations, and does not log
credentials, bodies or indices. It limits concurrency to four connections,
observations to 128 requests, and connection lifetime to 20 seconds. Observations
record transmission to the upstream TLS connection, not proof of server execution
or rollback on cancellation. It is test infrastructure, not a supported proxy.

Local TLS regressions are in `scripts/test_consistency_tls_relay.py`. They are
not live OpenBao evidence. The coordinated ignored Rust test
`staged_consistency_lag_tls` and `scripts/openbao_2_7_consistency_sdk_lag.py` now
wire this relay to the production SDK transport beneath the profile gate.
Their successful live run is retained in
`compat/onboarding/2.7.0/consistency-sdk-lag-tls.json`, independently digest-pinned
by `scripts/verify_openbao_2_7_consistency_sdk_lag.py`. The baseline SDK test was
rerun with the same rebuilt executable and its evidence pin refreshed; source
hash validation was not weakened. Both SDK reports were refreshed by the successful
independent-cluster run and match the current source and executable hashes. The protocol
and server-only lag reports remain valid and unchanged.

Build the minimal test binary as above, then run:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_consistency_sdk_lag.py --test-binary /absolute/path/to/target/debug/deps/openbao-HASH
```

This runner repeats the original SDK baseline and emits two reports only after
the combined run succeeds and cleanup finishes. The child uses bounded private
stdin/stdout pipes with fixed stage messages; arbitrary child output is never
printed. The controller confirms TLS transmission of cancellation and timeout
requests, retains the same SDK context for real-index lag/recovery, and checks
that a foreign namespace context rejects the index without dispatch. Cancellation
and timeout use explicitly synthetic unreachable indices; they do not claim
rollback of a real write. Upstream handlers are drained before final KV2 state
checks; neither those requests nor the inconsistent write may cause a version
change or be automatically retried.

The runner now also initializes a fourth, independent node (up to 4 GiB total
configured container memory limits). After lag recovery, it keeps the SDK
context and relay endpoint unchanged, switches both relay destinations to that
independent cluster, and requires the SDK's unauthenticated health preflight to
reject the changed cluster identity without dispatching the authenticated
operation. The independent node must report a distinct cluster ID and is never
joined to the original cluster. Local tests cover destination validation,
identity rejection, unexpected authenticated dispatch, and resource cleanup.
This additional live check passed; it tests a stable switch between requests,
not atomic protection against a backend changing between preflight and dispatch.

08c requires a constrained multi-node TLS fixture with read-enabled standby
behavior, stale-index failure, await success/deadline, forwarding, cluster and
namespace isolation, 429 behavior, cancellation and explicit non-idempotent
no-retry checks. Single-node success or Python-only tests cannot establish public
SDK dispatch or replication guarantees. Record limitations rather than silently
skipping cases. Checkpoint 10 still owns routable profile promotion.
