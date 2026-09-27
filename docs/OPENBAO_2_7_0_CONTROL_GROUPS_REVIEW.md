# OpenBao 2.7.0 Control Groups Review

Status: checkpoints 07a/b/c/d implement explicit authorization, validated secret
accessors, bounded request review, explicit deferred-execution handling and narrow
typed policy construction. Checkpoint 07 is not complete:
live lifecycle evidence remains open. No 2.7 routing
is promoted.

## Reviewed Contract

The locked 2.7.0 source (`ca305a02daa68b203325daa1b25c18d7a252d4b3`)
defines these operations in `internal/vault/logical_system_paths.go` and
`internal/vault/control_group.go`:

- `POST sys/control-group/authorize` takes a wrapping-token accessor and returns
  `data.approved` as a boolean. It records the current principal's authorization
  where permitted, then checks whether the policy factors are satisfied.
- `POST sys/control-group/request` takes the same accessor and returns approval
  state, original operation/path/data, requester identity and authorizations.
  The handler returns a full `logical.Entity`, not merely the two identity fields
  illustrated by the API documentation. Unknown identity metadata must not be
  assumed public or discarded without a deliberate schema decision.
- The control-group workflow stores the original request for deferred execution.
  Unwrapping an approved token executes that request and returns its original
  wire response. Approval is not execution, and a wrapping token is not an
  accessor. Cancellation or a lost response cannot establish server rollback.

Sources: tagged `website/content/docs/api/system/control-group.mdx`,
`website/content/docs/concepts/control-groups.mdx`, the handlers above, and
`internal/vault/wrapping.go`. The concept page contains inconsistent self-approval
terminology; the policy builder uses the parser contract rather than copying its
examples blindly. It also requires explicit controlled capabilities where some
concept examples imply omission is permitted.

## 07a Implementation

`sys::control_groups::ControlGroupAccessor` requires a `SecretString`, validates
1..=4096 visible ASCII bytes and redacts Debug. Its storage is private and cannot
be overwritten or deserialized around validation. Construction does not validate
existence, expiry, namespace or permissions. The server remains responsible for
those checks. Serialization is confined to a private request payload, with the
accessor in the sanitizing JSON body, not the path/query.

`Sys::authorize_control_group` is an explicit authenticated POST using the
client's configured namespace and credentials. No operator feature is required:
an approver can be a delegated application principal. No automatic approval,
request replay or unwrap is introduced. `ControlGroupApproval` requires a
non-null boolean and rejects duplicate `approved` fields. It is a point-in-time
status, not a capability or promise that a later unwrap will succeed.

The selected compatibility profile must be at least 2.7, followed by the normal
registered endpoint dispatch. All 25 active profiles, unselected compatibility
and acknowledged newer-server fallback remain rejected. Tests cover constructor
boundaries and controls, secret-free diagnostics, request serialization, strict
approval decoding and no operation transport on incompatible profiles.

## 07b Implementation

`Sys::read_control_group_request` uses the registered secret-response transport,
with the same compatibility gate, configured namespace and body-only accessor.
It does not approve, unwrap or replay. HTTP error bodies are not exposed.

`ControlGroupRequest` retains payload and the complete requester entity as
`ControlGroupRequestData`, backed by `SecretVec`. Explicit `with_json_bytes`
inspection avoids materializing an ordinary secret-bearing JSON value tree.
Operation/path and authorizer identity strings use `SecretString`. All Debug
implementations redact contents. Malformed responses yield a fixed decode error.

The decoder caps the whole envelope at 512 KiB, 16 nested containers, 4096 value
nodes, 256 members per container and 64 KiB per decoded string/key. These bounds
also cover unknown fields. A first validation pass rejects duplicate keys at
every depth, including escaped-equivalent keys, before typed decoding. Payload
must be an object or null; requester metadata must be an object. Required fields
are not silently defaulted. The 512 KiB cap applies before parsing, not during
network collection: the client response-byte limit bounds transport storage.

SDK-owned payload and duplicate-detection key storage sanitize on drop. Serde's
escaped-string scratch storage and HTTP/TLS buffers remain dependency residuals;
this is not a guarantee of total process-memory cleanup. Callers can introduce
their own copies through explicit inspection and must handle them accordingly.

Tests cover valid nested/escaped JSON, full entity metadata retention, null
payloads, redaction, malformed/type-invalid/missing fields, duplicate keys,
exact and exceeded decoder limits, and rejection before operation transport on
all active profiles and newer-server fallback. Positive registered SDK dispatch
and live server authorization semantics still require later evidence.

## Remaining Checkpoint 07

1. Retain live TLS evidence for independent approvers, self-approval denial,
   insufficient factors, expiration, namespace mismatch, replay and cancellation.
   Test original request/response shapes and metadata redaction. Python evidence
   alone cannot promote public SDK routing. Include policies emitted by the
   typed builder and verify their actual approval requirements.
2. At checkpoint 10, exercise successful registered SDK dispatch and mixed/older
   profile regression cases before promoting the staged profile.

## 07c Execution Ownership

The pinned `request_handling.go` defers the original request and executes it on
approved unwrap. It returns ordinary wrapping metadata without a reliable
control-group discriminator. The SDK therefore does not infer deferred state
from an accessor, TTL or creation path. Callers explicitly transfer an existing
`WrappedResponse<T>` using `into_control_group_execution`. This conversion sends
no request, asserts no approval and cannot track earlier attempts made through
other handles. The original wrapper API remains compatible, with corrected docs
warning that unwrap may execute a deferred write.

`ControlGroupExecution` retains its original client and configured namespace.
`try_execute_bytes` requires the promoted 2.7 profile, then sends an authenticated
registered POST to `sys/wrapping/unwrap`. OpenBao enforces approval, expiry and
token namespace; the SDK never treats cached `approved` metadata as permission.
Only HTTP 200/204 are accepted. The bounded response uses sanitizing byte storage
and preserves the entire original wire shape, including nested KV v2 data and
PKI responses. No-content responses return empty bytes. `try_execute` decodes
the entire response as `T`, not an assumed inner `data` field. Use secret-aware
types for `T`; arbitrary caller deserializers and dependency parser scratch can
create ordinary allocations outside this guarantee.

Local state starts `Ready`. Incompatible profiles leave it unchanged and send
no execution request. Tokens must be 1..=65536 visible ASCII bytes; empty or
malformed tokens fail locally, never selecting OpenBao's authenticated-token
fallback for an empty unwrap payload. Before transport starts it becomes `OutcomeUnknown`:
denial, expiry, timeout, disconnect or cancellation cannot reset it. The handle
retains credentials for deliberate application recovery but refuses any further
attempt. A complete accepted response sets `ResponseReceived` and clears the
local token/accessor before typed decoding, even if decoding then fails. This
does not assert server-side success beyond the received status. Other token
copies remain outside the local guard; dropping the handle does not revoke the
token, and a failed call never proves that a deferred write was rolled back.

Tests use the production transport helper after its separate compatibility gate
to check namespace/token placement, exact response bytes, typed shape decoding,
no-content behavior, denial/error redaction, malformed success responses, timeout,
disconnection and cancellation after the mock server received the request. They
check local replay rejection and rejection before transport for every active
profile. These tests do not promote 2.7 or replace live server lifecycle evidence;
successful public SDK dispatch is still required at checkpoint 10.

## 07d Policy Builder Decision

Implement a deliberately narrow identity-factor form, based on the locked
`internal/vault/policy/policy.go` parser and `control_group.go` evaluator:

- The actual self-approval key is `self_auth_allowed`, at control-group scope.
  Emit `false` explicitly. There is no typed option enabling self-approval.
- Every factor must include nonempty `controlled_capabilities`. Emit all of the
  rule's operations for every factor, never an implicit default. `Sudo` is not an
  operation and `Deny` is not an approval workflow; reject both and duplicates.
- Every applicable factor must meet its threshold. An entity belonging to
  several groups can contribute to several factors; do not claim disjointness.
- Only group names are modeled by this parser, not group IDs. The SDK does not
  invent a group-ID field or resolve identity groups before policy writing.

`ControlGroupFactor` accepts 1..=16 unique names and 1..=128 required approvals.
Names use a restricted ASCII alphabet (alphanumerics, spaces, `.`, `_`, `-`,
starting with an alphanumeric), capped at 128 bytes; factor labels use the same
alphabet capped at 64 bytes. `ControlGroupRequirement` requires 1..=8 unique
factor labels and a whole-second TTL of 1..=86400 seconds. These are conservative
SDK bounds, not a claim about the server's maximums. Iterators stop on overflow
without collecting unbounded lists. Existing 128-rule/16-KiB document limits
remain enforced. Constructors expose no mutable fields or Deserialize bypass.

`AclPolicyBuilder::allow_path_with_control_group` preserves existing path and
HCL-string validation, validates before insertion, and rejects exact-path
collisions involving protected rules in either insertion order. Wildcard
overlaps, other policies and group membership changes still need operator review.
Generated HCL uses fixed structural keys and numeric values; accepted labels and
group names cannot introduce templates, quotes, delimiters or control characters.

The ordinary `build_write_request` rejects builders containing these new rules.
Use `build_control_group_write_request`, which returns an opaque, non-serializable
`ControlGroupPolicyWriteRequest`, and `Sys::write_control_group_policy`. That
writer checks the 2.7 compatibility contract before invoking normal ACL writing;
all active profiles and newer-server fallback are still rejected before policy
transport. The operation replaces the named policy; it neither provisions groups
nor approves requests. Debug redacts the new factor/requirement/request contents.

Plain `build()` export and opaque `PolicyWriteRequest` remain explicit escape
hatches for advanced naming, selective factor operations, self-approval, combined
wrapping constraints or other HCL. They carry no structured compatibility guard:
the caller must verify server support and actual enforcement. The new typed form
does not change or reinterpret existing ordinary policy documents.

Tests cover exact generated HCL, parser field names, bounds, injection inputs,
iterator termination, atomic failed insertion, collision ordering, redaction,
document limits and policy-write rejection on every active/fallback profile.
Source review and golden-output tests are not live enforcement evidence. The
remaining TLS lifecycle fixture must exercise this policy with real identities
before checkpoint 07 can be considered complete.
