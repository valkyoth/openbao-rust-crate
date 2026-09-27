# OpenBao 2.7.0 Control Groups Review

Status: checkpoint 07a implements explicit authorization and validated secret
accessors. Checkpoint 07 is not complete. Request review, approval-aware wrapping,
live lifecycle evidence and the ACL builder decision remain open. No 2.7 routing
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
terminology; later policy-builder decisions must use the parser contract rather
than copying its examples blindly.

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

## Remaining Checkpoint 07

1. Add typed request review with bounded secret-aware `request_data`, requester
   and authorization metadata. Reject duplicate keys and excessive nesting,
   counts and bytes without materializing arbitrary secrets as ordinary JSON.
2. Add explicit approval-aware response handling and token ownership through
   deferred execution, cancellation, failed decoding and replay attempts. Preserve
   namespace binding. Do not treat a denied or expired approval as a normal
   wrapped response, or silently retry side-effecting requests.
3. Review narrowly typed control-group policy construction against the actual
   parser. Keep opaque `PolicyWriteRequest` available; do not weaken existing
   policy escaping or capability validation.
4. Retain live TLS evidence for independent approvers, self-approval denial,
   insufficient factors, expiration, namespace mismatch, replay and cancellation.
   Test original request/response shapes and metadata redaction. Python evidence
   alone cannot promote public SDK routing.
5. At checkpoint 10, exercise successful registered SDK dispatch and mixed/older
   profile regression cases before promoting the staged profile.
