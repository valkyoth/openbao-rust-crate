# OpenBao 2.6.0 Support Plan

## Status

- Planning baseline: crate `2.0.2`, toolchain checkpoint
  `5dcf81a787905d3f93812cd4b4ec64505049ad72`.
- Upstream target: OpenBao `v2.6.0`, released July 14, 2026.
- Recommended crate release: `2.1.0`. The server support and public API additions
  are semver-minor changes; they do not require another crate major release.
- Delivery model: ordered commits on `main`. Each commit receives green CI and
  an owner-provided pentest for its exact range before the next commit starts.
- Completed checkpoint: Commit 01 release evidence and Commit 02 API evidence
  are staged and independently validator-anchored. Commit 03 generates the
  22-profile candidate registry with 690 stable operation identities. Commit
  04 implements the changed system contracts and authenticated root-generation
  routing. Commit 05 adds the typed sealable-namespace lifecycle. Commit 06
  adds workflow CRUD, pagination, bounded secret-aware execution, and separately
  acknowledged trace and unauthenticated execution. The staged registry now
  has 684 resolved operations and 6 pending authentication operations. The
  historical projection remains
  byte-identical to the active 21-profile registry. The candidate is explicitly
  introspection-only: runtime policies and dispatch remain capped at 2.5.5
  until final cross-lock promotion in Commit 09.
- Compatibility invariant: append an exact `2.6.0` profile without modifying
  the behavior, evidence hashes, routes, or field rules of the 21 profiles from
  `2.0.0` through `2.5.5`.

This document is the implementation contract for adding OpenBao 2.6.0 to the
exact-version compatibility system. It is intentionally separate from the
completed 2.0.0 compatibility migration plan.

## Immutable Upstream Identity

The onboarding work must lock and verify all of these values before generated
artifacts are accepted:

| Evidence | OpenBao 2.6.0 value |
| --- | --- |
| Git tag | `v2.6.0` |
| Source commit | `03e3a243b6f07d17c60ce0a182adee7cf4c424eb` |
| OCI index digest | `sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653` |
| OCI linux/amd64 manifest | `sha256:80b71b06de94d9b11da83fd1cdb70cbd84b375739620c18b12d76b4f5ffe95ab` |
| Index signer | `release-images.yml@refs/tags/v2.6.0` |
| Index signature bundle | `sha256:ecb4a011104c0e7bd5a7f3456ac924ddf03f48e0bd2fe662de567063bcca431c` |
| linux/amd64 signature | Not separately published; bound by the verified signed index |
| Embedded provenance manifest | `sha256:a8195dad5e1b38bb9fbdf1c25b7bd89ec3f3623101ecd0ffc90875586057772e` |
| Tagged API documentation | 117 files, 688 extracted rows |
| Runtime OpenAPI | 526 paths, 760 operations, 551 schemas |

The prior `2.5.5` runtime OpenAPI has 516 paths, 739 operations, and 530
schemas. The exact runtime comparison reports 21 added operations and no
removed operations. Improved OpenAPI reporting accounts for several of those
additions, so operation counts alone must not be treated as new functionality.

The active release, snapshot, capability, contract, and live-test locks are
cryptographically cross-bound. A release cannot be appended to only one of
them while keeping CI honest. Therefore 2.6.0 is staged under
`compat/onboarding/2.6.0/` until the complete evidence set is ready for atomic
promotion into the active 22-profile inventory.

## Investigation Findings

### New HTTP surfaces

1. Sealable namespace lifecycle:
   - namespace creation accepts `seal` and `pgp_keys`;
   - creation can return secret `key_shares` and `key_threshold`;
   - `GET /sys/namespaces/:path/seal-status`;
   - `POST /sys/namespaces/:path/seal` and
     `POST /sys/namespaces/:path/unseal` in runtime OpenAPI;
   - `DELETE /sys/namespaces/:path/delete-sealed` with optional recursive
     force behavior.
2. Workflow management and execution:
   - LIST and SCAN `/sys/workflows/manage` and optional prefixes;
   - GET, POST, and DELETE `/sys/workflows/manage/:path`;
   - POST `/sys/workflows/execute/:path`;
   - POST `/sys/workflows/trace/:path`;
   - conditionally registered POST `/sys/workflows/unauthed-execute/:path`.
3. Authenticated root-token generation:
   - GET, POST, and DELETE `/sys/generate-root-token/attempt`;
   - POST `/sys/generate-root-token/update`.
4. JWT CEL role administration and login are newly documented in 2.6.0 but
   already existed in the 2.5.5 runtime OpenAPI. They are an older typed-API gap
   exposed by the current documentation review and must be closed:
   - POST `/auth/:jwt-mount/cel/login`;
   - GET or LIST `/auth/:jwt-mount/cel/role`;
   - GET, POST, PATCH, and DELETE `/auth/:jwt-mount/cel/role/:name`.

### Changed fields and behavior

| Area | 2.6.0 change | Compatibility action |
| --- | --- | --- |
| Root generation | Authenticated clients use `/sys/generate-root-token`; legacy `/sys/generate-root` is deprecated and disabled by default. | Keep one public ceremony API and select the path from the exact profile. Never probe and fall back. |
| Init/rekey | `stored_shares` is removed and ignored. | Keep the Rust fields for old profiles, add a maximum `2.5.5` field rule, and reject them locally for `2.6.0`. |
| Seal/version history | `build_date` becomes `commit_date`; seal status adds `recovery_seal_type`. | Decode both names additively. Preserve `build_date` for source compatibility and expose `commit_date` explicitly. |
| Lease lookup | Adds `path`, `namespace_path`, and `revoke_error`. | Add optional fields with bounded decoding and redacted Debug treatment for topology-bearing values. |
| CORS | Adds `allow_credentials`. | Add request and response fields, available since `2.6.0`. |
| Userpass | Adds mutually exclusive pre-hashed bcrypt `password_hash`. | Add secret-aware constructors and reset helpers that make plaintext/hash exclusivity explicit. |
| Kerberos | Adds `decode_pac`. | Add a versioned optional configuration field. |
| TOTP | Generated-code response adds `generated`, `expire_time`, and `period`. | Extend the response type with bounded optional fields. Do not copy the upstream OpenAPI misclassification into the validation request. |
| JWT | Adds the Kubernetes provider. | Add a typed Kubernetes provider constructor while retaining the deployment-specific map escape hatch. |
| ACL policy | Adds slash and wildcard identity-template overrides. | Require explicit dangerous-override acknowledgment and a 2.6.0 field rule. |
| PKI role | Adds the glob identity-template override. | Require explicit dangerous-override acknowledgment and a 2.6.0 field rule. |
| SSH role | Adds the comma identity-template override. | Require explicit dangerous-override acknowledgment and a 2.6.0 field rule. |
| OpenAPI | PATCH and SCAN reporting is corrected. | Correct evidence classifications only. Do not duplicate helpers that already implement these methods. |

### Evidence discrepancies to preserve explicitly

1. The tagged JWT CEL documentation uses plural `cel/roles` in places, while
   the exact source router and runtime OpenAPI use singular `cel/role`. Runtime
   routing wins. Record the documentation discrepancy rather than emitting a
   broken plural route.
2. The tagged Kubernetes JWT provider guide shows `oidc_discovery_url` together
   with `provider_config.provider = "kubernetes"`. Exact source rejects that
   combination and accepts `provider_config` as the sole key source. The typed
   constructor must follow runtime source behavior and the discrepancy must be
   recorded in generated evidence notes.
3. Workflow unauthenticated execution is documented but only registered when
   the server enables `allow_unauthenticated_workflows`. Keep it in the 2.6.0
   capability profile as tagged-documentation evidence even though a default
   runtime OpenAPI capture does not expose it.
4. Workflow LIST and SCAN share route patterns. Both source operations must be
   represented even if OpenAPI collapses them.
5. The namespace guide spells seal and unseal as `PUT`, while runtime OpenAPI
   reports `POST`. The crate will use the runtime-supported `POST` spelling and
   retain the guide mismatch as evidence.
6. Exact-image live testing confirmed an OpenBao 2.6.0 defect in prefixed
   workflow listing. `LIST /sys/workflows/manage/foo` closes the connection and
   the server logs `panic serving ... field parent not in the schema`. The
   tagged handler defines `path` but reads `parent`. Classify prefixed LIST and
   SCAN as security-blocked for the exact 2.6.0 profile, test that the SDK does
   not transmit them, and revisit only after an exact patched release fixes the
   server. Unprefixed LIST and SCAN remain supported.
7. Exact source and image review confirmed a second OpenBao 2.6.0 workflow
   defect: `handleWorkflowsUpdate` shadows the parsed `cas` pointer, so storage
   always receives no CAS value. Strict create/update cannot be guaranteed and
   setting `cas_required` can make later writes fail. Preserve the body field
   for fixed releases, reject CAS-selected writes locally while 2.6.0 is the
   only workflow profile, never retry, and document that exact 2.6.0 cannot
   provide workflow CAS semantics.

## Security Decisions

These decisions are part of the plan and are not deferred implementation
questions.

### Namespace sealing

- Treat returned key shares and unseal shares as `SecretString` values with
  redacted Debug output and bounded list decoding.
- Validate namespace paths and bound seal documents and PGP-key lists before
  transport.
- Put seal, unseal, and sealed-namespace deletion behind `operator-ops` and
  `operator-ops-acknowledged`.
- Require a named confirmation type for sealed-namespace deletion. The method
  documentation must state that external lease resources are not cleaned up.
- Do not expose raw key-share values through convenience Debug, tracing, or
  error messages.

### Workflows

- Treat workflow definitions, arbitrary execution input/output, and traces as
  sensitive. They can contain embedded tokens, authentication data, and
  secrets.
- Use bounded secret-aware JSON/document wrappers with redacted Debug output.
- Keep normal authenticated execution typed and available with `sys`.
- Gate trace execution behind `workflow-trace` plus
  `workflow-trace-acknowledged`; trace output includes the OpenBao token and
  full intermediate request data.
- Gate unauthenticated execution behind `unauthenticated-workflows` plus
  `unauthenticated-workflows-acknowledged` on `Client<Unauthenticated>`.
- Preserve CAS and pagination. Do not hide `cas_required` or silently retry
  workflow writes.
- Reject prefixed LIST and SCAN locally for the exact 2.6.0 profile because the
  released server panics while handling them. Do not probe the defective route.

### Identity-template overrides

- The four new flags weaken protections introduced for a published security
  issue. A casual public boolean is insufficient.
- Add one named acknowledgment type and require it to construct any request
  that sets an override to `true`.
- Also require an `identity-template-overrides-acknowledged` compile-time
  feature so dependency review records the decision.
- Reading `false` or `true` from server responses remains ungated. Only sending
  a dangerous override is gated.

### Authenticated root generation

- Keep the existing operator ceremony types and secret redaction.
- The selected exact profile determines the route. A 2.6.0 client must never
  silently fall back to the deprecated unauthenticated path, and an older
  profile must never be sent the new path.

## Ordered Commit Plan

Each pentest range starts at the prior accepted commit and ends at the new
commit produced by that checkpoint. For the first checkpoint, use
`5dcf81a787905d3f93812cd4b4ec64505049ad72..<commit-01>`.

### Commit 01: Stage OpenBao 2.6.0 release evidence

Suggested title: `Stage OpenBao 2.6.0 release evidence`

- Add a separately checksummed, validator-anchored onboarding record without
  changing the active 21-release inventory.
- Verify the source commit, GitHub release state, OCI index, and amd64 manifest.
- Record that the index signer moved to `release-images.yml`, that the amd64
  child is index-bound but not independently signed, and that embedded BuildKit
  provenance is present.
- Add fail-closed self-tests for signer, child-signature, provenance-subject,
  and checksum substitution.
- Do not alter generated capabilities or runtime code in this commit.

Pentest focus: lock-file substitution, duplicate/reordered release entries,
digest confusion, symlink/FIFO handling, and immutable historical-record
preservation.

Pentest range: `5dcf81a..<commit-01>`.

### Commit 02: Capture exact 2.6.0 API evidence

Suggested title: `Capture OpenBao 2.6.0 API snapshots`

- Extract tagged API documentation from source commit `03e3a243...`.
- Capture runtime OpenAPI from the digest-pinned 2.6.0 image.
- Generate `2.5.5--2.6.0` adjacent diffs and the 2.6 rendered-doc cross-check.
- Store the JWT CEL, Kubernetes provider, workflow, and method-reporting
  discrepancies as reviewed evidence.
- Prove every prior snapshot and diff hash remains unchanged.
- Keep these artifacts in the staged onboarding set; do not mutate the active
  21-profile snapshot lock yet.

Pentest focus: untrusted upstream JSON/docs parsing, archive traversal, image
identity, response-size bounds, generated-file determinism, and historical hash
drift.

Pentest range: `<commit-01>..<commit-02>`.

### Commit 03: Append the 2.6.0 capability profile

Suggested title: `Generate the OpenBao 2.6.0 capability profile`

- Expand generated profile tables and capability ranges from 21 to 22 exact
  releases.
- Add all new operation identities and corrected PATCH/SCAN evidence.
- Add route variants for old and new authenticated root-generation paths.
- Keep every old profile cell unchanged and add tests that compare the
  historical generated prefix byte-for-byte.
- Update Kani bounds/proofs and compatibility documentation for the new latest
  known profile.

Pentest focus: wrong-profile route selection, gaps or overlaps in route
variants, unknown-newer handling, stable operation identifiers, and accidental
mutation of 2.0.0 through 2.5.5.

Pentest range: `<commit-02>..<commit-03>`.

### Commit 04: Implement 2.6.0 system compatibility changes

Suggested title: `Handle OpenBao 2.6 system contract changes`

- Route the existing authenticated root-generation ceremony by exact profile.
- Add maximum-version request-field rules and validation for `stored_shares`.
- Add `commit_date`, legacy `build_date`, `recovery_seal_type`, lease lookup
  additions, CORS credentials, and TOTP generation metadata.
- Add representative old/new response fixtures and HTTP path tests.
- Keep public old-profile fields source-compatible.

Pentest focus: root-token leakage, deprecated-path fallback, unsupported-field
bypass, secret Debug output, malicious lease topology strings, and response
compatibility across both sides of the 2.6.0 boundary.

Pentest range: `<commit-03>..<commit-04>`.

### Commit 05: Add sealable namespace lifecycle APIs

Suggested title: `Add OpenBao 2.6 sealable namespace support`

- Extend namespace creation with typed seal configuration and PGP keys.
- Model returned key shares as bounded secret values.
- Add seal-status, unseal, seal, and operator-confirmed delete-sealed helpers.
- Test exact methods and paths against a 2.6.0 server and local rejection on
  every older profile.

Pentest focus: unseal-key and generated-share exposure, namespace path
injection, destructive confirmation bypass, force-recursion handling, and
operator feature-gate enforcement.

Pentest range: `<commit-04>..<commit-05>`.

### Commit 06: Add typed workflow management and execution

Suggested title: `Add OpenBao 2.6 workflow APIs`

Status: complete in this commit.

- Add bounded unprefixed LIST and SCAN support, read/write/delete, CAS, and
  pagination.
- Add authenticated execution with arbitrary but bounded secret-aware input and
  output.
- Add separately acknowledged trace and unauthenticated execution APIs.
- Cover conditional absence of unauthenticated execution without probing or
  fallback.
- Represent prefixed LIST and SCAN in the capability registry but block their
  transmission for exact 2.6.0 due to the confirmed upstream panic.
- Preserve documented body CAS without retry, and record the exact 2.6.0
  handler defect that prevents the server from honoring it.

Pentest focus: secret serialization and Debug output, trace disclosure,
unauthenticated dispatch, path injection, unbounded JSON/HCL, CAS races,
pagination abuse, and feature-gate combinations.

Pentest range: `<commit-05>..<commit-06>`.

### Commit 07: Complete 2.6.0 authentication changes

Suggested title: `Add OpenBao 2.6 authentication contracts`

- Add typed JWT CEL role list/read/write/patch/delete and CEL login.
- Add the Kubernetes JWT provider constructor following runtime source
  behavior, not the contradictory guide example.
- Add secret-aware userpass bcrypt-hash create/update operations with local
  mutual-exclusion checks.
- Add Kerberos `decode_pac`.
- Apply exact 2.6.0 request-field rules and old-profile rejection tests.

Pentest focus: JWT/CEL validation bypass, CEL resource exhaustion guidance,
password/hash ambiguity, bcrypt hash logging, provider map confusion, and
mount/path injection.

Pentest range: `<commit-06>..<commit-07>`.

### Commit 08: Add acknowledged template-security overrides

Suggested title: `Gate OpenBao 2.6 identity template overrides`

- Add ACL slash/wildcard, PKI glob, and SSH comma override response fields.
- Add explicit acknowledged constructors for sending `true`.
- Add the compile-time acknowledgment feature and feature-matrix tests.
- Document the exact rejected characters and why each override is dangerous.

Pentest focus: constructing or serializing dangerous flags without the marker
and feature, direct struct-literal bypass, old-profile rejection, and generated
policy/role output.

Pentest range: `<commit-07>..<commit-08>`.

### Commit 09: Run the complete 22-release compatibility matrix

Suggested title: `Verify OpenBao 2.0.0 through 2.6.0 compatibility`

- Extend live core-flow and version-contract matrices to all 22 releases.
- Run each image only against its own exact profile. Never run 2.0.0 while
  selecting 2.6.0, or vice versa.
- Add focused 2.6.0 live flows for root-generation routing, namespace sealing,
  workflows, JWT CEL, userpass hash, and changed response fields where
  practical.
- Preserve separate evidence for tagged docs, runtime OpenAPI, and live HTTP
  behavior.
- Update the support matrix and compatibility threat model.

Pentest focus: cross-version profile confusion, stale containers, image digest
verification, test secret cleanup, disabled optional routes, and false claims
of live coverage.

Pentest range: `<commit-08>..<commit-09>`.

### Commit 10: Prepare the 2.1.0 release candidate

Suggested title: `Prepare openbao crate 2.1.0`

- Set the crate version only after implementation and compatibility tests are
  complete.
- Update README examples, version support tables, migration notes, CHANGELOG,
  release notes, API stability audit, security residuals, and crates.io package
  contents.
- Run formatting, clippy on all feature combinations, unit/integration/doc
  tests, Kani, fuzz smoke tests, dependency policy, package verification, SBOM,
  and the full release gate.
- Require clean final pentests from multiple systems before signing the tag.

Pentest focus: complete public API, feature combinations, docs/examples,
package contents, dependency changes, and the full `2.0.0..=2.6.0` compatibility
claim.

Pentest range: `<commit-09>..<commit-10>`.

## Completion Criteria

The 2.1.0 release candidate is ready only when all of the following are true:

1. The exact 2.6.0 release, source, image, docs, and OpenAPI evidence are locked.
2. The staged evidence is promoted atomically across release, snapshot,
   capability, contract, CI, and live-test locks; all 22 exact profiles then
   validate and all 21 historical profiles are unchanged.
3. Every 2.6.0 tagged/runtime operation is typed, typed-gated, or explicitly
   security-blocked with a documented reason.
4. Changed request fields fail locally outside their supported exact profiles.
5. Changed responses deserialize under both old and new fixtures.
6. Live tests select each server's own exact profile and verify the reported
   server version before exercising authenticated flows.
7. No workflow data, key share, unseal share, password hash, token, namespace,
   or lease topology value appears in Debug, tracing, or error output.
8. CI, release gates, documentation checks, package verification, and the final
   independent pentests are green for the exact release commit.

## Scope Boundaries

- Auto-unseal KMS plugin implementation and registration are server/plugin
  deployment concerns, not new core HTTP SDK endpoints. Existing plugin catalog
  and custom-wrapper support remain the boundary.
- Distroless images and the container user change affect the test harness, not
  the public Rust API. The 2.6.0 integration harness must still run by immutable
  digest and non-root user.
- PKI CEL `encode_json` and `decode_json` are workflow-language functions, not
  HTTP endpoints. Document their server-version requirement; do not emulate
  them in the client.
- Kerberos, LDAP, RADIUS, and LDAP secrets deprecations announce a 2.7.0
  packaging move to external plugins. Their 2.6.0 HTTP contracts remain
  supported and must not be removed from older profiles.
