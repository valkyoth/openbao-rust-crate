# OpenBao Version Compatibility Plan

## Status

- Target crate release: `2.0.0`.
- Delivery model: ordered commits on `main`, not intermediate crate releases.
- Current implementation target: OpenBao stable releases from `v2.0.0`
  through `v2.5.5` listed below.
- Release rule: `main` identifies itself as unreleased `2.0.0` from the first
  breaking checkpoint onward. No `2.0.0` package is published or tagged until
  the final release-preparation commit and all release gates are complete.
- Advancement rule: each checkpoint must have green required CI and an
  owner-provided pentest for the exact resulting commit before work starts on
  the next checkpoint.

This document is the implementation contract for making one crate release
support multiple OpenBao server versions without allowing a newer OpenBao API
change to overwrite the behavior required by an older server.

The companion
[`OPENBAO_2_5_FULL_SUPPORT_AUDIT.md`](OPENBAO_2_5_FULL_SUPPORT_AUDIT.md)
records the baseline audit that found the existing endpoint inventory complete
but its implementation classifications and field-level coverage incomplete.
`2.0.0` must close those gaps as part of the multi-version work.

OpenBao currently documents its HTTP API under `/v1`, but explicitly warns
that this prefix does not yet guarantee backwards compatibility. Therefore,
compatibility cannot be inferred from the URL prefix or from successful
compilation of this crate.

Official references:

- https://openbao.org/api-docs/
- https://openbao.org/docs/policies/deprecation/
- https://openbao.org/docs/policies/support/
- https://openbao.org/api-docs/system/health/
- https://openbao.org/api-docs/system/internal-specs-openapi/

## Release Scope

The initial immutable release inventory covers these stable OpenBao releases:

| Minor line | Exact releases |
| --- | --- |
| `2.0.x` | `2.0.0`, `2.0.1`, `2.0.2`, `2.0.3` |
| `2.1.x` | `2.1.0`, `2.1.1` |
| `2.2.x` | `2.2.0`, `2.2.1`, `2.2.2` |
| `2.3.x` | `2.3.1`, `2.3.2` |
| `2.4.x` | `2.4.0`, `2.4.1`, `2.4.3`, `2.4.4` |
| `2.5.x` | `2.5.0`, `2.5.1`, `2.5.2`, `2.5.3`, `2.5.4`, `2.5.5` |

Beta, release-candidate, nightly, and development builds are not supported
profiles. They may be inspected in non-blocking compatibility jobs, but they
must not be added to the stable registry or advertised as supported.

The absence of `2.3.0` and `2.4.2` from the inventory is intentional. The
inventory follows published stable artifacts rather than assuming every
semantic-version sequence member exists.

### Documentation Evidence Sources

The OpenBao website currently publishes rendered API documentation for these
minor lines:

- `2.3.x`: https://openbao.org/api-docs/2.3.x/
- `2.4.x`: https://openbao.org/api-docs/2.4.x/
- current `2.5.x`: https://openbao.org/api-docs/

Equivalent website routes for `2.0.x`, `2.1.x`, and `2.2.x` are not currently
published. The official OpenBao repository retains the complete API
documentation source in each release tag under
`website/content/api-docs/**/*.mdx`, including the older releases. Examples:

- https://github.com/openbao/openbao/tree/v2.0.3/website/content/api-docs
- https://github.com/openbao/openbao/tree/v2.1.1/website/content/api-docs
- https://github.com/openbao/openbao/tree/v2.2.2/website/content/api-docs

The rendered website is a useful human cross-check, but it is not sufficient
as immutable or patch-specific evidence. A `2.3.x` page may reflect the final
state of that minor documentation line rather than the exact behavior of both
`2.3.1` and `2.3.2`.

For every exact release, the evidence priority is:

1. verified official release tag object and its peeled source commit;
2. `website/content/api-docs` from that exact source commit;
3. release notes and security notices for that exact patch;
4. normalized OpenAPI captured from that exact locked server image;
5. live contract and behavior tests against that image;
6. the rendered minor-line website as a secondary review aid.

No current rendered page may be copied backwards and treated as proof for an
older release. When tagged documentation, generated OpenAPI, and live behavior
disagree, the mismatch must be recorded and manually resolved. Live behavior
defines what the server does, while the discrepancy remains part of the
compatibility evidence rather than being silently discarded.

## Compatibility Promise

For a server version selected and verified by the compatibility layer:

- endpoint paths and HTTP methods are selected from that version's immutable
  profile;
- a path removed in a newer OpenBao version remains available to an older
  profile when its continued use is not prohibited by crate security policy;
- a replacement endpoint can be selected for a newer profile without changing
  the older profile;
- request fields unavailable on the selected server fail locally when the
  caller sets them;
- response aliases and optional fields are decoded according to reviewed
  version evidence;
- unsupported operations fail before request transmission with a typed,
  sanitized compatibility error;
- unknown newer server versions fail closed in strict mode;
- no compatibility failure includes tokens, namespaces, request bodies,
  response bodies, secret paths, or other secret material in `Debug`,
  `Display`, tracing, or reports.

The compatibility layer must never restore an endpoint that the crate has
blocked because of a known vulnerability. Functional compatibility with an
old release is subordinate to the crate's security invariants.

## Support Vocabulary

Server compatibility and server security support are separate claims.

| Status | Meaning |
| --- | --- |
| `tested` | All applicable live and contract tests passed for the exact release. |
| `tested-subset` | The documented subset passed; remaining operations have explicit classifications. |
| `security-deprecated` | Compatibility evidence exists, but the server lacks later security fixes and is not recommended for new deployments. |
| `unsupported-capability` | The selected server does not provide the operation, or crate policy blocks it. |
| `unverified` | No exact committed compatibility evidence exists. |
| `unknown-newer` | The server is newer than the registry; strict mode refuses typed dispatch. |

Documentation must not use `supported` as a synonym for `secure`. The newest
reviewed OpenBao patch remains the recommended deployment target even when
older releases are tested for wire compatibility.

## Architecture

### Version Model

Add a strict semantic OpenBao version type and a version requirement type.
Prerelease identifiers must be rejected by stable compatibility policies.
Version parsing must be bounded, deterministic, panic-free, and covered by
unit tests and fuzzing.

The public policy model should provide these concepts without exposing
generated registry internals:

- exact version requirement;
- inclusive version range for controlled rolling upgrades;
- strict automatic detection;
- explicit assumed version for environments where health probing is blocked;
- explicit acknowledgement for an unknown newer server.

An exact or range requirement describes what the caller permits. The version
returned by `/sys/health` selects the actual routing profile. A caller-provided
value must not silently override a conflicting detected version.

### Immutable Release Lock

Add a committed release inventory under `compat/`. Each release entry must
record at least:

- exact OpenBao version;
- official source tag object, peeled source commit, and signature-verification
  result;
- immutable OCI image digest;
- normalized OpenAPI snapshot hash;
- documentation or source revision used for endpoint evidence;
- snapshot format and generator version;
- compatibility status;
- security notes that affect SDK behavior.

No entry may contain `latest`, a mutable image tag without a digest, an
unverified redirect, or a floating documentation source. Updating support for
a new OpenBao release appends a profile. It must not regenerate or rewrite old
profiles from current documentation.

### Endpoint Registry

Each typed HTTP operation receives a stable internal endpoint identifier. The
generated registry maps that identifier to reviewed variants containing:

- version interval;
- HTTP method;
- path template;
- accepted success statuses;
- request fields introduced or removed in that interval;
- response field aliases and availability notes;
- security classification;
- replacement or terminal removal information.

Dynamic path values remain validated by the existing path validators. The
registry owns only static path templates and version selection; it must not
weaken path, query, header, response-size, or secret-handling controls.

### Runtime Dispatch

Typed helpers should ultimately dispatch through endpoint identifiers. The
dispatcher must:

1. obtain the selected or detected compatibility profile;
2. verify that the endpoint variant is valid for that profile;
3. validate version-specific request fields;
4. construct the path from a static template and validated parameters;
5. send exactly one request using the existing hardened transport;
6. decode through the reviewed response compatibility rules.

There must be no trial request to an old path followed by fallback to a new
path. Such probing can duplicate non-idempotent operations and can expose
endpoint existence. Routing is selected before transmission.

Raw JSON and custom plugin APIs remain escape hatches. They cannot inherit a
typed compatibility guarantee because application and external plugin schemas
are deployment-specific. Their documentation must state whether they bypass
the compatibility registry.

### Server Verification

Strict verification uses `/sys/health` over the already validated TLS
connection and caches only the parsed public server version. It must not cache
health response bodies or credentials.

An exact-version mismatch fails before the requested typed operation is sent.
For a version range, dispatch must use the actual detected version. If a mixed
version cluster cannot be verified, callers must use only the capability
intersection of the allowed range or complete the rolling upgrade before
using a route whose path differs within that range.

`/sys/internal/specs/openapi` is supporting evidence, not the sole source of
truth. Its output is permission-dependent and historically incomplete for
some plugin schemas. Release notes, immutable source documentation, response
fixtures, and live behavior tests remain required.

## Commit And Pentest Protocol

Every numbered checkpoint below produces one focused implementation commit.
The expected sequence is:

1. implement only the checkpoint goal;
2. run the checkpoint tests and the normal repository checks;
3. commit and push to `main`;
4. wait for all required GitHub checks to pass;
5. review an owner-provided `PENTEST.md` tied to that exact commit;
6. fix every actionable finding in a focused follow-up commit;
7. repeat CI and pentest against the new exact HEAD until clean;
8. delete `PENTEST.md` after its findings are resolved or explicitly recorded;
9. record accepted residual risk in `SECURITY.md` or the `2.0.0` release notes;
10. begin the next numbered checkpoint only after the current HEAD is clean.

Do not squash, amend, force-push, or rewrite reviewed commits on `main`. A
finding-fix commit becomes part of the same checkpoint and must itself receive
green CI and exact-HEAD pentest confirmation before advancement.

During implementation:

- keep `main` identified as unreleased `2.0.0` after the first breaking
  checkpoint;
- maintain changes under the `Unreleased` changelog section;
- do not create intermediate tags;
- do not claim historical compatibility in the README until its release
  profile has passed the required evidence;
- do not automatically accept generated endpoint changes without human
  review.

## Ordered Commit Plan

### Commit 00: Record The Compatibility Contract

Suggested commit title: `Plan OpenBao multi-version compatibility`

Goal:

- add this document;
- link it from `docs/RELEASE_PLAN.md`;
- establish `2.0.0` as the single release milestone.

Stop conditions:

- documentation and release metadata checks pass;
- the version inventory, security boundary, commit protocol, and final release
  criteria are unambiguous;
- no runtime or public API behavior changes.

Pentest focus:

- review the proposed fail-closed behavior, downgrade boundaries, artifact
  trust model, and secret-free diagnostics.

### Commit 01: Add Strict Version Types

Suggested commit title: `Add strict OpenBao version model`

Goal:

- add public version and version-requirement value types;
- add sanitized compatibility error variants;
- add strict parsing, ordering, range, and prerelease rejection tests.

Stop conditions:

- parser input is bounded and panic-free;
- malformed, overflowed, incomplete, and prerelease values are rejected;
- errors reveal only public version and capability information;
- no HTTP routing changes yet.

Pentest focus:

- parser denial of service, integer overflow, malformed Unicode, confusing
  version strings, and error-message sanitization.

### Commit 02: Add The Immutable Release Inventory

Suggested commit title: `Lock supported OpenBao release artifacts`

Goal:

- add the `compat/` inventory and lock schema;
- populate all listed stable releases with verified immutable evidence;
- add an offline lock validator.

Stop conditions:

- every release has an exact source commit and image digest;
- tag-object and peeled-commit identities are both retained so an annotated
  tag cannot be confused with its target commit;
- duplicate versions, duplicate mutable identifiers, missing hashes, and
  reordered or modified historical records fail validation;
- signed upstream tags and available artifact attestations are verified and
  recorded without claiming verification that upstream does not provide.
- source and OCI artifact hashes are complete in this checkpoint; normalized
  OpenAPI hashes land in Commit 03's separate append-only snapshot lock so the
  release-artifact lock is not rewritten.

Pentest focus:

- lockfile tampering, digest substitution, tag confusion, path traversal,
  duplicate-key parsing, and downgrade of verification status.

### Commit 03: Capture Historical API Evidence

Suggested commit title: `Generate immutable OpenBao API snapshots`

Goal:

- add a bounded generator for per-release endpoint evidence;
- store normalized OpenAPI and documentation-derived snapshots by version;
- hash generated artifacts in the release lock.

Stop conditions:

- the generator reads only the exact locked source and server artifact;
- tagged `website/content/api-docs` is the primary documentation input for
  every release, including `2.0.x` through `2.2.x` where no rendered versioned
  website route is available;
- rendered `2.3.x`, `2.4.x`, and current `2.5.x` pages are secondary
  cross-checks and cannot overwrite tagged evidence;
- normalization is deterministic;
- untrusted schemas are size, depth, item-count, and string-length bounded;
- generated diffs identify path, method, field, and schema changes;
- old snapshots do not change when a new profile is added.

Pentest focus:

- malicious OpenAPI documents, parser resource exhaustion, symlink and path
  escape, nondeterministic output, and generated-source injection.

### Commit 03A: Replace The Coverage Matrix

Suggested commit title: `Audit complete OpenBao API contracts`

Goal:

- replace broad page-level classification with an exact operation matrix;
- cover methods, paths, request parameters, response fields, transport shape,
  security classification, public helper, and test evidence;
- correct every false typed classification documented in
  `OPENBAO_2_5_FULL_SUPPORT_AUDIT.md` and any additional findings.

Stop conditions:

- all 643 `v2.5.5` endpoint rows are represented exactly once;
- no status is inferred merely from a documentation page or module prefix;
- every documented request parameter and response field has an explicit
  coverage state;
- missing code cannot be classified as typed;
- matrix generation fails on duplicate, missing, contradictory, or
  evidence-free rows;
- the corrected matrix is accepted as the implementation backlog, not
  presented as completed support.

Pentest focus:

- false coverage claims, parser ambiguity, duplicate operation identities,
  path normalization collisions, hidden secret fields, generated report
  tampering, and evidence downgrade.

### Commit 04: Parameterize The OpenBao Test Harness

Suggested commit title: `Add version-locked OpenBao test harness`

Goal:

- make the integration harness select an exact inventory entry;
- start images only by locked digest;
- verify `/sys/health` reports the expected exact version;
- isolate data, network, ports, credentials, and cleanup per run.

Stop conditions:

- arbitrary image references and shell fragments are rejected;
- no test credentials survive cleanup or enter logs/artifacts;
- version mismatch fails before integration tests;
- parallel jobs cannot share volumes, ports, tokens, or TLS keys.

Pentest focus:

- command and environment injection, container escape assumptions, stale
  credential files, unsafe cleanup, image substitution, and cross-job state.

### Commit 05: Establish The Historical Core Baseline

Suggested commit title: `Test core SDK flow across OpenBao releases`

Goal:

- run the existing health, mount, KV, policy, token, capability, and wrapping
  integration flow against every inventory release;
- classify each failure as a crate defect, expected server difference,
  security-policy block, or infrastructure problem.

Stop conditions:

- every exact release produces a machine-readable result;
- a skipped operation requires a stable reason code;
- zero-test or all-skipped runs fail;
- no compatibility claim exceeds the live evidence.

Pentest focus:

- false-green reporting, skip abuse, secret leakage in reports, cleanup after
  failed tests, and unsafe behavior on known-vulnerable servers.

### Commit 06: Add The Multi-Version CI Matrix

Suggested commit title: `Run OpenBao compatibility matrix in CI`

Goal:

- add representative pull-request jobs;
- add all-release nightly and release-gate jobs;
- publish a compatibility report artifact.

Pull requests should cover the oldest profile and the latest patch in each
minor line. Scheduled and release gates must cover every exact inventory
release.

Stop conditions:

- matrix values come only from the validated inventory;
- required jobs cannot be bypassed through a pull-request-controlled value;
- artifact retention excludes tokens, TLS private keys, server data, and raw
  secret responses;
- infrastructure failure is distinct from compatibility failure.

Pentest focus:

- workflow expression injection, untrusted artifact handling, cache poisoning,
  secret scope, matrix manipulation, and false-green job aggregation.

### Commit 07: Generate The Capability Registry

Suggested commit title: `Generate versioned OpenBao capability registry`

Goal:

- assign stable internal identifiers to typed operations;
- generate per-version method/path/capability variants;
- expose read-only compatibility reporting without exposing secret paths.

Stop conditions:

- every typed endpoint row has one stable identifier or an explicit exclusion;
- overlapping, missing, or contradictory version ranges fail generation;
- security-blocked operations cannot be marked available by generated input
  alone;
- generated Rust is deterministic and reviewed.

Pentest focus:

- range gaps and overlaps, method confusion, template injection, capability
  downgrade, registry corruption, and unsafe generated code.

### Commit 08: Add Client Compatibility Policies

Suggested commit title: `Add verified OpenBao compatibility policies`

Goal:

- add exact, range, automatic strict, explicit assume, and acknowledged
  unknown-newer policies;
- verify and cache the public server version;
- provide a sanitized compatibility report.

For `2.0.0`, existing constructors remain available and retain their current
unverified behavior unless a compatibility policy is selected. Strict
verification becomes the recommended documented path. Strict mode is not the
unconditional default because an automatic preflight request would add network
I/O to client construction and prevent offline configuration.

Stop conditions:

- exact mismatch and unknown strict versions fail closed;
- assumed mode is visibly named and never reported as verified;
- cached versions cannot cross base URLs or client instances;
- concurrent first use cannot select conflicting profiles;
- health errors do not expose request URLs or credentials.

Pentest focus:

- version spoofing, downgrade, cache confusion, race conditions, proxy and
  load-balancer behavior, malformed health responses, and sensitive logging.

### Commit 09: Add Version-Aware Dispatch

Suggested commit title: `Dispatch typed requests by OpenBao capability`

Goal:

- add the internal endpoint dispatcher;
- select one route before transmission;
- add typed unsupported-version and unsupported-capability failures;
- retain hardened raw request escape hatches with explicit compatibility
  caveats.

Stop conditions:

- no fallback request is sent after 404, 405, or decode failure;
- unsupported calls fail before body serialization and transmission;
- path and query validation remain unchanged or stronger;
- default requests remain single-shot;
- tracing remains secret-free.

Pentest focus:

- confused-deputy routing, path traversal, method substitution, duplicate
  writes, endpoint probing, body serialization before rejection, and logs.

### Commit 10: Migrate System Operations

Suggested commit title: `Version OpenBao system endpoint routing`

Goal:

- migrate typed `sys` operations to endpoint identifiers;
- classify historical root/recovery, rekey/rotate, lease, audit, namespace,
  seal-status, version-history, and internal endpoint differences;
- implement modern ACL policy paths, detailed policy lists, auth mount reads,
  lease prefix/full listing, barrier rekey backup/verification, root rotation,
  rotation verification/backup, and automatic rotation config;
- implement typed UI header, internal counter, request-inspection, and
  router-inspection APIs behind the required operator or unstable gates;
- preserve operator feature gates and acknowledgements.

Stop conditions:

- system operations have exact per-version evidence;
- no system row remains rejected or falsely classified as typed;
- removed unsafe legacy lease routes are never restored;
- operator operations cannot bypass existing compile-time gates;
- response field renames use reviewed aliases without silently inventing data.

Pentest focus:

- privilege boundary regressions, legacy unsafe routes, unauthenticated versus
  authenticated ceremony confusion, destructive calls, and response spoofing.

### Commit 11: Migrate Authentication Operations

Suggested commit title: `Version OpenBao authentication endpoint routing`

Goal:

- migrate token, AppRole, JWT/OIDC, Kubernetes, certificate, LDAP, RADIUS,
  Kerberos, and userpass operations;
- classify request and response differences by exact release.
- complete all documented token, token-role, JWT/OIDC, Kubernetes, and
  callback parameters;
- add typed Identity OIDC provider authorize, token, and userinfo protocol
  operations with secret-aware token and PKCE handling.

Stop conditions:

- login secrets and returned tokens remain secret-aware;
- unavailable auth features fail locally in strict mode;
- MFA and callback flows are tested only where supported;
- legacy security acknowledgements remain enforced.

Pentest focus:

- token disclosure, auth-method confusion, callback injection, MFA bypass,
  unsafe legacy authentication, and version-dependent policy weakening.

### Commit 12: Migrate KV And Transit Operations

Suggested commit title: `Version OpenBao KV and Transit routing`

Goal:

- migrate KV v1, KV v2, Cubbyhole, and Transit operations;
- classify pagination, scan, soft-delete, derivation, BYOK, CSR, and other
  version-specific capabilities.
- implement KV v1/v2 SCAN, KV v2 subkeys, detailed metadata, and all documented
  pagination/depth options;
- implement Transit partial-failure response controls and sign/verify hash
  path variants.

Stop conditions:

- CAS and destructive version operations retain their safety checks;
- unsupported request options are rejected rather than dropped;
- Transit plaintext, ciphertext, backups, imports, and key material retain
  secret-aware handling;
- no compatibility fallback duplicates a cryptographic operation.

Pentest focus:

- CAS bypass, secret exposure, duplicate encryption/signing, version rollback,
  key import confusion, and insecure algorithm availability.

### Commit 13: Migrate PKI Operations

Suggested commit title: `Version OpenBao PKI routing`

Goal:

- migrate PKI issuance, issuer/key lifecycle, CRL, tidy, ACME administration,
  CEL, sign-verbatim, cross-sign, and root operations;
- classify multi-issuer and newer field availability.
- add unauthenticated public CA, certificate, CRL, and serial read helpers;
- add first-class bounded OCSP GET/POST byte helpers;
- add the feature-gated ACME protocol boundary required to operate every
  documented directory scope without ad hoc JWS or challenge handling;
- complete all documented PKI request and response fields and correct the CRL
  rotation method discrepancy using live evidence.

Stop conditions:

- destructive and unconstrained signing operations retain operator gates;
- named and default issuer routes select the documented version variant;
- unsupported fields fail locally;
- every documented public protocol endpoint has a first-class bounded crate
  API even when protocol state machines remain delegated to established
  protocol libraries.

Pentest focus:

- unconstrained issuance, issuer confusion, root deletion, cross-sign misuse,
  revocation bypass, request-field downgrade, and private-key exposure.

### Commit 14: Migrate Remaining Engines And Identity

Suggested commit title: `Version remaining OpenBao engine routing`

Goal:

- migrate Identity, database, SSH, LDAP secrets, Kubernetes secrets,
  RabbitMQ, TOTP, and remaining typed engine operations;
- account for built-in and external plugin version limitations.
- add unauthenticated SSH public-key reads and complete SSH role fields;
- add typed, secret-aware connection builders for every documented built-in
  database plugin rather than relying on string-only extension fields;
- complete Identity entity-merge and provider-list parameters.

Stop conditions:

- core server compatibility is not presented as proof for an arbitrary
  external plugin version;
- external plugin schemas retain the custom-wrapper boundary;
- dynamic credentials, MFA values, TOTP secrets, SSH OTPs, and connection
  credentials remain redacted and bounded;
- every operation has a version classification.

Pentest focus:

- plugin-version confusion, credential disclosure, identity privilege
  escalation, alias collisions, role downgrade, and response allocation bounds.

### Commit 14A: Add Bounded Streaming Transport

Suggested commit title: `Add bounded OpenBao monitor streaming`

Goal:

- add a non-default streaming transport feature;
- implement `/sys/monitor` with typed log level and format options;
- expose bounded frames with cancellation and consumer back-pressure.

Stop conditions:

- frame size, total buffered bytes, and decode error text are bounded;
- a slow consumer cannot cause unbounded allocation;
- dropping the stream cancels the request and releases connection resources;
- log contents are never emitted through crate tracing or `Debug`;
- JSON and text monitor formats are covered without assuming trusted log data.

Pentest focus:

- unbounded streams, oversized lines, partial UTF-8, malicious JSON logs,
  cancellation races, connection leaks, back-pressure bypass, and accidental
  log re-emission.

### Commit 15: Enforce Version-Specific Request Fields

Suggested commit title: `Validate OpenBao request fields by version`

Goal:

- add central version-aware request validation;
- reject caller-selected fields unavailable on the detected profile;
- document fields whose semantics changed without changing names.

Stop conditions:

- a caller-set unsupported field is never silently omitted;
- unset optional fields preserve existing serialization;
- validation happens before secret serialization and transport handoff;
- error messages identify public field and version names only.

Pentest focus:

- silent security-option downgrade, request smuggling through flattened JSON,
  validation ordering, secret-bearing error paths, and conflicting options.

### Commit 16: Harden Versioned Response Decoding

Suggested commit title: `Harden OpenBao response compatibility`

Goal:

- add reviewed aliases and optional/default handling for historical responses;
- audit server-controlled enums and bounded extension fields;
- add per-version serde fixtures.

Stop conditions:

- missing old fields and renamed new fields follow explicit evidence;
- unknown fields remain bounded or ignored without unbounded allocation;
- unknown enum values never cause unsafe defaults;
- secret fields remain secret-aware under every response variant;
- no `deny_unknown_fields` rule prevents safe additive compatibility without a
  recorded reason.

Pentest focus:

- type confusion, malicious unknown values, oversized maps and lists, alias
  collisions, duplicate JSON fields, secret `Debug`, and misleading defaults.

### Commit 17: Complete Per-Version Contract Coverage

Suggested commit title: `Complete OpenBao version contract tests`

Goal:

- add endpoint-presence, request-shape, response-fixture, and representative
  live behavior coverage for every profile;
- generate the user-facing compatibility matrix.

Stop conditions:

- every documented `2.5.5` endpoint is implemented as typed or typed-gated,
  and
  every endpoint/profile cell records its live or contract evidence;
- older profiles may mark a capability unavailable or security-blocked only
  when that exact server lacks it or crate security policy forbids it;
- zero cells remain `planned`, `decision`, or unexplained;
- the final `2.5.5` matrix contains zero `partial`, `raw`, `external`, or
  `rejected` rows;
- destructive tests run only in fresh isolated servers;
- external-service-dependent tests state exactly what was and was not proven;
- compatibility percentages are derived mechanically from committed evidence.

Pentest focus:

- false claims, false-green skips, destructive fixture isolation, report
  sanitization, stale snapshots, and differences between test and release
  feature sets.

### Commit 18: Document Selection And Migration

Suggested commit title: `Document OpenBao server version selection`

Goal:

- update README, API coverage, API stability, migration, security, examples,
  and crate documentation;
- explain exact selection, strict auto-detection, ranges, mixed clusters,
  external plugins, raw APIs, and security-deprecated servers.

Stop conditions:

- examples compile;
- support tables distinguish tested compatibility from security endorsement;
- users of `2.2.0` can find a complete verified-client example;
- future release onboarding is documented;
- no documentation claims that `/v1` guarantees compatibility.

Pentest focus:

- insecure examples, misleading guarantees, downgrade guidance, assumed-mode
  visibility, mixed-cluster ambiguity, and accidental secret logging.

### Commit 19: Harden The Compatibility Boundary

Suggested commit title: `Harden OpenBao compatibility boundary`

Goal:

- fuzz version parsing, profile decoding, snapshot normalization, capability
  selection, and versioned response envelopes;
- add focused Kani proofs where bounded pure helpers are suitable;
- update the threat model and residual-risk register.

Stop conditions:

- fuzz corpora include historical and malformed version artifacts;
- capability selection cannot return a variant outside its interval;
- malformed compatibility data fails closed;
- supply-chain, runtime detection, mixed-cluster, plugin-version, and stale
  profile residuals are documented;
- full repository checks pass.

Pentest focus:

- the complete compatibility attack surface, especially downgrade, generated
  data trust, parser bounds, route selection, concurrency, and reporting.

### Commit 20: Prepare The 2.0.0 Release Candidate

Suggested commit title: `Prepare OpenBao SDK 2.0.0`

Goal:

- verify package metadata and standalone test-fixture constraints remain
  exactly `2.0.0`;
- finalize changelog and release notes;
- freeze generated compatibility artifacts;
- run the complete all-release gate.

Stop conditions:

- all 21 exact release profiles pass their required evidence;
- all historical lock and snapshot integrity checks pass;
- every public typed HTTP helper is registered or explicitly excluded;
- all Rust toolchain, dependency, CodeQL, audit, deny, SBOM, docs, examples,
  fuzz, Kani, unit, mock HTTP, and live OpenBao gates pass;
- GitHub is green for the exact release candidate;
- a final independent pentest is clean for the exact release candidate;
- release notes identify all security-deprecated server profiles and accepted
  residual risks;
- no tag is created until the owner explicitly approves the green candidate.

Pentest focus:

- full release regression and verification that evidence matches the exact
  crate contents, generated registry, container digests, and release commit.

## Future OpenBao Release Procedure

After `2.0.0`, a new stable OpenBao release is added through this sequence:

1. verify the official stable tag and immutable image digest;
2. append one release inventory record;
3. capture bounded immutable API evidence;
4. generate and manually review the diff against the previous release;
5. classify every path, method, request, response, and semantic change;
6. add routing variants without modifying historical profiles;
7. run the representative and full historical matrices;
8. pentest the exact commit;
9. advertise support only after all required evidence is green.

If an endpoint is removed, its old profile remains intact. The new profile
either selects a reviewed replacement or reports `unsupported-capability`
before transmission. Rust methods are not removed merely because a newer
OpenBao server removed an endpoint; crate API removal remains governed by Rust
semantic versioning and the crate's security policy.

## Explicit Non-Goals For 2.0.0

- Cargo features named after OpenBao versions.
- One crate release per OpenBao server release.
- Automatic fallback after HTTP errors.
- Claiming arbitrary external plugin compatibility from the core server
  version.
- Treating OpenAPI output as complete proof of behavior.
- Re-enabling endpoints blocked for known security reasons.
- Implementing arbitrary undocumented external plugin schemas or the behavior
  of third-party databases, identity providers, DNS providers, and browsers.
- Making strict automatic preflight mandatory for every constructor.
- Supporting beta, release-candidate, or development OpenBao builds as stable
  profiles.

## Final 2.0.0 Definition Of Done

`2.0.0` is complete only when an application can select or strictly detect an
included OpenBao release, receive the correct reviewed endpoint behavior for
that exact profile, and get a local typed error for unavailable behavior. A
future profile must be append-only and must not change the endpoint contract,
test evidence, or generated hash of an older profile. For OpenBao `2.5.5`, all
643 documented endpoint rows and their documented request/response
surfaces must be implemented as typed or appropriately gated crate APIs; an
external protocol handoff or generic raw request alone does not satisfy the
full-support target.
