# OpenBao 2.5.5 Full-Support Audit

## Status

- Audit target: official OpenBao `v2.5.5` tag
  `028992583c693c4de6350b8aa52ff85e30375a99`.
- Tagged API documentation files reviewed: `115` MDX files under
  `website/content/api-docs`.
- Tagged documentation endpoint rows: `651` raw rows, `644` unique documented
  rows, and `663` expanded method/path operations.
- The old rendered-documentation matrix omitted `HEAD /sys/health`; the exact
  tagged-source capture corrects that inventory defect.
- Audit status: exact inventory and field evidence are captured. Public helper,
  transport, security, and test evidence remain intentionally unverified.
- Release target for closure: `2.0.0`.
- Implementation progress: compatibility Commits 12 and 13 migrated KV v1, KV v2,
  Cubbyhole, and Transit through exact-release dispatch. KV SCAN and detailed
  metadata are locally rejected before OpenBao 2.2.0; Transit CSR and
  certificate installation are locally rejected before 2.1.0. PKI now uses
  exact-release dispatch, exposes unauthenticated bounded public distribution
  and OCSP helpers, and provides a feature-gated ACME client handoff.

This is a static audit checkpoint, not a compatibility certification. Live
OpenAPI capture and behavior tests against the locked `v2.5.5` image remain
required by `OPENBAO_VERSION_COMPATIBILITY_PLAN.md`.

## Meaning Of 100 Percent

For `2.0.0`, full OpenBao `2.5.5` HTTP API support means:

- every documented method/path row is represented by a first-class
  typed or typed-and-gated crate API;
- every documented request parameter is represented by a typed field, typed
  option, or deliberately bounded protocol value with correct secret handling;
- every documented response field is decoded, preserved in a bounded extension
  type, or explicitly documented as intentionally discarded metadata;
- binary, text, streaming, ACME, OIDC, OCSP, and unauthenticated endpoints use
  protocol-appropriate APIs rather than being called complete through a URL
  builder or generic raw escape hatch;
- operator, internal, unstable, destructive, and legacy operations remain
  available only behind appropriate feature and acknowledgement gates;
- endpoint aliases documented by OpenBao are either implemented or proven by
  live evidence not to exist, with the discrepancy recorded;
- no row remains `partial`, `raw`, `external`, `rejected`, `planned`, or
  `decision` in the final `2.5.5` full-support matrix.

This definition covers the official OpenBao HTTP API. It does not claim that
the crate implements arbitrary undocumented external plugin schemas, external
database servers, browser rendering, DNS challenge provisioning, or third-party
identity-provider behavior. It does require a safe first-class crate boundary
for every OpenBao endpoint participating in those workflows.

## Current Matrix Backlog

The replacement matrix reports:

| Classification | Rows |
| --- | ---: |
| `unverified` | 641 |
| `confirmed-gap` | 3 |
| `typed` | 0 |
| `typed-gated` | 0 |
| Total | 644 |

The machine-readable source of truth is
`docs/openbao-2.5-contract-matrix.json`. It records exact tagged source,
documented parameters, sampled response fields, normalized OpenAPI evidence,
transport/security review state, crate helper/type links, and test evidence.
The CSV is only a review index. No page or module prefix can confer typed
status.

## Previously Non-Strict Rows

These 46 rows are already visible in the matrix and must be implemented for the
new full-support goal:

| Area | Rows | Required closure |
| --- | ---: | --- |
| Token lookup-self | 1 | Use the documented GET operation as the canonical typed route. |
| PKI ACME directories and protocol | 4 | Add a first-class, feature-gated ACME protocol handoff/client boundary rather than URL-only classification. |
| PKI public CA, certificate, and CRL reads | 22 | Add unauthenticated typed JSON, bounded PEM/text, and DER byte helpers. |
| PKI OCSP | 2 | Add bounded GET and POST OCSP byte helpers with correct MIME types and request encoding. |
| SSH public keys | 2 | Add unauthenticated bounded text/public-key helpers. |
| Identity OIDC provider protocol | 3 | Add typed authorize, token, and userinfo operations with PKCE and secret-aware token handling. |
| System UI headers | 4 | Add sudo-sensitive typed read, write, list, and delete helpers. |
| Internal counters | 2 | Add gated typed entity and token counter responses with stability warnings. |
| System monitor | 1 | Add a bounded streaming API with back-pressure and cancellation. |
| Internal request inspection | 1 | Add an operator-gated response whose raw token and accessor fields are secret-aware. |
| Internal router inspection | 4 | Add operator-gated bounded router inspection response types. |

The earlier decisions to classify these rows as external or rejected were
reasonable for a narrower stable SDK. They are superseded by the explicit
`2.0.0` goal of full documented OpenBao support.

## Initial Incorrect Typed Classifications

The initial audit found 33 rows labelled `typed` or `typed-gated` without an
exact matching public helper or documented method. This table records that
starting point; the generated matrix is the current source of truth:

| Area | Rows | Confirmed gap |
| --- | ---: | --- |
| KV v1/v2 | 5 | KV v1 SCAN; KV v2 subkeys; metadata SCAN; detailed-metadata LIST and SCAN. |
| ACL policies | 7 | Current code uses legacy `/sys/policy`; modern `/sys/policies/acl` list, detailed list, read, write, and delete paths are absent. |
| Barrier rekey | 5 | `/sys/rekey/backup` read/delete and `/sys/rekey/verify` read/delete/update are absent. |
| Auth mount inspection | 1 | Exact `GET /sys/auth/:path` is absent; tune and list helpers do not replace it. |
| Lease administration | 2 | Prefix lease listing and full irrevocable lease listing are absent. |
| Key rotation | 11 | Legacy keyring alias, root rotation, automatic rotation config read/write aliases, verification, and backup operations are absent. |
| PKI CRL rotation | 2 | The docs specify GET for CRL and delta-CRL rotation; current helpers send POST. |

Compatibility Commits 10 through 12 have moved reviewed system,
authentication, KV, Cubbyhole, and Transit rows out of the confirmed-gap set.
The remaining `3` confirmed gaps are SSH public-key reads and `sys/monitor`.
No support percentage is published from this backlog.

### Exact Confirmed False-Typed Operations

The 33 confirmed rows are:

```text
SCAN /secret/:path
GET /:secret-mount-path/subkeys/:path
SCAN /:secret-mount-path/metadata/:path
LIST /:secret-mount-path/detailed-metadata/:path
SCAN /:secret-mount-path/detailed-metadata/:path

LIST /sys/policies/acl
LIST /sys/policies/acl/:prefix
LIST /sys/policies/detailed/acl
LIST /sys/policies/detailed/acl/:prefix
GET /sys/policies/acl/:name
POST /sys/policies/acl/:name
DELETE /sys/policies/acl/:name

GET /sys/rekey/backup
DELETE /sys/rekey/backup
GET /sys/rekey/verify
DELETE /sys/rekey/verify
POST /sys/rekey/verify

GET /sys/auth/:path
LIST /sys/leases/lookup/:prefix
GET /sys/leases

POST /sys/rotate
POST /sys/rotate/keyring/config
POST /sys/rotate/config
GET /sys/rotate/keyring/config
GET /sys/rotate/config
POST /sys/rotate/root
GET /sys/rotate/(root|recovery)/verify
DELETE /sys/rotate/(root|recovery)/verify
POST /sys/rotate/(root|recovery)/verify
GET /sys/rotate/(root|recovery)/backup
DELETE /sys/rotate/(root|recovery)/backup

GET /pki/crl/rotate
GET /pki/crl/rotate-delta
```

The tagged rotate-verification MDX spells the DELETE table path as
`/sys/rotation/(root|recovery)/verify`, while its prose and curl examples use
`/sys/rotate/(root|recovery)/verify`. The implementation must resolve that
documentation discrepancy against live `v2.5.5` behavior and preserve both
pieces of evidence; it must not blindly implement the apparent typo.

## Confirmed Request And Response Surface Gaps

The endpoint matrix does not measure parameters or response fields. Comparing
the tagged MDX parameter lists with current public Rust types confirmed these
examples.

### System

- Health status-code controls: `standbyok`, `activecode`, `standbycode`,
  `sealedcode`, and `uninitcode`.
- Lease `include_child_namespaces` and lease-list `limit` support.
- Automatic key rotation `max_operations`, `interval`, and `enabled` config.
- Detailed policy-list response data.
- Streaming monitor `log_level` and `log_format` options.

### Token And Authentication

- Token creation `id`, deprecated-but-documented `lease`, and `entity_alias`.
  Caller-selected token IDs must be secret-aware.
- Token role `allowed_policies_glob` and `disallowed_policies_glob`.
- Kubernetes auth `disable_iss_validation`.
- JWT config `override_allowed_server_names` and `skip_jwks_validation`.
- JWT/OIDC role `oauth2_metadata`, `callback_mode`, `oidc_disable_confirmation`,
  `verbose_oidc_logging`, `max_age`, and `token_policies_template_claims`.
- OIDC callback error fields need typed handling without logging provider error
  payloads unsafely.

### KV And Transit

- Completed in compatibility Commit 12: KV v1/v2 SCAN, KV v2 subkey
  `version`/`depth`, detailed-metadata pagination, Transit partial-failure
  response controls, and sign/verify hash algorithm path dispatch.
- Existing SHA-1 acknowledgement policy remains enforced, and `none` plus
  `prehashed` remain explicit caller choices rather than compatibility
  fallbacks.

### SSH

The SSH role request and response omit multiple documented fields, including:

- `exclude_cidr_list`;
- `allowed_domains` and `allowed_domains_template`;
- `default_extensions_template`;
- `allow_user_key_ids` and `key_id_format`;
- `allowed_user_key_lengths`;
- `algorithm_signer`;
- `not_before_duration`;
- `allow_empty_principals`.

SHA-1-backed `ssh-rsa` selection must remain explicitly acknowledged or
rejected according to crate security policy.

### PKI

Completed in compatibility Commit 13:

- certificate issuance `skid`;
- self-issued signing `require_matching_certificate_algorithms`;
- certificate generation `add_basic_constraints`;
- issuer `revocation_signature_algorithm`;
- URL config `enable_aia_url_templating`;
- regular role `use_csr_common_name` and `use_csr_sans`;
- current tidy `revoked_safety_buffer` where not present on every relevant
  request/response type;
- manual CRL signing `next_update` and complete extension entries;
- complete CEL program request and response structure;
- bounded unauthenticated CA, chain, certificate, CRL, and OCSP transports;
- feature-gated ACME directory and EAB handoff configuration;
- exact 2.2+ detailed-certificate and 2.4+ CEL route enforcement;
- CRL rotation aligned to the documented `GET` method.

### Identity And Database

- Entity merge `conflicting_alias_ids_to_keep`.
- Built-in database plugin connection fields are not fully typed. The current
  secret-aware, string-only extension map prevents unknown values from entering
  ordinary `String` fields or `Debug`, but cannot faithfully represent
  documented booleans, integers, lists, or structured plugin options.
- PostgreSQL, MySQL/MariaDB, Cassandra, InfluxDB, and Valkey need reviewed
  plugin-specific typed connection builders and secret-aware debug behavior.

This list records confirmed examples, not the final field inventory. Commit
03A in the compatibility plan must generate and manually verify the complete
method, parameter, response, and security-classification matrix before closure
implementation proceeds.

## Required Matrix Redesign

The replacement matrix must use one row per operation and include at least:

- exact OpenBao release;
- documentation source commit and file;
- HTTP method and normalized path;
- stable crate endpoint identifier;
- public helper name;
- request type and every documented parameter;
- response type and every documented field;
- authentication requirement;
- sudo/operator/internal/unstable classification;
- secret fields and redaction requirements;
- transport shape: JSON, text, bytes, redirect, or stream;
- unit, fixture, mock HTTP, OpenAPI, and live-test evidence;
- final status limited to `typed` or `typed-gated` for release completion.

Broad rules such as "all endpoints on this page are typed" are prohibited.
Every typed status must be derived from explicit operation evidence.

## Security Requirements For Closure

- Public unauthenticated endpoints must not accidentally attach a token when
  called from an authenticated client unless the API explicitly opts into it.
- Internal inspect responses containing raw tokens, accessors, headers, paths,
  or storage prefixes must be treated as sensitive operational data and remain
  operator-gated.
- Streaming monitor frames must have bounded frame and buffered-byte limits;
  slow consumers must apply back-pressure rather than permit unbounded memory.
- Protocol helpers must use exact MIME types and must not parse ASN.1, JOSE, or
  ACME structures with ad hoc cryptography.
- Database plugin-specific secrets must not enter ordinary `String` extension
  maps or derived `Debug` output.
- An endpoint documented but removed for a security vulnerability may be
  represented as a typed security-blocked capability rather than re-enabled.
- Documentation defects discovered through live testing must be reported as
  evidence mismatches, not hidden by changing the generator classification.

## Exit Criteria

The `2.5.5` closure is complete only when:

- all 644 rows and all 663 expanded operations are mechanically classified as
  `typed` or `typed-gated`;
- all documented parameters and response fields have explicit coverage;
- generated coverage cannot claim a helper that is absent from the public API;
- mock, fixture, and live evidence exists at the level promised by each row;
- the full-support matrix is regenerated from the immutable `v2.5.5` evidence;
- the compatibility and full-support pentests are clean for the exact commit.
