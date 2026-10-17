# Current Capability Status

This document contains the detailed capability inventory for the current
`openbao` release line. For installation and first-use examples, start with
the [README](../README.md). For endpoint-level classifications, see
[OpenBao API Coverage](OPENBAO_API_COVERAGE.md) and the generated
[exact-version support matrix](OPENBAO_VERSION_SUPPORT_MATRIX.md).

## Release Snapshot

### SDK 2.2.4

SDK `2.2.4` is a tooling and dependency maintenance release using Rust 1.99.1
with an unchanged Rust 1.90 MSRV. It includes Tokio 1.53.3 and non-yanked
`inout 0.2.4`. Public APIs, feature defaults, 28 exact server profiles and
reviewed external-plugin operations are unchanged. See the
[2.2.4 release notes](../release-notes/RELEASE_NOTES_2.2.4.md).

All 15 privileged fixture invocations passed against the 2.2.4 inputs and
rebuilt executables. Retained evidence comprises 16 reports and six plugin
API schemas, verified against current source-input hashes, local executable
digests, exact operation scope and success requirements:

- Current-profile CI: `compat/ci/2.2.4/{2.6.4,2.7.0,2.7.1}.json`.
- Normal patch SDK: `sdk-normal-tls-v9.json` on 2.6.4 and 2.7.1.
- 2.7.0 consistency and backup SDK captures: `*-tls-v10.json`.
- LDAP, Kerberos and RADIUS: `sdk-normal-v4/` on both 2.7.0 and 2.7.1.

Older reports remain immutable and cannot satisfy the current-input gates.
Server-only evidence was not relabelled. Unsigned directory/RADIUS fixture
acknowledgements, trusted local-builder boundaries and the upstream
control-group replay limitation remain unchanged. GitHub approval and
publication are separate from these local fixture results.

Final local validation passed: the complete `scripts/checks.sh` run and all
536 Python tests, including previous-release evidence rejection. Checks cover
669 all-feature Rust tests and five doctests, default-feature tests, Clippy,
MSRV, native-TLS unification, fuzz compilation, ML-DSA validation budgets,
documentation, packaging, dependency policy, fresh audits and Kani proofs.

The following checkpoint results describe the preceding 2.2.3 development
tree. They are historical evidence, not captures bound to the 2.2.4 package.

### Local Tooling Update (2026-10-16)

The unpublished development tree uses Rust 1.99.1, refreshed GitHub Actions
pins and updated dependency lockfiles, including Tokio 1.53.3. The package
version and MSRV are unchanged. The release snapshot below describes published
2.2.3, not fresh live verification of these dependency updates.

The original SDK and current-profile CI captures remain unchanged as historical
evidence. Their input hashes do not match the updated tree. Fresh captures for
the tooling update are retained separately as described below; no tag or
release is part of this tooling checkpoint.

Local verification passed: 669 all-feature Rust tests and five doctests,
default tests, formatting, default/all/minimal-feature Clippy, Rust 1.90 MSRV,
fuzz compilation, native-TLS unification, docs, packaging and packaged smoke
tests/examples, the ML-DSA validation budget, Kani, SBOM generation, and
dependency policy/RustSec checks for all three lockfiles. The toolchain-pin
and workflow-control tests also passed. Python discovery ran 523 tests with
two failures and 34 errors, all in stale retained-evidence validation, before
the refresh below. That initial `scripts/checks.sh` run stopped at the
current-profile evidence gate and was not completed release validation.

The 2026-10-17 CI follow-up updates the historical compatibility controller's
reviewed workflow hash for the Rust/action pin changes. Its self-test and
workflow mutation regressions pass. This fixes matrix planning, not the
separate SDK/current-profile evidence gate; no version bump is needed.

### Live Evidence Refresh (2026-10-17)

All 15 privileged fixture invocations passed against the Rust 1.99.1 builds,
producing 16 reports plus six mounted-plugin API schemas. Before retention,
the reports were checked against the current source-input hashes and actual
local executable SHA-256 digests, with exact scope and success requirements.

- Current-profile CI on 2.6.4, 2.7.0 and 2.7.1: `compat/ci/2.2.3/*-v3.json`.
- Normal SDK on 2.6.4 and advanced SDK on 2.7.1: `sdk-normal-tls-v7.json`.
- 2.7.0 consistency baseline/lag and ordinary, strict and candidate backup
  SDK captures: `*-tls-v8.json`.
- LDAP, Kerberos and RADIUS on 2.7.0 and 2.7.1: each plugin's `sdk-normal-v2/`.

Previous captures are immutable and tested to reject reuse against current
inputs even if their report and binary pins are restored. Server-only evidence
was not relabelled or rerun. The unsigned directory/RADIUS backend acknowledgements,
local trusted-builder boundary, and known upstream replay limitation remain.
GitHub approval and any release remain separate from these local captures.

Post-refresh verification passed: the complete `scripts/checks.sh` run,
all 534 Python tests, and SBOM generation. This includes the restored
current-source evidence gates, 669 all-feature Rust tests, five doctests,
MSRV, Clippy, packaging, all configured Kani proofs, and fresh RustSec scans
of all three lockfiles against 1,334 advisories. The CI installer action is
pinned to reviewed `taiki-e/install-action` v2.87.29 for the latest-tool gate.

### Yanked Dependency Follow-up (2026-10-17)

GitHub's dependency-policy gate rejected the upstream-yanked `inout 0.2.3`.
The main lockfile now selects non-yanked `inout 0.2.4`; the other lockfiles,
package version, and production Rust are unchanged. The policy was not relaxed.

All 15 privileged fixture invocations passed again with this lockfile.
The 16 validated reports and six plugin schemas are retained separately:

- Current-profile CI: `compat/ci/2.2.3/*-v4.json`.
- Normal patch SDK: `sdk-normal-tls-v8.json` on 2.6.4 and 2.7.1.
- 2.7.0 consistency and backup SDK captures: `*-tls-v9.json`.
- LDAP, Kerberos and RADIUS: `sdk-normal-v3/` on both 2.7.0 and 2.7.1.

The preceding refresh remains historical. Current validators require the new
lockfile hash, even when an old report's digest and executable pins are restored.
GitHub approval and any release remain separate.

Post-refresh verification passed: the complete `scripts/checks.sh` run and
all 535 Python tests. This includes formatting, MSRV, Clippy, Rust tests and
doctests, packaging, dependency policy, fresh RustSec audits, and Kani proofs.

### Published 2.2.3

SDK `2.2.3` adds explicitly selected official v0.1.0 LDAP auth/secrets,
Kerberos and RADIUS plugins on exact OpenBao 2.7.0 and 2.7.1. Feature defaults
are unchanged from `2.2.2`; Tokio is updated to 1.53.2.
The generated Rust inventory contains 707 operation identities across 28 exact
profiles (19,796 cells), including independently reviewed
[OpenBao 2.6.4](OPENBAO_2_6_4_REVIEW.md), `2.7.0` and
[OpenBao 2.7.1](OPENBAO_2_7_1_REVIEW.md).

Plugin contracts cover 48 distinct operations across eight plugin/server
combinations. They require a verified server profile and an explicit mount and
artifact selection, which is an administrator assertion rather than remote
attestation. See [external plugin selection](OPENBAO_EXTERNAL_PLUGINS.md).
Current-source validators require exact input hashes; earlier release and
checkpoint captures remain historical and are not relabelled.

The historical 25-release CI matrix is preserved. Supplemental live CI checks
exercise eight public SDK core operations over verified TLS on `2.6.4`, `2.7.0`
and `2.7.1`. A coverage guard checks the union against all supported profiles.
Historical 2.2.2 CI reports remain under `compat/ci/2.2.2/`. These jobs are not
substitutes for advanced, multi-node or external-plugin fixture evidence.
See the [2.2.3 release notes](../release-notes/RELEASE_NOTES_2.2.3.md) for
the separate evidence and CI release gates.

Published `2.2.3` used Rust `1.99.0`; the MSRV remains `1.90.0`. The unselected
client still uses the unverified `2.6.3` baseline. Legacy LDAP, Kerberos and
RADIUS engines remain built-in on `2.6.4`; on both reviewed 2.7 profiles they
require the external-plugin selections described above. The known upstream
control-group replay failure persists on `2.7.1`.

### Published 2.2.0 Baseline

`2.2.0` adds [OpenBao 2.7.0 support](OPENBAO_2_7_0_PLAN.md).
That release's generated Rust inventory contains
707 operation identities across 26 profiles. The checkpoint 10 pentest follow-up
hardens inspection storage and executable custody; affected source-bound live
evidence has been recaptured and validated, and the full local release checks
passed. The final security retest was clean, and Rust CI and CodeQL passed on
implementation commit `eb85bf9`.

The 2.7 additions include external keys, Transit and PKI ML-DSA/KMS controls,
control groups, scoped consistency, workflow CAS and grouped rotation backups.
LDAP auth/secrets, Kerberos and RADIUS remain excluded on 2.7 pending verified
external plugins; their older built-in profiles remain supported. The known
upstream control-group replay defect is not fixed by the SDK.

Unconfigured clients retain the unverified 2.6.3 contract. See
[version selection](OPENBAO_VERSION_SELECTION.md) for explicit 2.7 selection
and stricter workflow CAS/consistency requirements. The separate 2.7 reports
do not claim live execution of every endpoint.

### Published Historical Baseline

The following inventory describes the unchanged profiles inherited from
stable `2.1.9`.

The preceding stable line, `2.1.x`, provides explicit, fail-closed OpenBao
server-version compatibility for every published stable release from `2.0.0`
through `2.6.3`. The active registry contains 691 operation identities across
25 exact profiles and 17,275 explicit operation/profile cells.

Exact OpenBao `2.6.3` resolves all 689 documented operations: 594 typed, 93
typed-gated, and two security-blocked because of confirmed upstream defects.
No operation is postponed or left in a planning state.

Every digest-pinned release from `2.0.0` through `2.6.3` passes its own
exact-profile live matrix. OpenBao 2.6 response additions use semver-safe
`*Details` types and methods, including `seal_status_details`,
`lookup_lease_details`, `version_history_details`, `read_policy_details`, and
engine-specific detailed role/config reads. Existing constructible 2.0 structs
keep their original field sets. Explicit methods such as
`configure_with_decode_pac` and `write_cors_config_with_credentials` send
2.6-only request fields after exact profile validation.
OpenBao `2.6.1` through `2.6.3` expose typed ACL policy PATCH and preserve JWT CEL
PATCH constraints. CEL PATCH remains blocked for exact `2.6.0` and requires
explicit claim-validation acknowledgement on `2.6.1` through `2.6.3`. Exact
`2.6.2` and `2.6.3` also pass live regressions for unauthenticated workflow dispatch,
CSR IP-SAN CIDR enforcement, and non-default Transit HMAC verification.
Exact `2.6.3` additionally tests canonical userpass ACL denial and raw storage
round trips. See [the patch review](OPENBAO_2_6_3_REVIEW.md) for the upstream
explicit-compression creation caveat and the corrected raw-read envelope.

## Implemented Capabilities

- Async client with typestate authentication.
- Direct token authentication with re-exported `openbao::SecretString`.
- AppRole login plus role and SecretID administration, with role IDs,
  SecretIDs, accessors, and returned tokens treated as secret material.
- Kubernetes auth login plus config and role administration helpers.
- TLS certificate auth login, method config, CA role, and CRL administration
  helpers.
- JWT login plus JWT/OIDC auth method config, role administration, browser
  authorization URL and direct/device polling helpers, plus explicitly
  acknowledged GET callback redemption and 2.6 CEL/Kubernetes-provider
  contracts.
- LDAP auth login plus config and user/group policy mapping helpers.
- RADIUS login plus config and user policy mapping helpers.
- Kerberos login plus service-account, LDAP config, and group policy mapping
  helpers, including 2.6 PAC-decoding configuration.
- Userpass login plus user create/read/list/delete, password update, and
  policy update helpers, including 2.6 validated bcrypt hashes.
- OpenBao 2.6 ACL, PKI, and SSH identity-template delimiter readback, with
  dangerous write overrides available only through an acknowledged feature
  and explicit per-surface constructors.
- Token create, create-orphan, role create/read/list/delete, lookup, accessor
  lookup/list/renew/revoke, renew, revoke, revoke-orphan, revoke-self, and tidy
  helpers.
- KV v2 read, write, CAS write, patch, list, latest delete, version read,
  version delete, undelete, destroy, metadata, backend config, typed data, and
  secret-aware service config read/write helpers.
- KV v1 read, write, delete, and list helpers.
- Cubbyhole read, optional read, write, delete, and list helpers for
  token-scoped handoff data.
- Kubernetes secrets engine config, role create/read/list/delete, and service
  account credential generation helpers.
- RabbitMQ secrets engine connection config, lease config, role
  create/read/list/delete, and dynamic credential helpers.
- Database connection config, dynamic roles, static roles, root/static
  rotation, and credential helpers, with secret-aware role credential
  configuration for client-certificate CA private keys.
- Identity entity, group, entity-alias, and group-alias lifecycle, lookup,
  entity merge, OIDC token backend config, signing key CRUD/rotate, role CRUD,
  signed ID token generation, token introspection, discovery, JWKS, OIDC
  provider/scope/client/assignment admin, and named-provider discovery/JWKS
  helpers.
- LDAP secrets engine config, static role, dynamic role, credential, library
  checkout, and check-in helpers.
- SSH role, zero-address role, IP lookup, OTP credential, issuer config,
  issuer list/submit/read/update/delete, CA public-key metadata, CA sign,
  generated certificate/key issue, and OTP verification helpers.
- TOTP key create/read/list/delete, code generation, and code validation
  helpers.
- PKI URL and CRL config, default issuer/key config, root/intermediate
  generation, root rotate/replace, intermediate signing and install,
  multi-issuer issue/sign flows, role write/read/list/delete/patch, CEL roles,
  issue, sign, revoke, revoke-with-key, certificate list/read, issuer/key
  list/read/delete/update, issuer revoke, CA/key import, ACME config/EAB and
  typed client handoff, unauthenticated CA/certificate/CRL distribution and
  OCSP helpers, CRL and delta-CRL management, tidy, tidy status, and tidy
  cancel helpers.
- Transit key create, read, list, delete, config update, rotate, export, BYOK
  wrapping-key/import/import-version/export helpers, soft-delete/restore,
  cache/global config, CSR generation, certificate-chain install, backup,
  restore, trim, encrypt/decrypt/rewrap batch helpers, data key, random, hash,
  HMAC, sign/verify batch helpers, typed RSA/JWS signing options, optional
  raw-byte helpers, and gated software import-wrapping helpers.
- System health, readiness polling, seal status, leader status, OpenAPI
  discovery, JSON metrics, runtime logger level, version history, namespace
  management, rate-limit quota management, password policies, resultant ACL
  inspection, and loopback-only dev bootstrap helpers.
- Secret and auth mount enable, list, read, tune, and disable helpers.
- Response wrapping lookup, wrap, unwrap, and rewrap helpers.
- Typed response wrapping through `Client::wrapping`, `WrappingContext`, and
  `WrappedResponse<T>`.
- ACL policy list, read, write, 2.6.1 merge-patch, delete, and prefix list
  helpers.
- Bounded ACL policy builder helpers for common KV v2 and Transit
  least-privilege rules, including response-wrapping TTL constraints.
- Idempotent admin bootstrap plan builder for KV v2 mounts, Transit mounts,
  Transit keys, ACL policies, KV v2 string secret values, auth methods,
  AppRole roles, PKI/database/SSH mount and role convergence, explicit scoped
  service-token issuance, and explicit AppRole SecretID issuance.
- Capability checks for the caller token, an explicit token, or a token
  accessor.
- Audit device list, enable, disable, and hash helpers.
- Safe exact lease lookup, renew, revoke, prefix revoke, force prefix revoke,
  and lease count helpers.
- Plugin catalog list, type-list, register, read, delete, and backend reload
  helpers.
- Explicitly gated production init, unseal, seal, rekey, key-share rotation,
  keyring rotation, root/recovery-token generation, local token decoding,
  legacy recovery-key rekey, and in-flight request inspection operator APIs.
- Environment-based client construction from common OpenBao/Vault variables.
- Shared authenticated client and Rust `Duration` to OpenBao duration string
  helpers for async application ergonomics.
- Explicit retry/backoff helpers for caller-approved idempotent raw requests.
- Bootstrap read-only preview, report lookup helpers for issued credentials,
  and changed steps.
- Best-effort FIPS-oriented posture reporting for crate-visible Transit and
  deployment assumptions; this is advisory and not a certification claim.
- Shared `ListEntries` ergonomics for common list responses without changing
  their documented fields.
- Optional RFC3339 timestamp parsing helpers behind the `time` feature.
- Optional `tracing` and HTTP/2 features without default dependency or runtime
  transport hooks.
- Feature-gated raw JSON request escape hatch for audited deployment-specific
  wrappers.
- Operator-gated raw storage read, write, list, and delete helpers.
- Operator-gated pprof diagnostic byte helpers.
- Typed custom plugin wrapper pattern documentation and safe building blocks
  for application-specific OpenBao plugin APIs.
- Local TLS OpenBao Podman stack on `9940` and `9941`.
- Version-locked real OpenBao integration harness plus a committed core-flow
  baseline covering all 25 exact releases from `2.0.0` through `2.6.3`.
- Generated read-only capability profiles with 707 stable, secret-free
  operation identities, including 16 added identities. The immutable
  historical registry retains 691 identities across 25 profiles;
  2.2.0 can dispatch against 26 reviewed profiles including
  2.7. Affected live evidence is refreshed. Unselected
  clients retain the unverified 2.6.3 API contract, not an implicit 2.7 upgrade.

## Evidence And History

Repository-only compatibility evidence, CI workflows, release tooling, and
historical planning files remain available from the signed Git tag without
being copied into every crates.io download. The registry archive retains the
runtime source, compiled examples, compact consumer/security documentation,
and a public-API package smoke test. Full repository tests run before the
extracted archive is tested and are retained in the signed source tag. Feature
history and release details live in the [changelog](../CHANGELOG.md) and
[GitHub releases](https://github.com/valkyoth/openbao-rust-crate/releases).

See the [API coverage document](OPENBAO_API_COVERAGE.md),
[version-selection guide](OPENBAO_VERSION_SELECTION.md), and
[API stability audit](API_STABILITY_AUDIT.md) for the maintained support
boundaries.
