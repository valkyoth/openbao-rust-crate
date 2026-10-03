# Current Capability Status

This document contains the detailed capability inventory for the current
`openbao` release line. For installation and first-use examples, start with
the [README](../README.md). For endpoint-level classifications, see
[OpenBao API Coverage](OPENBAO_API_COVERAGE.md) and the generated
[exact-version support matrix](OPENBAO_VERSION_SUPPORT_MATRIX.md).

## Release Snapshot

SDK `2.2.2` is documentation and CI maintenance only; its SDK implementation,
dependencies and feature defaults are unchanged from the released `2.2.1`.
The generated Rust inventory contains 707 operation identities across 28 exact
profiles (19,796 cells), including independently reviewed
[OpenBao 2.6.4](OPENBAO_2_6_4_REVIEW.md), `2.7.0` and
[OpenBao 2.7.1](OPENBAO_2_7_1_REVIEW.md).

The signed `v2.2.1` tag records the clean final pentest and green GitHub checks
on `68a4b12`. That release passed 657 all-feature Rust tests, 5 doctests,
configured Clippy, MSRV, package, dependency and Kani checks. Its seven final
SDK captures cover the mapping and OIDC security corrections. Those original
reports remain immutable. Seven fresh 2.2.2 SDK captures now bind the changed
package metadata and README: patch normal-build `-v4` and 2.7.0 SDK `-v5`
reports. Every captured input must match exactly; the old README exception is
removed and previous executions are not relabelled.

The historical 25-release CI matrix is preserved. Supplemental live CI checks
exercise eight public SDK core operations over verified TLS on `2.6.4`, `2.7.0`
and `2.7.1`. A coverage guard checks the union against all supported profiles.
All three supplemental profiles passed locally; their source-bound reports
are retained under `compat/ci/2.2.2/` with pinned validators and mutation tests.
These jobs are not substitutes for advanced or multi-node fixture evidence.
See the [2.2.2 release notes](../release-notes/RELEASE_NOTES_2.2.2.md) for
the separate final evidence and CI release gates.

The primary compiler is Rust `1.99.0`; the MSRV remains `1.90.0`. The unselected
client still uses the unverified `2.6.3` baseline. Legacy LDAP, Kerberos and
RADIUS engines remain available on `2.6.4` and excluded on both reviewed 2.7
profiles. The known upstream control-group replay failure persists on `2.7.1`.

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
