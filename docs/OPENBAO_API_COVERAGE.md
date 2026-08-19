# OpenBao API Coverage Plan

Checked against official OpenBao `2.5.x` documentation on 2026-05-30.
AppRole administration was refreshed against the same documentation set on
2026-06-01.
RabbitMQ secrets engine coverage was refreshed against official `2.5.x`
documentation on 2026-06-01.
Identity entity, group, and alias coverage was refreshed against official
`2.5.x` documentation on 2026-06-01.
LDAP secrets engine coverage was refreshed against official `2.5.x`
documentation on 2026-06-01.
RADIUS auth coverage was refreshed against official `2.5.x` documentation on
2026-06-02.
LDAP auth coverage was refreshed against official `2.5.x` documentation on
2026-06-02.
Kerberos auth coverage was refreshed against official `2.5.x` documentation on
2026-06-02.
OpenBao `2.6.0` was reviewed from its exact tagged source, runtime OpenAPI, and
digest-pinned image on 2026-07-14 and promoted after the complete live matrix.
OpenBao `2.6.1` was reviewed with the same evidence chain on 2026-07-25.
OpenBao `2.6.2` was reviewed with the same evidence chain on 2026-08-19. Its
tagged API surface changes only generated namespace-list metadata; live tests
cover the release's workflow, PKI, and Transit security fixes.
The exact endpoint contract baseline is captured from the official OpenBao
`v2.5.5` tagged source commit and reconciled with the locked-image OpenAPI
snapshot. It is summarized in `docs/OPENBAO_2_5_ENDPOINT_MATRIX.md`; the
machine-readable extraction is `docs/openbao-2.5-contract-matrix.json`, and the
CSV is a review index. The finalized multi-version source of truth is
`compat/version-contract-matrix.json`.
The tagged-source inventory contains `644` documented rows and `663` expanded
method/path operations. The locked OpenAPI snapshot adds two documented
operations absent from that extraction, producing 665 current `2.5.5`
operations. The supported-release union through OpenBao `2.6.2` contains 691
logical operation identities. The version contract expands that union to
16,584 operation/profile cells. It also fixes the old rendered-
documentation parser's omission of `HEAD /sys/health`.

Sources:

- OpenBao HTTP API: https://openbao.org/api-docs/
- Secret engines: https://openbao.org/api-docs/secret/
- Auth methods: https://openbao.org/api-docs/auth/
- System backend: https://openbao.org/api-docs/system/
- KV v2: https://openbao.org/api-docs/secret/kv/kv-v2/
- AppRole: https://openbao.org/api-docs/auth/approle/
- Database secrets engine: https://openbao.org/api-docs/secret/databases/
- JWT/OIDC auth: https://openbao.org/api-docs/auth/jwt/
- Kubernetes auth: https://openbao.org/api-docs/auth/kubernetes/
- TLS certificate auth: https://openbao.org/api-docs/auth/cert/
- Userpass auth: https://openbao.org/api-docs/auth/userpass/
- LDAP auth: https://openbao.org/api-docs/auth/ldap/
- RADIUS auth: https://openbao.org/api-docs/auth/radius/
- Kerberos auth: https://openbao.org/api-docs/auth/kerberos/
- Transit: https://openbao.org/api-docs/secret/transit/
- PKI: https://openbao.org/api-docs/secret/pki/
- SSH: https://openbao.org/api-docs/secret/ssh/
- TOTP: https://openbao.org/api-docs/secret/totp/
- RabbitMQ: https://openbao.org/api-docs/secret/rabbitmq/
- Identity entity: https://openbao.org/api-docs/secret/identity/entity/
- Identity group: https://openbao.org/api-docs/secret/identity/group/
- Identity entity alias: https://openbao.org/api-docs/secret/identity/entity-alias/
- Identity group alias: https://openbao.org/api-docs/secret/identity/group-alias/
- LDAP secrets engine: https://openbao.org/api-docs/secret/ldap/
- System audit config: https://openbao.org/api-docs/system/config-auditing/
- System config state: https://openbao.org/api-docs/system/config-state/
- System internal UI mounts: https://openbao.org/api-docs/next/system/internal-ui-mounts/
- System internal UI namespaces: https://openbao.org/api-docs/system/internal-ui-namespaces/
- System loggers: https://openbao.org/api-docs/system/loggers/
- System version history: https://openbao.org/api-docs/next/system/version-history/
- System namespaces: https://openbao.org/api-docs/system/namespaces/
- System quotas config: https://openbao.org/api-docs/system/quotas-config/
- System rate-limit quotas: https://openbao.org/api-docs/2.4.x/system/rate-limit-quotas/
- System host info: https://openbao.org/api-docs/system/host-info/
- System locked users: https://openbao.org/api-docs/next/system/user-lockout/
- System Raft storage: https://openbao.org/api-docs/system/storage/raft/
- System Raft Autopilot: https://openbao.org/api-docs/system/storage/raftautopilot/
- System metrics: https://openbao.org/api-docs/2.4.x/system/metrics/
- System HA status: https://openbao.org/api-docs/2.3.x/system/ha-status/
- System key status: https://openbao.org/api-docs/system/key-status/
- System CORS config: https://openbao.org/api-docs/system/config-cors/
- System step down: https://openbao.org/api-docs/system/step-down/
- System remount: https://openbao.org/api-docs/system/remount/
- System tools: https://openbao.org/api-docs/next/system/tools/

## Endpoint Matrix

The `2.0.0` line replaced the former page-level classifications with an exact
operation contract. The original extraction checkpoint recorded:

- unique tagged-documentation rows: `644`;
- expanded method/path operations: `663`;
- exact OpenAPI-pattern matches: `611`;
- ambiguous OpenAPI matches retained for review: `11`;
- documented operations absent from the OpenAPI snapshot: `41`;
- `confirmed-gap` rows at extraction: `38`;
- `unverified` rows at extraction: `606`;
- typed claims in that baseline: `0`.

The earlier `597/643` percentage is withdrawn. The finalized registry contains
691 logical operation identities across all 24 locked releases and 16,584
operation/profile cells. Every operation available in a supported profile is
now `typed`, `typed-gated`, or `security-blocked`; the current `2.6.2` profile
contains 594 typed, 93 typed-gated, and 2 security-blocked operations. Contract
and serde evidence
is endpoint-complete, while live tests remain an explicitly representative
core-flow subset. See
`docs/OPENBAO_VERSION_SUPPORT_MATRIX.md` for current totals and
`compat/version-contract-matrix.json` for the full contract.

## Foundation

- Client config and TLS policy.
- Token and bearer authentication header strategies.
- Namespace header support.
- Response wrapping headers.
- Raw JSON request layer.
- Typed custom plugin wrapper pattern documented in
  `docs/CUSTOM_PLUGIN_PATTERN.md`, backed by public `PluginMount`, path
  validation, and bounded string-list helpers. Generic plugin traits remain
  rejected because plugin schemas are deployment-specific.
- Typed error envelope.
- Health and seal status.
- OpenAPI discovery support through `/sys/internal/specs/openapi`.
- Environment-based client construction from common `OPENBAO_*`, `BAO_*`, and
  `VAULT_*` variables is implemented in `0.4.0`.
- Implemented downstream ergonomics from Mjolni/Pawalyze review:
  KV v2 service config loading into typed structs or bounded secret string maps
  with required-key accessors, byte-oriented Transit helpers, JWS-oriented
  Transit sign/verify helpers, ACL policy builders, and idempotent admin
  bootstrap for common service setup.
- Posture helpers:
  best-effort FIPS-oriented reporting is implemented for crate-visible Transit
  and seal-assumption choices. `docs/QUANTUM_READINESS.md` tracks the
  advisory-only quantum-readiness posture without claiming current
  post-quantum safety.
- Shared list ergonomics:
  common string list response structs implement `ListEntries`; secret accessor
  lists remain separate secret-aware types.
- Timestamp ergonomics:
  optional RFC3339 parsing helpers are available behind the `time` feature
  while response structs keep OpenBao's original string fields.

## Auth Methods

The official `2.5.x` API navigation lists:

- AppRole.
- JWT/OIDC.
- Kerberos.
- Kubernetes.
- LDAP.
- RADIUS.
- TLS certificates.
- Tokens.
- Username and password.

Support plan:

- `0.1.0`: AppRole login.
- `0.2.0`: token lifecycle helpers; create, lookup, renew, revoke, and accessor
  flows are implemented.
- `0.4.0`: Kubernetes login/config/role helpers and TLS certificate
  login/config/role/CRL helpers are implemented.
- `0.5.0`: userpass login and user administration are implemented; JWT login
  plus JWT/OIDC config and role administration helpers are implemented.
- `0.8.0`: JWT/OIDC browser flow helpers for authorization URL, callback, and
  direct/device polling are implemented. In `2.0.0`, GET
  callback redemption and direct/device polling require
  `oidc-get-callback-acknowledged` because credentials and correlation values
  necessarily enter URL query strings.
- `0.7.0`: AppRole role and SecretID administration is implemented. Admin
  bootstrap orchestration for auth method enablement, AppRole role
  convergence, and explicit SecretID issuance is implemented.
- `0.9.0`: AppRole delegated role-property helpers are implemented for all
  documented OpenBao `2.5.x` per-property paths, including read, write, and
  reset/delete operations.
- `0.8.0`: LDAP login, config, user mapping, group mapping, list, read, and
  delete helpers are implemented. RADIUS login, config, user mapping, user
  deletion, and paginated user listing are implemented. Kerberos SPNEGO login,
  service-account/keytab config, Kerberos LDAP config, and group policy mapping
  helpers are implemented. LDAP and Kerberos LDAP TLS version fields reject
  deprecated TLS 1.0 and TLS 1.1 values.

## Secret Engines

The official `2.5.x` API navigation lists:

- Cubbyhole.
- Databases.
- Identity.
- Key/Value v1 and v2.
- Kubernetes.
- LDAP.
- PKI.
- RabbitMQ.
- SSH.
- TOTP.
- Transit.

Support plan:

- `0.1.0`: KV v2.
- `0.2.0`: KV v1 and expanded KV v2 metadata/version operations; KV v1
  read/write/delete/list and KV v2 patch, config, metadata, undelete, destroy,
  and version reads are implemented.
- `0.4.0`: KV v2 typed data reads and bounded service config maps with
  `SecretString` values are implemented.
- `0.3.0`: Transit key create/read/list/delete, encrypt, decrypt, rewrap,
  data key, random, hash, HMAC, sign, and verify are implemented.
- `0.5.0`: optional `transit-bytes` helpers encode raw request bytes and
  decode base64 Transit response fields using `base64-ng`; typed RSA
  signature options, JWS marshaling helpers, and RSA-PSS salt length helpers
  are implemented for sign/verify.
- `0.8.0`: Transit key config update, key rotation, export, backup, restore,
  trim, and batch encrypt/decrypt/rewrap/sign/verify helpers are implemented.
- `0.11.0`: Transit wrapping-key, import/import-version, BYOK export,
  soft-delete/restore, cache config, global key config, CSR generation, and
  certificate install rows are implemented. `wrapping_key` returns a public
  PEM string. Import requests carry pre-wrapped ciphertext as `SecretString`
  or public-key-only import material and reject empty import material;
  optional derivation context is also secret-aware. BYOK export returns a
  wrapped ciphertext blob as `SecretString`. Raw private key bytes are never
  accepted by these default endpoint wrappers. The optional `transit-import`
  feature prepares OpenBao's
  wrapped-key blob with AES-KWP/RSA-OAEP behind feature-gated `openssl` and
  `aes-kw` dependencies.
- `0.4.0`: PKI URL and CRL config, root/intermediate generation,
  intermediate signing/install, role write/read/list/delete, issue, sign,
  revoke, certificate list/read, issuer/key list/read/delete/update, issuer
  revocation, CA/key import, ACME config/EAB/directory URL helpers, CRL
  rotation, tidy, tidy status, tidy cancel, role merge-patch, default
  issuer/key config, named-issuer issue/sign, root rotate/replace, standalone
  key generation, multi-issuer root/intermediate generation, and
  operator-gated default root deletion with explicit `PkiRootDeletion`
  confirmation, cluster config, auto-tidy config, revoke-with-key,
  sign-verbatim behind operator gates, current-doc field expansion for PKI
  role/generation/CRL/tidy structs, revocation/CRL management, CEL roles,
  named-issuer sign-intermediate, delta CRL rotation, and operator-gated
  sign-self-issued/cross-sign rows are implemented.
  Unauthenticated public CA/certificate/CRL reads and bounded raw OCSP
  transport are typed. Full ACME
  account/order/authorization/challenge client flows are permanently external:
  use the typed ACME config, EAB, and directory URL helpers to hand off to a
  dedicated ACME client.

Compatibility Commit 13 added token-free bounded OCSP and public
CA/CRL/certificate distribution transport. ASN.1 parsing and ACME protocol
state machines remain with established protocol libraries.
- `0.5.0`: database connection config/list/read/delete/reset, root rotation,
  dynamic role list/write/read/delete, dynamic credentials, static role
  list/write/read/delete, static credentials, and static role rotation are
  implemented.
- `0.6.0`: TOTP key create/read/list/delete, code generation, and code
  validation are implemented. SSH role management, zero-address roles, IP role
  lookup, OTP credential issue, default issuer config, issuer
  list/submit/read/update/delete, authenticated CA public-key metadata, CA
  sign/issue, and OTP verification are implemented. Compatibility Commit 14
  adds complete role fields and token-free bounded default/per-issuer
  `text/plain` public-key reads.
- `0.7.0`: Cubbyhole read/write/delete/list is implemented. Kubernetes secrets
  engine config, roles, role listing, deletion, and credential generation are
  implemented. RabbitMQ connection config, lease config, role
  write/read/list/delete, and generated credential helpers are implemented.
  Identity entity, group, entity-alias, and group-alias lifecycle helpers are
  implemented. Entity/group lookup and entity merge helpers are implemented in
  `0.8.0`. Identity OIDC token backend config, signing key CRUD/rotate, role
  CRUD/list, signed token generation, token introspection, discovery metadata,
  and default JWKS reads are implemented in `0.10.0`. Identity OIDC provider,
  scope, client, assignment, named-provider discovery, and named-provider JWKS
  helpers are implemented in `0.10.0`. Typed named-provider authorize, token,
  and userinfo protocol helpers are implemented on the `2.0.0` development
  line, using an unauthenticated handle, secret-aware OAuth values, form token
  exchange, and explicit Basic/Bearer header separation. MFA method management, MFA TOTP
  generation/admin actions, and MFA login enforcement helpers are implemented
  in `0.10.0`. LDAP config,
  root rotation, static roles/credentials, dynamic roles/credentials, and
  library check-out/check-in helpers are implemented.

## System Backend

The official `2.5.x` system backend includes many endpoints under `/sys`,
including audit, auth mounts, capabilities, config, health, init, leader,
leases, loggers, metrics, mounts, namespaces, plugins, policies, quotas, raw,
rekey, remount, rotate, seal, storage, tools, unseal, locked users, version
history, and response wrapping.

Support plan:

- `0.1.0`: health and seal status.
- `0.2.0`: mounts, auth mounts, response wrapping, policies, and capabilities.
- `0.3.0`: audit device list/enable/disable/hash, exact lease
  lookup/renew/revoke, plugin catalog list/type-list/register/read/delete,
  mounted plugin backend reload, init status, and loopback-only dev bootstrap
  are implemented.
- `0.8.0`: token role write/read/list/delete, token tidy, and revoke-orphan are
  implemented.
- `0.9.0`: token create-orphan and accessor renewal helpers are implemented.
  The `2.0.0` version contract represents applicable lookup-self GET and POST
  forms as separate immutable operation variants rather than a partial claim.
- `0.10.0`: `sys/mfa/validate` is implemented as the typed second step for
  MFA-enforced login flows, with passcodes, returned client tokens, and
  accessors handled as secret material.
- `0.8.0`: capability responses now include typed borrowed views and common
  access-check helpers while preserving the raw string lists.
- `0.6.0`: idempotent admin bootstrap builder is implemented for KV v2 mounts,
  Transit mounts, Transit keys, ACL policies, KV v2 string secret values, and
  explicit scoped service-token issuance.
- `0.7.0`: admin bootstrap now supports auth method enablement, AppRole role
  convergence, and explicit AppRole SecretID issuance.
- `0.8.0`: admin bootstrap read-only preview is implemented for existing
  bootstrap operations, including explicit `WouldIssue` reporting for
  credential issuance steps.
- `0.6.0`: production init, unseal, seal, legacy rekey, OpenBao key-share
  rotation, and keyring rotation are implemented only behind explicit
  `operator-ops` plus `operator-ops-acknowledged` feature gates.
- `0.8.0`: leader status, HA status, key status, OpenAPI discovery, internal
  UI namespace/mount discovery, JSON metrics, host diagnostics, sanitized
  config state, audited request-header configuration, CORS configuration,
  runtime logger read/set/reset, installed version history, namespace
  management, rate-limit quota management, remount/mount-migration
  start/status, operator-gated active-node step-down, system random/hash tools,
  Prometheus metrics text output, and locked-user list/filter/unlock helpers are
  implemented. Integrated Storage Raft join/configuration/peer
  mutation/bootstrap helpers, capped snapshot download/restore helpers, and
  Autopilot JSON helpers are implemented; Raft join inputs require HTTPS leader
  addresses and HTTPS auto-join schemes. Raw storage read/write/list/delete
  helpers and pprof diagnostic byte helpers are implemented behind explicit
  operator-operation feature gates. Lease prefix revoke, force prefix revoke,
  lease count, lease tidy, and `RenewalHint` timing helpers are implemented.
  CORS wildcard origins are rejected locally. Password policies, resultant ACL,
  operator-gated generate-root/recovery-token, local token decoding, legacy
  recovery-key rekey, and typed operator-gated in-flight request inspection are
  implemented in `0.14.0`. System config UI and internal router, counter, and
  request inspection are now typed behind unstable operator gates. Monitor is
  omitted for stable scope.

## Ergonomics And Capability Roadmap

Started in `0.9.0`:

- API stability audit checklist in `docs/API_STABILITY_AUDIT.md`.
- Migration guide from earlier `openbao` releases, `vaultrs`, and bespoke
  `reqwest` wrappers in `docs/MIGRATION_GUIDE.md`.

Implemented in `0.8.0`:

- `Error::is_rate_limited`, `Error::is_temporary`, and
  `Error::is_permission_denied` helpers.
- Runtime-neutral `Sys::wait_ready_with_delay` for startup and integration
  tests.
- Runtime-neutral `Sys::wait_until_unsealed_with_delay` plus
  `tokio-helpers`-gated `Sys::wait_until_unsealed` for bounded startup and
  recovery polling.
- `Client::wrapping`, `WrappingContext`, and `WrappedResponse<T>` for typed
  response-wrapped JSON requests and typed unwrap of the original response
  shape.
- ACL policy-builder wrapping TTL constraints and helper variants for policies
  that require response wrapping.
- Selective AdminBootstrap convergence for PKI, database, and SSH mounts,
  database dynamic/static roles, and SSH roles.
- KV v2 historical reads were already covered by `read_version` and
  `read_data_version`.

Finalization work completed before `1.0.0`:

- explicit opt-in retry policy with exponential backoff and bounded jitter is
  implemented through `RetryPolicy`, `RetryableMethod`, and
  `Client::request_json_with_retry`;
- shared non-secret paginated-list abstraction is implemented in `0.9.0`
  through `ListPageOptions`;
- admin bootstrap convergence for PKI roles and Identity entities/groups is
  implemented in `0.9.0`;
- representative serde response fixtures are added in `0.9.0`;
- fuzz target scaffolding for path validation, error decoding, and response
  envelopes is added in `0.9.0`;
- reject background token auto-renewal, background lease tracking, and
  `LeaseHandle` wrappers for stable scope; use `RenewalHint` for caller-owned
  renewal timing;
- keep the optional `tracing` feature as the stable observability boundary,
  reject OpenTelemetry SDK dependencies and custom request hooks for stable
  scope, defer W3C `traceparent` propagation, add non-default `http2` support
  without a runtime transport knob, and reject HTTP/3 for stable scope.
- reject ongoing request-level seal back-pressure as application
  retry-middleware policy.
- reject per-engine wrapped response method duplication; callers use
  `Client::wrapping` for generic typed JSON response wrapping.
- reject PKI CA setup, database connection config, SSH CA setup, and KV v1
  convergence in the bootstrap layer.
- reject ACL parameter-constraint generation because safe output requires a
  full HCL value serializer.
- reject leaf certificate and SPKI pinning for stable scope; use root-only
  trust with an internal OpenBao CA or self-signed OpenBao certificate instead.
- use `0.10.0` through `0.14.0` for Identity/auth, Transit, PKI, and System
  endpoint-family completion;
- used `0.15.0` as the endpoint-closure release where no matrix row could
  remain `decision`.

## OpenBao-Specific Notes

The official `2.5.x` HTTP API documentation states:

- all API routes are prefixed with `/v1`; this is a routing namespace, not a
  promise that operation contracts remain compatible between server releases;
- TLS with certificate verification is expected;
- tokens are documented through `X-Vault-Token` or `Authorization: Bearer`;
- `X-Vault-Request: true` is used by the official SDK/CLI behavior;
- path parameters must not end in periods;
- applications should accept both `200` and `204` where applicable;
- KV v2 patch operations use `application/merge-patch+json`;
- errors commonly use `{"errors": [...]}` for status codes `>= 400`.

The crate follows those documented behaviors by default.
