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
- System loggers: https://openbao.org/api-docs/system/loggers/
- System version history: https://openbao.org/api-docs/next/system/version-history/
- System namespaces: https://openbao.org/api-docs/system/namespaces/
- System quotas config: https://openbao.org/api-docs/system/quotas-config/
- System rate-limit quotas: https://openbao.org/api-docs/2.4.x/system/rate-limit-quotas/
- System host info: https://openbao.org/api-docs/system/host-info/
- System locked users: https://openbao.org/api-docs/next/system/user-lockout/
- System Raft storage: https://openbao.org/api-docs/system/storage/raft/
- System Raft Autopilot: https://openbao.org/api-docs/system/storage/raftautopilot/
- System HA status: https://openbao.org/api-docs/2.3.x/system/ha-status/
- System key status: https://openbao.org/api-docs/system/key-status/
- System CORS config: https://openbao.org/api-docs/system/config-cors/
- System step down: https://openbao.org/api-docs/system/step-down/
- System remount: https://openbao.org/api-docs/system/remount/

## Foundation

- Client config and TLS policy.
- Token and bearer authentication header strategies.
- Namespace header support.
- Response wrapping headers.
- Raw JSON request layer.
- Typed custom plugin wrapper pattern documented in
  `docs/CUSTOM_PLUGIN_PATTERN.md`.
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
  and seal-assumption choices. A future quantum-readiness profile remains
  planned once OpenBao exposes stable primitives.
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
  plus JWT/OIDC config and role administration helpers are implemented. Browser
  OIDC callback helpers remain planned.
- `0.7.0`: AppRole role and SecretID administration is implemented. Admin
  bootstrap orchestration for auth method enablement, AppRole role
  convergence, and explicit SecretID issuance is implemented.
- `0.8.0`: LDAP login, config, user mapping, group mapping, list, read, and
  delete helpers are implemented. RADIUS login, config, user mapping, user
  deletion, and paginated user listing are implemented. Kerberos SPNEGO login,
  service-account/keytab config, Kerberos LDAP config, and group policy mapping
  helpers are implemented.

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
- `0.4.0`: PKI URL and CRL config, root/intermediate generation,
  intermediate signing/install, role write/read/list/delete, issue, sign,
  revoke, certificate list/read, issuer/key list/read/delete/update, issuer
  revocation, CA/key import, ACME config/EAB/directory URL helpers, CRL
  rotation, and tidy are implemented. Full ACME account/order/challenge client
  flows are intentionally left to dedicated ACME clients.
- `0.5.0`: database connection config/list/read/delete/reset, root rotation,
  dynamic role list/write/read/delete, dynamic credentials, static role
  list/write/read/delete, static credentials, and static role rotation are
  implemented.
- `0.6.0`: TOTP key create/read/list/delete, code generation, and code
  validation are implemented. SSH role management, zero-address roles, IP role
  lookup, OTP credential issue, default issuer config, issuer
  list/submit/read/update/delete, authenticated CA public-key metadata, CA
  sign/issue, and OTP verification are implemented. Raw unauthenticated
  text/plain SSH public-key reads are intentionally not typed.
- `0.7.0`: Cubbyhole read/write/delete/list is implemented. Kubernetes secrets
  engine config, roles, role listing, deletion, and credential generation are
  implemented. RabbitMQ connection config, lease config, role
  write/read/list/delete, and generated credential helpers are implemented.
  Identity entity, group, entity-alias, and group-alias lifecycle helpers are
  implemented. LDAP config, root rotation, static roles/credentials, dynamic
  roles/credentials, and library check-out/check-in helpers are implemented.

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
- `0.8.0`: leader status, HA status, key status, OpenAPI discovery, JSON
  metrics, host diagnostics, CORS configuration, runtime logger read/set/reset,
  installed version history, namespace management, rate-limit quota management,
  remount/mount-migration start/status, active-node step-down, and locked-user
  list/filter/unlock helpers are implemented. Integrated Storage Raft
  join/configuration/peer mutation/bootstrap helpers and Autopilot JSON helpers
  are implemented. Binary Raft snapshots, raw storage, and broader diagnostic
  endpoints remain planned until the crate has an explicit raw-body transport
  API.

## OpenBao-Specific Notes

The official `2.5.x` HTTP API documentation states:

- all API routes are prefixed with `/v1`;
- TLS with certificate verification is expected;
- tokens are documented through `X-Vault-Token` or `Authorization: Bearer`;
- `X-Vault-Request: true` is used by the official SDK/CLI behavior;
- path parameters must not end in periods;
- applications should accept both `200` and `204` where applicable;
- KV v2 patch operations use `application/merge-patch+json`;
- errors commonly use `{"errors": [...]}` for status codes `>= 400`.

The crate follows those documented behaviors by default.
