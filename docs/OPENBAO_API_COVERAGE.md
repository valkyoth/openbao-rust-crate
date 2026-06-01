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

## Foundation

- Client config and TLS policy.
- Token and bearer authentication header strategies.
- Namespace header support.
- Response wrapping headers.
- Raw JSON request layer.
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
- Planned posture helpers:
  best-effort FIPS profile validation for crate-controlled choices and a
  future quantum-readiness profile once OpenBao exposes stable primitives.

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
- `0.8.0`: LDAP, RADIUS, and Kerberos.

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
- `0.6.0`: idempotent admin bootstrap builder is implemented for KV v2 mounts,
  Transit mounts, Transit keys, ACL policies, KV v2 string secret values, and
  explicit scoped service-token issuance.
- `0.7.0`: admin bootstrap now supports auth method enablement, AppRole role
  convergence, and explicit AppRole SecretID issuance.
- `0.6.0`: production init, unseal, seal, legacy rekey, OpenBao key-share
  rotation, and keyring rotation are implemented only behind explicit
  `operator-ops` plus `operator-ops-acknowledged` feature gates.
- `0.8.0`: metrics, quotas, namespaces, storage, diagnostic endpoints.

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
