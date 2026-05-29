# OpenBao API Coverage Plan

Checked against official OpenBao `2.5.x` documentation on 2026-05-28.

Sources:

- OpenBao HTTP API: https://openbao.org/api-docs/
- Secret engines: https://openbao.org/api-docs/secret/
- Auth methods: https://openbao.org/api-docs/auth/
- System backend: https://openbao.org/api-docs/system/
- KV v2: https://openbao.org/api-docs/secret/kv/kv-v2/
- AppRole: https://openbao.org/api-docs/auth/approle/
- Transit: https://openbao.org/api-docs/secret/transit/

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
- Planned downstream ergonomics from Mjolni/Pawalyze review:
  KV v2 service config loading, byte-oriented Transit helpers, JWT/JWKS
  Transit helpers, idempotent admin bootstrap, and ACL policy builders.
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
- `0.4.0`: Kubernetes login/config/role helpers are implemented; TLS
  certificate auth remains planned.
- `0.5.0`: JWT/OIDC and userpass.
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
- `0.3.0`: Transit key create/read/list/delete, encrypt, decrypt, rewrap,
  data key, random, hash, HMAC, sign, and verify are implemented.
- `0.4.0`: PKI.
- `0.5.0`: database dynamic credentials.
- `0.6.0`: SSH and TOTP.
- `0.7.0`: Kubernetes, LDAP, RabbitMQ, cubbyhole, identity.

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
- `0.6.0`: production init, unseal, rekey, rotate with strong safety
  documentation.
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
