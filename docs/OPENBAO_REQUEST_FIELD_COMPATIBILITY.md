# OpenBao Request-Field Compatibility

The typed client validates caller-selected fields whose availability changes
across the 21 immutable OpenBao profiles from `2.0.0` through `2.5.5`.
Validation uses the selected compatibility profile and runs before a
secret-bearing payload is constructed or serialized. An unavailable selected
field returns `Error::UnsupportedOpenBaoRequestField` containing only a stable
endpoint identifier, public field name, and exact profile version.

Unset optional fields are not rejected and retain their existing
`skip_serializing_if` behavior. The client does not silently remove a selected
field to make a request appear compatible.

## Reviewed Introduction Rules

| Endpoint | Public field | First profile |
| --- | --- | --- |
| `auth.jwt.config` | `skip_jwks_validation` | `2.3.1` |
| `auth.jwt.config` | `override_allowed_server_names` | `2.4.0` |
| `auth.jwt.role` | `callback_mode` | `2.1.0` |
| `auth.jwt.role` | `poll_interval` | `2.1.0` |
| `auth.jwt.role` | `token_policies_template_claims` | `2.1.0` |
| `auth.jwt.role` | `oidc_disable_confirmation` | `2.5.2` |
| `identity.oidc.provider.token` | `scope` | `2.5.0` |
| `ssh.role` | `allow_empty_principals` | `2.0.2` |
| `ssh.role` | `issuer_ref` | `2.3.1` |
| `sys.policy.write` | `expiration` | `2.3.1` |
| `sys.policy.write` | `ttl` | `2.3.1` |
| `sys.policy.write` | `cas` | `2.3.1` |
| `sys.policy.write` | `cas_required` | `2.3.1` |
| `sys.storage.raft.join` | `non_voter` | `2.2.0` |
| `sys.rotate.config` | `interval` | `2.4.0` |
| `sys.plugins.catalog.register` | `oci` | `2.5.0` |
| `transit.datakey` | `associated_data` | `2.5.0` |
| `pki.authority.generate` | `not_before` | `2.1.0` |
| `pki.sign_verbatim` | `not_before` | `2.1.0` |
| `pki.role` | `not_before` | `2.1.0` |
| `pki.role` | `not_before_bound` | `2.3.1` |
| `pki.role` | `not_after_bound` | `2.3.1` |
| `pki.role` | `allowed_ip_sans_cidr` | `2.5.0` |
| `pki.tidy` | `tidy_invalid_certs` | `2.1.0` |
| `pki.tidy` | `page_size` | `2.2.0` |
| `pki.config.auto_tidy` | `tidy_invalid_certs` | `2.1.0` |
| `pki.config.auto_tidy` | `revoked_safety_buffer` | `2.1.0` |
| `pki.config.auto_tidy` | `page_size` | `2.2.0` |

These boundaries come from the locked tagged documentation and normalized
OpenAPI snapshots in `compat/api-snapshots/`, with adjacent-release changes
recorded in `compat/api-diffs/`. OpenAPI-only schema churn is not accepted as
proof when tagged documentation or live behavior contradicts it.

## Same-Name Semantic Notes

- PKI `not_before` is an absolute timestamp. It does not replace
  `not_before_duration`, which remains a relative backdating/skew control.
- PKI role `not_before_bound` and `not_after_bound` constrain caller-selected
  certificate times; they are not aliases for the role's ordinary
  `not_before` or `not_after` values.
- Transit `associated_data` participates in AEAD authentication and must match
  when the resulting key material is consumed. It is not metadata that can be
  dropped for an older server.
- JWT `skip_jwks_validation` changes save-time validation behavior. Selecting
  it on a profile that predates the field fails locally rather than silently
  restoring strict validation or sending an ignored security option.
- SSH `issuer_ref` changes which CA signs certificates in a multi-issuer
  mount. Omitting it preserves the server's default-issuer behavior.
- ACL `cas`, `cas_required`, `expiration`, and `ttl` are policy lifecycle and
  concurrency controls. `expiration` and `ttl` remain mutually exclusive.
- Plugin `oci` changes plugin execution mode. It is never omitted as a
  compatibility fallback.

## Boundary

This guarantee applies to typed helpers that expose the fields above. Public
raw transports and deployment-specific external plugin JSON cannot be
validated against OpenBao's core request schemas and remain behind the
`raw-api` acknowledgement boundary.
