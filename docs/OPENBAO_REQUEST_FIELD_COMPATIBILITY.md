# OpenBao Request-Field Compatibility

The typed client validates caller-selected fields whose availability changes
across the 23 immutable OpenBao profiles from `2.0.0` through `2.6.1`.
Validation uses the selected compatibility profile and runs before a
secret-bearing payload is constructed or serialized. An unavailable selected
field returns `Error::UnsupportedOpenBaoRequestField` containing only a stable
endpoint identifier, public field name, and exact profile version.

Unset optional fields are not rejected and retain their existing
`skip_serializing_if` behavior. The client does not silently remove a selected
field to make a request appear compatible.

## Reviewed Availability Rules

| Endpoint | Public field | First profile | Last profile |
| --- | --- | --- | --- |
| `auth.jwt.config` | `skip_jwks_validation` | `2.3.1` | `-` |
| `auth.jwt.config` | `override_allowed_server_names` | `2.4.0` | `-` |
| `auth.jwt.config` | `provider_config.kubernetes` | `2.6.0` | `-` |
| `auth.jwt.role` | `callback_mode` | `2.1.0` | `-` |
| `auth.jwt.role` | `poll_interval` | `2.1.0` | `-` |
| `auth.jwt.role` | `token_policies_template_claims` | `2.1.0` | `-` |
| `auth.jwt.role` | `oidc_disable_confirmation` | `2.5.2` | `-` |
| `auth.userpass.user` | `password_hash` | `2.6.0` | `-` |
| `auth.userpass.password` | `password_hash` | `2.6.0` | `-` |
| `auth.kerberos.config` | `decode_pac` | `2.6.0` | `-` |
| `identity.oidc.provider.token` | `scope` | `2.5.0` | `-` |
| `ssh.role` | `allow_empty_principals` | `2.0.2` | `-` |
| `ssh.role` | `issuer_ref` | `2.3.1` | `-` |
| `ssh.role` | `allow_commas_in_identity_templates` | `2.6.0` | `-` |
| `sys.policy.write` | `expiration` | `2.3.1` | `-` |
| `sys.policy.write` | `ttl` | `2.3.1` | `-` |
| `sys.policy.write` | `cas` | `2.3.1` | `-` |
| `sys.policy.write` | `cas_required` | `2.3.1` | `-` |
| `sys.policy.write` | `allow_slashes_in_identity_templates` | `2.6.0` | `-` |
| `sys.policy.write` | `allow_wildcards_in_identity_templates` | `2.6.0` | `-` |
| `sys.policy.patch` | `policy` | `2.6.1` | `-` |
| `sys.policy.patch` | `expiration` | `2.6.1` | `-` |
| `sys.policy.patch` | `ttl` | `2.6.1` | `-` |
| `sys.policy.patch` | `cas` | `2.6.1` | `-` |
| `sys.policy.patch` | `cas_required` | `2.6.1` | `-` |
| `sys.policy.patch` | `allow_slashes_in_identity_templates` | `2.6.1` | `-` |
| `sys.policy.patch` | `allow_wildcards_in_identity_templates` | `2.6.1` | `-` |
| `sys.init` | `stored_shares` | `2.0.0` | `2.5.5` |
| `sys.rekey` | `stored_shares` | `2.0.0` | `2.5.5` |
| `sys.config.cors` | `allow_credentials` | `2.6.0` | `-` |
| `sys.namespaces.create` | `seal` | `2.6.0` | `-` |
| `sys.storage.raft.join` | `non_voter` | `2.2.0` | `-` |
| `sys.rotate.config` | `interval` | `2.4.0` | `-` |
| `sys.plugins.catalog.register` | `oci` | `2.5.0` | `-` |
| `transit.datakey` | `associated_data` | `2.5.0` | `-` |
| `pki.authority.generate` | `not_before` | `2.1.0` | `-` |
| `pki.sign_verbatim` | `not_before` | `2.1.0` | `-` |
| `pki.role` | `not_before` | `2.1.0` | `-` |
| `pki.role` | `not_before_bound` | `2.3.1` | `-` |
| `pki.role` | `not_after_bound` | `2.3.1` | `-` |
| `pki.role` | `allowed_ip_sans_cidr` | `2.5.0` | `-` |
| `pki.role` | `allow_globs_in_identity_templates` | `2.6.0` | `-` |
| `pki.tidy` | `tidy_invalid_certs` | `2.1.0` | `-` |
| `pki.tidy` | `page_size` | `2.2.0` | `-` |
| `pki.config.auto_tidy` | `tidy_invalid_certs` | `2.1.0` | `-` |
| `pki.config.auto_tidy` | `revoked_safety_buffer` | `2.1.0` | `-` |
| `pki.config.auto_tidy` | `page_size` | `2.2.0` | `-` |

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
- JWT `provider_config.kubernetes` is available from `2.6.0`. The typed
  constructor rejects OIDC discovery, JWKS, and static validation-key sources
  because the runtime Kubernetes provider derives its only key source from
  the pod service-account environment.
- Userpass `password_hash` is accepted from `2.6.0`. Typed helpers require a
  validated, redacted bcrypt value with cost 5 through 12 and never serialize
  it together with plaintext `password`.
- `KerberosAuthAdmin::configure_with_decode_pac` is rejected before `2.6.0`;
  `configure` preserves the historical request body.
- SSH `issuer_ref` changes which CA signs certificates in a multi-issuer
  mount. Omitting it preserves the server's default-issuer behavior.
- ACL `cas`, `cas_required`, `expiration`, and `ttl` are policy lifecycle and
  concurrency controls. `expiration` and `ttl` remain mutually exclusive.
  Policy PATCH is available only from `2.6.1` and preserves omitted fields.
- OpenBao 2.6 ACL template overrides permit `/`, `*`, or `+` in rendered
  identity metadata; PKI permits `*` in templated allowed domains and URI SANs;
  SSH permits `,` in templated users and domains. ACL policy writes and
  `2.6.1` patches both require the same acknowledgement. Each can expand the resource
  selected by untrusted metadata. Typed writes require the non-default
  `identity-template-overrides-acknowledged` feature and an explicit marker.
  Ordinary request serialization cannot emit these flags. Bootstrap preview
  reports enabled flags as drift, but apply returns
  `Error::UnsafeBootstrapConfiguration` before replacing partial ACL, PKI, or
  SSH configuration; disable the flag with a state-preserving operation first.
- Plugin `oci` changes plugin execution mode. It is never omitted as a
  compatibility fallback.
- System `stored_shares` is retained for old profiles but is rejected for
  `2.6.0`, where OpenBao removed and ignores it. The client never silently
  sends an ineffective operator-ceremony field.
- `Sys::write_cors_config_with_credentials` is rejected before `2.6.0`;
  `write_cors_config` preserves the older CORS request shape.
- Sealable namespace creation is rejected before `2.6.0`. The typed helper
  always sends a validated Shamir `seal` document and never silently creates
  an ordinary namespace when the selected profile lacks namespace sealing.

## Boundary

This guarantee applies to typed helpers that expose the fields above. Public
raw transports and deployment-specific external plugin JSON cannot be
validated against OpenBao's core request schemas and remain behind the
`raw-api` acknowledgement boundary.
