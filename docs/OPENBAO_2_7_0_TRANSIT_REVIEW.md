# OpenBao 2.7.0 Transit Review

Status: checkpoint 05a implements additive request/response APIs and offline/mock
regressions. Checkpoint 05b live cryptographic evidence is still required. This
document is not a claim of routable or verified OpenBao 2.7 SDK support.

## Reviewed Contract

Source baseline: OpenBao tag v2.7.0, commit
`ca305a02daa68b203325daa1b25c18d7a252d4b3`, specifically
`internal/builtin/logical/transit/path_keys.go`, `path_import.go`,
`path_rotate.go`, `path_export.go`, `path_sign_verify.go`,
`sdk/helper/keysutil/policy.go` and the tagged Transit API documentation.
The staging inventory and runtime OpenAPI remain unchanged.

- ML-DSA-44, ML-DSA-65 and ML-DSA-87 are distinct key types. They do not
  support derivation or convergent encryption. Creating them is not an assertion
  of ML-DSA TLS negotiation or a local cryptographic implementation.
- `external-key` creation and rotation reference `<config>:<key>` in the
  registry. Each component, and each new API's Transit key name, must match the
  bounded ASCII generic-name grammar. Grants and remote provider availability
  are separate requirements. Rotation requires a new, granted mapping; it does
  not rotate the remote material. Do not change a mapping to a different key
  while old Transit versions still refer to it.
- External keys do not support import, export, derivation, convergence or
  automatic rotation. The optional `key_size` controls an auxiliary local HMAC
  key (32 through 512 bytes), not remote KMS key size. Generic read capability
  flags do not prove that a provider supports each cryptographic operation.
- ML-DSA imports accept PEM SubjectPublicKeyInfo or wrapped PKCS#8 private
  material. Raw private exports are ML-DSA seeds, not ready-to-import PKCS#8.
  The caller owns wrapping; SDK endpoint wrappers never accept raw private bytes.
  The server checks parameter-set matches and rejects further imported versions
  after server-side rotation. Import APIs cannot select `external-key`.
- Exports add `format`: default, raw, DER or PEM. The SDK retains the existing
  secret-aware export response and does not decode private exports into ordinary
  strings. Explicit versions are bounded positive integers; omission exports
  all versions, subject to server policy.
- `hash_algorithm=mldsa-mu` requires `prehashed=true` and exactly 64 decoded
  bytes. The SDK accepts canonical padded Base64 through `base64-ng`'s secret
  decoder, after checking the bounded encoded length. The caller must compute
  mu with the correct public-key/message binding. Verification of mu is explicitly
  rejected by the server: verify against the original message instead.
- Signing batch mode and key version are top-level request fields. They are
  not per-item controls. New batch APIs reject mixed modes or versions rather
  than silently ignoring them. Both batch APIs retain existing count limits
  and secret-aware bounded result types.
- Signing APIs do not perform extra metadata reads, which could require
  privileges absent from a sign-only token. Callers select the correct key;
  method names alone do not prove the server key is ML-DSA. The server enforces
  the requested cryptographic operation and provider capabilities.

## Additive API Design

Existing exhaustive `TransitKeyType`/`TransitHashAlgorithm` enums and public
request struct literals are unchanged. The new private-field request types are
`TransitMldsaCreateRequest`, `TransitMldsaImportRequest`,
`TransitExternalKeyCreateRequest`, `TransitMldsaSignRequest` and
`TransitMldsaVerifyRequest`. `TransitExternalKeyReference` validates registry
references; `MldsaParameterSet`, `TransitMldsaSignMode` and `TransitExportFormat`
are non-exhaustive option enums.

The new operations are `create_mldsa_key`, `create_external_key`,
`rotate_external_key`, `import_mldsa_key`, `import_mldsa_key_version`,
`export_key_with_format`, `sign_mldsa`, `verify_mldsa`, `batch_sign_mldsa` and
`batch_verify_mldsa`. They fail closed on every currently promoted profile,
including unselected/default compatibility and a 2.7 server using the explicitly
acknowledged 2.6.3 fallback. Registered dispatch remains mandatory after the
precheck; checkpoint 10 must wire and test all promoted field/route contracts.

`read_key_details` is also usable on older profiles: it sends the same registered
GET with no new request fields or request body. `TransitKeyDetails` handles
timestamp, asymmetric object and external-reference version records, with a
bounded, duplicate-key-rejecting map. It includes `latest_version`,
`min_available_version`, `auto_rotate_period`, `imported_key`,
`imported_key_allow_rotation`, and `soft_deleted` without changing
`TransitKeyInfo`'s public struct shape. Existing `rotate_key`, version import,
encrypt/decrypt, rewrap, HMAC, backup and certificate operations remain separate;
only provider-supported operations can succeed on an external key.

The `transit` feature now enables the existing optional `base64-ng` dependency
even without `transit-bytes`, to validate external mu. No new dependency version
or crypto implementation is introduced. Sensitive request fields are borrowed
only during serialization into the existing sanitizing transport. Response
parser and HTTP/TLS residuals in SECURITY.md still apply.

## Verification And Remaining 05b Work

05a tests cover every parameter-set spelling; create defaults; external-name
injection and size boundaries; auxiliary HMAC bounds; secret serialization and
Debug redaction; malformed/incorrect-size mu; explicit version bounds; exact
batch limits and mixed controls; response shapes, duplicate fields and map
overflow; export format spellings; old/default/newer-fallback rejection for all
new operations; and real mock dispatch of the additive read on an older profile.
Minimal Transit-only builds must also pass, without relying on Identity or
operator features to enable Base64 support.

05b must retain signed-image, input-bound TLS server evidence for:

- All three parameter sets: create/read, sign/verify, rotation and explicit
  older-version signing, valid-format tampering, wrong-message rejection and
  empty-message behavior.
- Caller-computed mu signing and verification against the original message;
  short/long mu, wrong prehashed flags and direct mu verification rejection.
- Batch positive/mixed-result behavior with top-level controls and correct
  ordering, not merely an HTTP success status.
- Public-only PEM import, parameter mismatch, version import and refusal after
  server rotation. Private wrapped PKCS#8 import must be tested separately from
  public-only imports; raw/DER/PEM export formats need round-trip assertions.
- External reference creation/rotation, allowed and denied grants, old-version
  access, provider-dependent encryption/signing/verification and unsupported
  export/import/derivation/auto-rotation. Transit-provider evidence is not an HSM
  or PKCS#11 guarantee.

Any source/runtime discrepancy must be resolved before marking checkpoint 05
complete. Public SDK positive dispatch and the complete historical/mixed-profile
matrix remain required at checkpoint 10; no fixture may bypass production
compatibility checks to claim SDK support early.
