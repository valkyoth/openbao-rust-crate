# OpenBao 2.7 External-Key Administration

Status: checkpoint 04a provider schemas implemented; checkpoint 04 incomplete.
No new route is enabled and OpenBao 2.7.0 remains unpromoted.

## Contracts Reviewed

Reviewed against the immutable `v2.7.0` source checkout at
`ca305a02daa68b203325daa1b25c18d7a252d4b3`, not the moving latest API:

- [System handlers](https://github.com/openbao/openbao/blob/v2.7.0/internal/vault/logical_system_external_keys.go)
- [Administration API](https://github.com/openbao/openbao/blob/v2.7.0/website/content/docs/api/system/external-keys/index.mdx)
- [Transit provider](https://github.com/openbao/openbao/blob/v2.7.0/website/content/docs/api/system/external-keys/plugins/transit.mdx)
- [PKCS#11 provider](https://github.com/openbao/openbao/blob/v2.7.0/website/content/docs/api/system/external-keys/plugins/pkcs11.mdx)

Configs hold provider parameters; keys map to existing provider key material.
Deleting a mapping does not delete the remote KMS key. Deleting a config removes
all its mappings. Grants authorize mount **paths**, not mount identities, and
persist when a mount is disabled. Reusing a granted mount path can therefore
give a replacement mount access to the key.

Config and key POST replace provider options; PATCH performs JSON Merge Patch.
Explicit null deletes an option, while omission preserves it. `verify` defaults
to true, is per request and is not persisted. Config `plugin` is processed
separately from the provider-options merge. Grant changes bypass provider
verification in the server. Future wrappers must not conflate any of these.

## Implemented In 04a

The `sys::external_keys` provider schemas require `operator-ops` and the existing
`operator-ops-acknowledged` gate. Private fields and fallible constructors prevent
post-validation mutation. They serialize provider options only; the enclosing
config request's `plugin` and `verify` fields will be supplied by later wrappers.

- Transit config requires HTTPS without URL credentials, query or fragment.
  TLS verification is always on. Mount/namespace paths and TLS host overrides
  are validated. Token values are bounded, nonempty visible ASCII. Client TLS
  certificates and secret keys are supplied as a pair.
- Transit key mappings require one bounded key name and an explicit version in
  `1..=2147483647` for conservative signed-32-bit server interoperability.
  Prehashing remains enabled unless explicitly disabled.
- PKCS#11 config requires a registered library alias and at least one slot,
  serial or label selector. Slots serialize as decimal strings, including large
  u64 values; JSON-number precision cannot change a slot. Multiple selectors
  must all match. PINs use secret storage.
- PKCS#11 key mappings require at least a label or a nonempty hexadecimal ID.
  IDs preserve leading zero octets. Mechanism and OAEP hash enums encode the
  documented values. Software public-key encryption remains the server default;
  callers may explicitly disable it.
- Token, PIN and client private-key inputs use `SecretString`. Config Debug
  omits all values. Validation errors do not echo supplied values. Each provider
  text value is bounded to 64 KiB; key names/aliases to 256 bytes; binary key IDs
  to 2048 octets. Existing endpoint limits further bound URLs and paths.

Serialization intentionally exposes credentials to the selected serializer.
These types do not guarantee sanitization if a caller serializes them into an
ordinary String or JSON value. Their later HTTP wrappers must use the existing
sanitizing SDK transport and aggregate request-size limit. PEM syntax, matching
client certificate/key pairs, provider existence and remote key availability
are server validation responsibilities, not claims made by these schemas.

Transit delegation still transfers plaintext to another trusted server for
some operations. It does not provide an HSM boundary. PKCS#11 schemas do not
prove hardware custody, plugin installation or hardware execution. No PKCS#11
live test or certification is claimed here.

## Verification And Remaining Work

The new unit tests cover exact field names/defaults, secret serialization and
Debug redaction, invalid token/header/URL/path/SNI input, text-limit boundaries,
version boundaries, lossless large slot IDs, combined selectors, hexadecimal ID
validation and all documented mechanism/hash encodings.

Required before checkpoint 04 completion:

1. Bounded, secret-aware custom provider options and response decoding, including
   duplicate-key rejection and no credential echo in diagnostics.
2. Config/key/grant CRUD and LIST, PATCH omission versus null deletion, and an
   explicit acknowledgement when bypassing server provider verification.
3. Exact-profile rejection before credentials are serialized or transmitted;
   no route exposure through assumed/fallback profiles.
4. HTTP contract tests, aggregate request limits, credential-safe errors/tracing
   and live TLS tests demonstrating both permitted delegation and denied mounts.

Audit base for 04a: `61d88cf`. The staged TLS fixture retained for checkpoint 03
is unchanged; it does not count as a delegation test for checkpoint 04.

Checks run for 04a:

- All-feature library suite: 369 tests passed, including 11 provider tests.
- Default-feature library suite: 309 tests passed.
- Provider tests with only `rustls-tls,sys,operator-ops,operator-ops-acknowledged`:
  11 passed. Existing shared helpers emit dead-code warnings in this reduced
  test configuration; none originate in the provider module.
- Strict all-feature/all-target Clippy and Rust 1.90.0 all-target/all-feature
  compilation passed. Rustdoc with warnings denied passed.
- Formatting, release metadata, staged API verification, retained TLS evidence
  verification and the active 691-operation capability registry check passed.

This is focused checkpoint verification, not the final release gate. No live
delegation fixture or full release gate was run for this schema-only subcommit.
