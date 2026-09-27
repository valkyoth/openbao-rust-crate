# OpenBao 2.7 External-Key Administration

Status: checkpoint 04 complete for pentest review, including retained live evidence.
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

Implemented in 04b:

- Thirteen operator-gated config/key/grant methods: config and key read, write,
  patch, delete and paginated LIST; grant LIST, creation and deletion. Writes use
  POST (the documented PUT alias is not a separate SDK method), require 204 and
  use the existing sanitizing transport. PATCH sets the Merge Patch media type.
- `ExternalKeyOptions` retains JSON in `SecretVec`, capped at 256 KiB, eight
  container levels, 2048 value nodes, 64 object members and 64 KiB per decoded
  string. Every object rejects duplicate keys, including escaped equivalents.
  Top-level names are ASCII identifiers capped at 256 bytes. Reserved request
  fields cannot override path parameters, `plugin` or `verify`.
  Read parameter objects permit one additional root member for the server's
  `plugin` metadata, retaining all other limits.
- Custom options and all partial patches require
  `ExternalKeyCustomOptionsAcknowledgement::acknowledge_unvalidated_provider()`.
  This is a review marker, not a security sandbox. Custom options can disable
  provider TLS checks or otherwise bypass the typed Transit schema. Provider
  semantics are deliberately not inferred from arbitrary custom fields.
- Full requests verify by default. `verify=false` requires a separate
  `ExternalKeyVerificationBypass::acknowledge_deferred_validation()` value.
  Config patch plugin changes are separate from option null deletion.
- Provider reads keep unknown parameters in bounded sanitizing storage. The SDK
  does not trust plugins to redact correctly. Read responses cannot be passed
  directly into request builders; `(redacted)` credentials must not be replayed.
- Errors and Debug do not echo values. Parser scratch storage remains a
  dependency-owned memory residual; validation is not a claim of whole-process
  erasure. Top-level request option identifiers are non-secret metadata.
- All 13 methods reject all 25 older active profiles before endpoint transport.
  A detected 2.7 server with an acknowledged older fallback is also rejected.
  Dispatch still requires the generated registry; candidate operation promotion
  and successful public-SDK 2.7 transport remain checkpoint 10 work.

Retained live TLS result: permitted delegation, denied mounts, grant removal,
administration and cleanup passed. Reproduce with:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_external_keys.py
```

This fixture creates a constrained disposable server, delegates from one Transit
mount to another with a narrowly scoped provider token, checks CRUD/LIST/PATCH,
proves encryption/decryption succeeds only with the grant, and checks mapping
deletion leaves the original key intact. It verifies TLS 1.3 and TLS rejection,
resource limits and isolated networking using the unchanged checkpoint 03
helpers. No arbitrary existing deployment is targeted. A result is produced
only after cleanup and stable-input checks pass. Python/dependency-owned memory
is not promised erased. This is server-contract evidence, not a promoted SDK
profile or PKCS#11 hardware test.

Evidence: `compat/onboarding/2.7.0/external-key-tls.json`, SHA-256
`dee89246afdd1a3b30be28f7c68be3fc39043659f8ce96b5fc20d838c3931aa6`.
`scripts/verify_openbao_2_7_external_keys.py` checks its pinned hash, canonical
encoding, exact scope/checks and current fixture inputs. Tests reject altered
scope, missing checks, stale inputs and changed evidence bytes. This is retained
operator-executed evidence, not independent remote attestation.

The first live run passed config/key writes and patches, redaction, ungranted
mount denial, granted encryption/decryption and denial after grant removal. It
then exposed a missing-resource HTTP discrepancy: the tagged handlers construct
a coded 404, but `sdk/logical/response_util.go` replaces an error response with a
plain error in `RespondErrorCommon`, losing that code before HTTP adjustment.
The observed missing-key response was 400. The fixture now requires HTTP 400
**and the exact missing-key/config error**, rather than accepting arbitrary
failure as proof of deletion. SDK reads preserve this as an API error without
retaining the response body. A failed run is not retained as successful evidence.

Checkpoint 10 must register the documented operations without changing older
profile cells. In particular the grant `:mount-path` tail is multi-segment;
config and key names are single-segment. The SDK wrappers must continue through
registered dispatch after the minimum-profile precheck.

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
delegation fixture or full release gate was run for the schema-only 04a subcommit.

Audit base for 04b: `b4edeff`. The complete checkpoint audit begins at `61d88cf`.

04b verification includes 21 external-key unit tests, 13-method rejection across
all 25 active profiles, acknowledged-newer fallback rejection, nine offline
fixture/evidence tests and the successful rootful TLS run. The all-feature suite
passed with 379 library tests and 165 HTTP tests; all other enabled targets also
passed. MSRV 1.90.0 compilation, strict Clippy, strict rustdoc and unchanged
active-registry/retained checkpoint 03 evidence checks passed.
The complete `scripts/checks.sh` run finished with `checks: ok`, including
packaged-crate checks, dependency checks and Kani. This remains checkpoint
verification, not permission to publish the unfinished 2.2.0 release.
