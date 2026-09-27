# OpenBao 2.7.0 PKI Review

Status: checkpoints 06a through 06d add typed ML-DSA selection, KMS generation,
role/authority signature options, issuance options and profile guards.
Checkpoint 06e retains passing signed-image TLS certificate evidence. Checkpoint
06 implementation is ready for pentest; successful SDK dispatch remains a
checkpoint 10 promotion requirement.
OpenBao 2.7 routing is not promoted.

Pentest follow-up: the shared bounded subprocess runner now explicitly closes
its stdout pipe on successful, failed and interrupted execution, including
selector setup errors, and reaps failed children. Real subprocess regression
tests retain exception tracebacks to prove cleanup does not depend on garbage
collection. The PKI crypto tests no longer emit unclosed-pipe ResourceWarnings.
The four 2.7 TLS evidence reports require recapture for this changed harness;
their previous input hashes are not rewritten as if they were new runs.

## Source Contract

Reviewed tagged source: `ca305a02daa68b203325daa1b25c18d7a252d4b3`, including
`website/content/docs/api/secret/pki.mdx`, `internal/builtin/logical/pki/fields.go`,
`ca_util.go`, `path_root.go`, `path_intermediate.go`, `path_manage_keys.go`,
`path_roles.go`, `path_ocsp.go`, and `sdk/helper/certutil/helpers.go`.

- PKI spells the key type `mldsa` and selects 44, 65 or 87 through `key_bits`.
  This differs from Transit's `mldsa-44`/`mldsa-65`/`mldsa-87` wire types.
  Missing/zero `key_bits` selects the server default, 44.
- Root, root rotation, intermediate CSR, standalone key and role operations
  need this algorithm selection. Issuance overrides for roles permitting any
  algorithm need additive request options because the existing issue struct
  does not expose those fields.
- `kms` is a generation path component, not a private key algorithm. It requires
  an `external_key_ref`; the source rejects that field for non-KMS generation.
  Existing-key reuse uses `key_ref`, a different namespace and contract. A grant
  and provider support are required independently from path/schema acceptance.
- Tagged `use_pss` field definitions default to false. Omitted and explicitly
  false must remain distinguishable in PATCH/options payloads. Certificate/CSR
  behavior must be checked live; schema defaults alone are insufficient evidence.
- OCSP uses the external Go OCSP implementation. The tagged server explicitly
  maps RSA-PSS revocation algorithms to PKCS#1 v1.5 for OCSP. Do not infer ML-DSA
  OCSP support from certificate generation or signing support.
- ML-DSA certificate issuance does not imply rustls/native-TLS acceptance of
  those certificates for the SDK's transport.

## 06a Implementation

`PkiMldsaParameterSet` and additive `with_mldsa` methods on
`PkiGenerateRootRequest`, `PkiGenerateIntermediateRequest`,
`PkiGenerateKeyRequest` and `PkiRole` select both wire fields explicitly. Existing
public struct literals and exhaustive generation enums remain unchanged. The
parameter-set type lives under PKI and does not require the Transit feature.

All six existing generation paths validate ML-DSA parameters and require a
selected profile of at least 2.7.0 before sending. The same validation covers
role write/PATCH and both identity-template override variants. Direct public-field
assignment is checked too; callers cannot bypass the guard by avoiding the
builders. ASCII case variants are conservatively gated, without normalizing
them into server-supported spellings. Classical algorithms retain existing
behavior and do not acquire an extra preflight request.

The field guard uses the existing compatibility selection mechanism, not the
detected server version alone. Every active profile, unselected compatibility,
and the acknowledged unknown-newer fallback remain blocked. Eventual successful
dispatch must still pass the generated endpoint registry at checkpoint 10.

Tests cover all parameter sets, default/invalid parameter values, unchanged
unrelated fields and defaults, all existing generation modes/paths, role variants,
direct field mutation, all 25 historical profiles, and unknown-newer fallback.
The HTTP tests assert that no operation reaches the listener after the optional
unauthenticated health probe. Existing classical PKI HTTP regressions also remain
in the all-feature suite.

## 06b Implementation

Six additive `*_kms` methods cover root generation, multi-issuer root generation,
root rotation, intermediate and multi-issuer intermediate CSR generation, and
standalone key registration. They use the existing registered request path and
require a selected 2.7+ profile, without adding variants to the exhaustive
`PkiKeyGenerationType` or fields to existing public request structs.

`PkiExternalKeyReference` accepts separate registry config/key names. Each is
bounded to 256 ASCII bytes with the server generic-name grammar; path delimiters,
colons, percent encoding, controls and empty names are rejected. This reference
is metadata, not private key material. Provider availability, signing capability
and grants for the consuming mount remain server-enforced prerequisites.

Authority requests reject any `key_type`, `key_bits`, `key_ref` or
`private_key_format`, including explicit empty/zero values, before compatibility
probing. Standalone requests similarly reject key type/size, which that server
handler otherwise ignores for KMS. Existing `not_before` guards remain in place.
KMS is never an export mode. Standalone generation retains the returned reference
through additive `PkiGeneratedKeyDetails`; authority responses retain their
existing type because the tagged handlers do not return an external reference.
Unexpected private-key response fields still use secret-aware storage and
redacted diagnostics.

Tests cover reference boundaries and injection strings, exact payload fields,
each conflicting field individually, response parsing/redaction,
all six method gates across the 25 active profiles and unselected compatibility,
and rejection after an unauthenticated newer-server health probe. Positive SDK
dispatch remains blocked, and must be tested during checkpoint 10 promotion.
These tests are not a substitute for live provider/certificate evidence.

## Evidence And Promotion

1. Checkpoint 06e retains signed-image TLS evidence for ML-DSA certificate/CSR generation,
   issuance/signing, import/read response shapes, KMS grant denial and provider
   operations, RSA-PSS defaults/overrides, invalid trailing-dot names and
   unsupported ML-DSA OCSP behavior. OpenSSL verifies certificate/CSR signatures
   and exported-key matching, rather than accepting HTTP success alone.
2. Complete SDK positive dispatch and historical/mixed-profile checks during
   checkpoint 10 promotion. No source-only or Python fixture result substitutes
   for those production API checks.

## 06c Implementation

Tagged `path_roles.go`, `path_issue_sign.go`, `fields.go` and
`sdk/helper/certutil/helpers.go` distinguish subject-key selection from signer
preferences. Ordinary issue/sign operations inherit signature settings from the
role. They do not accept a per-request PSS override. CEL evaluates raw request
inputs and controls the final key/signature output, so its request settings are
inputs to policy, not guaranteed overrides. Self-issued signing does not expose
`use_pss`/`signature_bits`; no invented parameters were added to that endpoint.

`PkiSignatureOptions` preserves omission versus explicit false and zero. Digest
sizes are limited to 0/256/384/512. `PkiRoleSigningOptions` adds these fields to
role write/PATCH without changing existing public structs. Its optional template
glob override is private, has no deserialization path, and requires the existing
feature and typed acknowledgement. The implementation retains the versioned role
field guards and Merge Patch content type. `PkiRoleSigningDetails` adds optional
readback fields while retaining existing role and template metadata. Reads use
existing registered routes on older profiles, with missing values left absent.

`PkiIssuanceKey` validates RSA (0/2048/3072/4096/8192), EC
(0/224/256/384/521), Ed25519 and all three ML-DSA parameter sets. The tagged helper
allows RSA-8192 even though some endpoint descriptions list only up to 4096.
Ordinary and named-issuer issue helpers send key selection but not signature
overrides. A role with a specific key type ignores the selection; callers must
use an appropriate `any` role and inspect the resulting certificate as needed.
CEL issue/sign helpers send signature inputs, with optional issuance key selection.
CSR signing does not generate a new subject key.

All new write helpers conservatively require a selected 2.7+ profile, even for
classical algorithms or empty options. This is the reviewed additive contract,
not a claim that the individual fields never existed on older servers. Existing
public methods and their historical behavior remain unchanged. Tests cover all
25 active profiles, unselected and unknown-newer fallback, invalid paths before
health probing, omission/false/zero serialization, size/parameter sets, readback
and duplicate rejection. Compile-fail examples prevent generic deserialization
or direct construction of the template override. Historical mock reads and the
existing PKI HTTP regressions pass. Actual 2.7 write/PATCH dispatch and header
checks remain required at promotion; no live certificate result is claimed here.

## 06d Implementation

`PkiAuthorityKeySource` selects internal, exported, existing or KMS keys without
extending the old exhaustive enum. Five additive generation helpers cover root,
multi-issuer root, rotation, intermediate and multi-issuer intermediate routes,
reusing `PkiSignatureOptions`. Two intermediate-signing variants apply signature
preferences to the issuing CA, not to the CSR's public key. Sign-verbatim already
has the signature fields and remains operator-gated; no duplicate fields were added.

The new existing-key mode requires an explicit bounded, single-segment `key_ref`
(including `default` when intended), and rejects key type/size/export format.
Internal/exported generation rejects `key_ref`; KMS retains 06b's conflict checks.
Existing ML-DSA parameter and authority `not_before` guards remain in the request
path. New writes require the reviewed 2.7 profile even with default signature
options; neither older profiles nor unknown-newer fallback can send them.

`cross_sign_intermediate_csr` is the additive corrected model of
`intermediate/cross-sign`: it accepts intermediate-generation subject fields,
reuses an explicit existing key, and decodes `csr`/`key_id` without requiring a
certificate. It remains behind both operator feature gates. It does not sign an
input CSR, establish trust by itself, or export a key. The legacy helper's docs
call out its incompatible 2.7 response model; its public signature is unchanged.

Response review also identified a private-key handling issue beyond the new APIs:
exported `pem_bundle` puts private material into the ordinary `certificate`/`csr`
string as well as the secret-aware `private_key` field. Existing and new exported
authority helpers and ordinary issue helpers now reject that format before any
health probe or operation. Use `pem` or `der`; public-only bundle output remains
available. The tagged CEL handler constructs its certificate field separately and
does not use this bundle-format branch. These checks assume conforming server
responses; they do not make arbitrary hostile certificate text secret-aware.

Tests cover source conversion/validation, omitted/false/zero signature payloads,
CSR response shape and private-key Debug redaction, all authority write gates
across historical/unselected/fallback profiles, preflight conflict rejection, and
the exported-bundle restriction in both old and new methods. A minimal-feature
compile-fail doctest checks the cross-sign operator gate. Live cryptographic
verification was outstanding at 06d and is retained in 06e below. Successful
2.7 SDK dispatch remains outstanding until checkpoint 10.

## 06e Retained Evidence

`scripts/openbao_2_7_pki.py` adds a staged signed-image TLS fixture. It checks
ML-DSA-44/65/87 roots, CSRs, named-issuer issue/sign, key import/read and
existing-key cross-sign CSRs; RSA-PSS defaults and explicit settings; trailing-dot
rejection; and Transit-provider KMS signing with denied, removed and restored
mount grants. OCSP checks require the exact unsupported ML-DSA response and a
cryptographically verified successful RSA response, not just an arbitrary failure.

The trailing-dot assertion requires HTTP 400 and the exact IDNA invalid-label
error for the fixture name. Tagged `cert_util.go` performs CN-to-IDNA conversion
before role checks; its pinned `golang.org/x/net v0.58.0` rejects the final dot
with `VerifyDNSLength` under Unicode 16+. A generic role-policy denial is not
accepted as evidence of this dependency behavior.

The fixture provider policy grants read access to the exact
`pki-source/export/public-key/signer/latest` path used by the pinned Transit KMS
provider's `ExportPublic` implementation, in addition to key metadata and
sign/verify operations. Key metadata access alone is insufficient for PKI KMS
registration. Private signing-key export and mount administration remain denied;
the live fixture checks both denials with the restricted provider token.

The separate OpenSSL verifier checks actual signatures and exported-key/public-key
matching, with ambient trust disabled for certificate verification. Its local
tests accept valid signatures and reject tampering, wrong issuer keys and wrong
private keys. Run the complete local crypto suite with OpenSSL 3.5+:

```sh
python3 -B scripts/test_openbao_2_7_pki_crypto.py
```

Ordinary checks run the offline lifecycle tests and classical crypto checks;
the live fixture requires ML-DSA-capable OpenSSL and never silently skips it.
Run the disposable server fixture on the constrained rootful Podman host:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_pki.py
```

The passing result is retained at `compat/onboarding/2.7.0/pki-tls.json` and
checked by `scripts/verify_openbao_2_7_pki.py`. It is canonical, digest-pinned and
bound to all imported fixture inputs. Tests reject input drift, scope/coverage
changes, missing/extra fields and wrong scalar types. The evidence covers local
ML-DSA-44/65/87 authority, import, rotation and issuance flows; the live KMS
provider case uses ML-DSA-44 over Transit, not PKCS#11 or an HSM.

This is **server-fixture-only**, not SDK integration evidence. Checkpoint 06 is
ready for pentest, but this does not promote the 2.7 profile. Successful SDK
dispatch, aliases and historical/mixed-profile regressions remain mandatory at
checkpoint 10. Fixture scratch files are private
and wiped before removal; Python, OpenSSL, filesystem and OS copies are not a
guaranteed memory-erasure boundary. Only disposable fixture secrets are used.
