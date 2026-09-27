# OpenBao 2.7.0 PKI Review

Status: checkpoint 06a adds typed ML-DSA selection and existing-route profile
guards. Checkpoint 06 is not complete: additive KMS/PSS APIs, response details
and live certificate evidence remain required. OpenBao 2.7 routing is not promoted.

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

## Remaining Checkpoint 06

1. Add validated KMS references and generation options without extending the
   existing exhaustive enum or public struct shapes. Cover root/rotate,
   intermediate and standalone key paths and conflicting/ignored inputs.
2. Add PSS/signature and issuance algorithm options across affected role,
   issue/sign and authority methods, with additive response details where needed.
   Preserve merge-patch semantics and operator/template acknowledgement gates.
3. Retain signed-image TLS evidence for ML-DSA certificate/CSR generation,
   issuance/signing, import/read response shapes, KMS grant denial and provider
   operations, RSA-PSS defaults/overrides, invalid trailing-dot names and
   unsupported ML-DSA OCSP behavior. Verify certificates cryptographically;
   HTTP success or a returned PEM string is not sufficient.
4. Complete SDK positive dispatch and historical/mixed-profile checks during
   checkpoint 10 promotion. No source-only or Python fixture result substitutes
   for those production API checks.
