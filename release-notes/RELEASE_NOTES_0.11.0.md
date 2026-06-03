# openbao 0.11.0 Release Notes

Status: in development.

Readiness: implementation complete locally and local release gates pass; wait
for external pentest and CI validation before tagging.

## Summary

`0.11.0` is the Transit advanced key-management line. It focuses on BYOK/import
endpoint wrappers, reversible Transit key soft deletion, global/cache
configuration, and certificate/CSR helpers while keeping raw key material out of
the default endpoint wrappers.

## Added

- Transit wrapping-key helper for reading the RSA BYOK wrapping public key PEM.
- Transit import and import-version request types that accept pre-wrapped BYOK
  ciphertext as `SecretString`, reject empty ciphertext constructors, and redact
  ciphertext/context fields from `Debug`.
- Public-key-only Transit import and import-version constructors for imported
  verification/encryption keys that do not carry private key material.
- Optional `transit-import` software wrapping helper that follows OpenBao's
  documented AES-KWP/RSA-OAEP flow and returns the import ciphertext as
  `SecretString`.
- Transit BYOK export helper that returns destination-wrapped ciphertext blobs
  as redacted `SecretString` values.
- Transit soft-delete and soft-delete-restore helpers.
- Transit global key configuration and cache configuration helpers.
- Transit CSR generation and certificate-chain install helpers.

## Security Notes

- Raw key bytes must not be passed to the endpoint wrappers. Callers fetch the
  wrapping key, wrap key material externally through an HSM, OpenSSL, or a
  reviewed crypto library, and pass only the base64 BYOK ciphertext blob.
- The `transit-import` helper is non-default and software-only. It is an
  ergonomic helper for audited development and automation use; it is not an
  OpenBao, HSM, FIPS, certification, or post-quantum security claim.
- BYOK export blobs are ciphertext, but the crate treats them as secret-aware
  values because leakage may enable unintended import workflows.
- PEM CSRs and certificate chains are documented as public certificate material;
  private key material remains inside Transit.
