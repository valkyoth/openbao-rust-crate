# openbao 0.11.0 Release Notes

Status: in development.

Readiness: implementation started locally; wait for external pentest and CI
validation before tagging.

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
- Transit BYOK export helper that returns destination-wrapped ciphertext blobs
  as redacted `SecretString` values.
- Transit soft-delete and soft-delete-restore helpers.
- Transit global key configuration and cache configuration helpers.
- Transit CSR generation and certificate-chain install helpers.

## Security Notes

- Raw key bytes must not be passed to the endpoint wrappers. Callers fetch the
  wrapping key, wrap key material externally through an HSM, OpenSSL, or a
  reviewed crypto library, and pass only the base64 BYOK ciphertext blob.
- BYOK export blobs are ciphertext, but the crate treats them as secret-aware
  values because leakage may enable unintended import workflows.
- PEM CSRs and certificate chains are documented as public certificate material;
  private key material remains inside Transit.

## Known Work

- The optional `transit-import` client-side wrapping helper is still pending.
  It will require a separate feature-gated dependency and security review.
