# openbao 0.11.0 Release Notes

Status: in development.

Readiness: implementation complete locally and local release gates pass; wait
for external pentest and CI validation before tagging.

## Version

- Version: 0.11.0
- Release date: pending
- Git tag: pending
- Git commit: pending
- License: MIT OR Apache-2.0

## Summary

`0.11.0` is the Transit advanced key-management line. It focuses on BYOK/import
endpoint wrappers, reversible Transit key soft deletion, global/cache
configuration, and certificate/CSR helpers while keeping raw private or
symmetric key material out of the default endpoint wrappers.

Remaining `0.11.0` planned work: none. The local release-gate components and
the OpenBao `2.5.4` integration smoke test pass locally; this candidate is
waiting for external pentest feedback and GitHub CI validation before the
`v0.11.0` tag.

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

- Pentest feedback for this release line tightened retry, Transit, bootstrap,
  path-validation, and secret-encoding behavior before tagging.
- `Client::request_json_with_retry` now accepts `RetryableMethod` instead of
  arbitrary `reqwest::Method`, preventing accidental retries of non-idempotent
  OpenBao write operations.
- `AdminBootstrap` uses KV v2 CAS for secret-value convergence where OpenBao
  supports it, and the security policy now states that all bootstrap plans
  still require external serialization for ACL policies, AppRole settings, and
  other read-compare-write operations.
- OpenBao path validation rejects non-ASCII and percent characters to avoid
  visually ambiguous or percent-encoded path input.
- Transit BYOK export and normal export reject version `0` locally. BYOK export
  now takes `Option<u64>` for version selection.
- Transit sign responses expose returned public keys as public `String` data
  while keeping signatures secret-aware and redacted.
- TOTP SHA-1 remains available for legacy RFC 4226 compatibility but is
  deprecated; use SHA-256 or SHA-512 for new deployments.
- Base64 secret helpers now move the single exposed base64 allocation directly
  into `SecretString`, avoiding an unnecessary duplicate plaintext copy while
  relying on `SecretString` zeroization on drop.
- Retryable LIST request conversion no longer uses an impossible
  `unreachable!` panic path.
- Policy HCL string escaping removed the now-dead `%{` branch because policy
  path validation rejects percent characters before serialization.
- Raw private or symmetric key bytes must not be passed to the default endpoint
  wrappers. For private/symmetric imports, callers fetch the wrapping key, wrap
  key material externally through an HSM, OpenSSL, or a reviewed crypto
  library, and pass only the base64 BYOK ciphertext blob. Public-key-only import
  constructors carry public material.
- The `transit-import` helper is non-default and software-only. It is an
  ergonomic helper for audited development and automation use; it depends on an
  audited OpenSSL 1.1.1+ runtime baseline and is not an OpenBao, HSM, FIPS,
  certification, or post-quantum security claim.
- BYOK export blobs are ciphertext, but the crate treats them as secret-aware
  values because leakage may enable unintended import workflows.
- PEM CSRs and certificate chains are documented as public certificate material;
  private key material remains inside Transit.

## Security And Stability Gate

- Gate command: `OPENBAO_SKIP_INTEGRATION=1 scripts/release_0_11_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Local validation completed for dependency freshness, formatting, release
  metadata, clippy default/all-features, tests default/all-features, doctests,
  docs, package verification, dependency policy, RustSec audit, SBOM
  generation, and the pinned OpenBao `2.5.4` dev instance smoke test.
- Do not tag until external pentest feedback is reviewed and GitHub CI is
  green.
