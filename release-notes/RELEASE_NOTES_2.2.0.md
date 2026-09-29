# openbao 2.2.0

Version: 2.2.0
Status: unreleased; checkpoint 10 pentest and exact-commit GitHub checks pending

## OpenBao 2.7.0

This release adds the reviewed 2.7.0 compatibility profile while preserving all
25 historical profiles through 2.6.3. The generated Rust inventory contains
707 operation identities across 26 profiles. The historical contract matrix
remains separately anchored; it is not regenerated from current server docs.

- External-key config, key and mount-grant administration, including bounded
  provider options, merge patches and explicit verification acknowledgements.
- Transit ML-DSA-44/65/87 and external-key operations, key metadata, import/export,
  rotation, message and external-mu signing/verification, and batch controls.
- PKI ML-DSA and KMS generation, issuance and signing options, authority lifecycle
  helpers and RSA-PSS controls, without changing existing optional defaults.
- Control-group review, authorization, policy-builder support and explicit
  deferred execution. No automatic approval or replay is introduced.
- Opt-in consistency contexts with bounded, secret-aware indices, explicit
  await/fail/forward policies, namespace/cluster scoping and no automatic retry.
- Reviewed workflow CAS and plugin latest-version controls, plus corrected
  internal inspection routing and strict grouped rotation-backup decoding.

## Migration

Clients without a compatibility policy retain the unverified 2.6.3 contract.
Select exact 2.7 or strict automatic detection to use new 2.7 controls.
Assumed profiles are not verified; workflow CAS and consistency require stricter
verified policies and reject rolling ranges and unknown-newer fallback.

Additional pentest hardening changes the unstable request-inspection return type
to `InternalRequestInspection`. Use `with_json_bytes` for explicit access to the
complete response envelope; it is no longer an ordinary `JsonValue` data object.
The new type has redacted diagnostics and bounded sanitizing storage.

Two other hardening changes affect existing callers:

- A wrapped-response handle permits only one unwrap attempt, including after
  cancellation or an error. Do not treat an unknown outcome as safe to replay.
- Secret-bearing PKI generation and issuance reject `pem_bundle`, which can put
  private keys into public certificate/CSR fields. Use `pem` or `der` for those
  requests; public-only bundle output is unaffected.

See the [migration guide](../docs/MIGRATION_GUIDE.md) and
[version-selection guide](../docs/OPENBAO_VERSION_SELECTION.md).

## Explicit Limits

LDAP auth/secrets, Kerberos and RADIUS are excluded on 2.7 until external plugin
artifacts are separately verified. Their older built-in profiles remain usable.
Workflow prefix listing remains security-blocked.

The known upstream OpenBao 2.7.0 control-group replay defect remains recorded.
The SDK's one-attempt guard is local; it does not establish server-wide token
consumption or fix the upstream defect.

Evidence does not certify PKCS#11 hardware, FIPS status, complete process-memory
erasure, PGP share decryption, or unreviewed external services. Consistency
preflight cannot prevent a load balancer from switching clusters afterward.
The existing [security model](../docs/SECURITY_MODEL.md) continues to apply.

## Verification

The checkpoint 10 pentest follow-up changes Rust sources and SDK runners.
All twelve affected live reports have been recaptured and validated. Sealed binary
execution is not signed source-to-binary provenance; local build inputs and the
invoking user remain trusted. The full local check suite also passed after
the refresh. Retest and exact-commit GitHub checks are still required.

The full local `scripts/checks.sh` passed, including MSRV 1.90.0, strict Clippy,
Rust tests and doctests, historical contracts, packaging, dependency policy,
fresh RustSec audits and Kani. Rust 1.98.1 remains the primary toolchain.

Source-bound live reports cover TLS, external keys, Transit/PKI cryptography,
control groups, workflow CAS, MFA, backup reads/upgrades and coordinated
consistency lag/cancellation/isolation. Exact-profile normal-build SDK backup
evidence is distinct from disposable candidate evidence. Reports retain their
individual scopes; this is not a claim of live execution of every endpoint.

The package checked at 493,052 bytes, below the 512 KiB limit. Checkpoint history,
reviewed discrepancies and evidence details remain in the
[onboarding plan](../docs/OPENBAO_2_7_0_PLAN.md). Do not tag or publish before the
checkpoint 10 pentest and exact-commit GitHub checks complete.
