# OpenBao Rust SDK 0.14.0 Release Notes

## Version

- Version: 0.14.0
- Status: in development
- Git tag: pending
- Git commit: pending
- License: MIT OR Apache-2.0

## Summary

`0.14.0` is the system backend completion line. It adds operator-gated
generate-root, generate-recovery-token, decode-token, legacy recovery-key
rekey, and in-flight request inspection helpers, plus ungated password policy
and resultant ACL helpers.

## Added

- Started the `0.14.0` release line.
- Added generate-root, generate-recovery-token, decode-token, and legacy
  recovery-key rekey helpers behind `operator-ops` plus
  `operator-ops-acknowledged`.
- Added password policy list/read/write/delete/generate helpers without a
  feature gate. Generated passwords return `SecretString`.
- Added resultant ACL inspection without a feature gate, with a documented
  internal-endpoint stability caveat and conservative capability maps.
- Added in-flight request inspection as a typed operator-gated diagnostic
  helper with `SecretString` token accessors and bounded response maps.
- Added the new system request/response types to the prelude where appropriate,
  with operator ceremony types still gated by `operator-ops`.
- Kept sys/config/ui, sys/monitor streaming, internal router inspection,
  internal counters, and internal request inspection rejected for stable scope.
- Regenerated the OpenBao `2.5.x` endpoint matrix. It now records `643`
  documented rows, `597/643` strict typed or operator-gated coverage, and zero
  `planned` or `decision` rows.

## Security Notes

- Operator ceremony helpers must stay behind `operator-ops` plus
  `operator-ops-acknowledged`.
- Root tokens, recovery tokens, OTP values, encoded tokens, key shares,
  generated passwords, and token accessors must be stored as `SecretString`
  and redacted from `Debug`.
- Internal endpoints that are kept for practical automation must carry explicit
  stability caveats.
- Pentest follow-up hardened retry jitter conversion, CORS origin validation,
  lease count query validation, Raft snapshot request bounds, and Raft peer path
  construction. The local `PENTEST.md` report was deleted before commit.
- Transit import software wrapping docs now call out the OpenSSL-managed heap
  residual for the ephemeral AES key; HSM or audited-boundary wrapping remains
  the recommended path for high-assurance deployments.
- Second pentest follow-up redacted optional tracing span paths, removed JSON
  decode categories from user-facing errors, tightened RADIUS host validation,
  and added post-write verification for non-CAS bootstrap convergence paths.
  The local second `PENTEST.md` report was deleted before commit.
- Third pentest follow-up sanitizes OpenBao response warnings before exposing
  them to callers, moves retry jitter to direct OS randomness, adds
  acknowledgment gates for `transit-import` and `sensitive-http-test-only`, and
  strengthens documentation for TLS revocation limits, RADIUS suitability,
  tracing path-shape metadata, Transit request-body residuals, and BYOK
  software wrapping residuals. The local third `PENTEST.md` report was deleted
  before commit.

## Security And Stability Gate

- Release gate script: `scripts/release_0_14_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag `v0.14.0` until local validation, external pentest feedback, and
  GitHub CI are green.
