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

## Security And Stability Gate

- Release gate script: `scripts/release_0_14_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag `v0.14.0` until local validation, external pentest feedback, and
  GitHub CI are green.
