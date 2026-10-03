# OpenBao Rust SDK 2.2.1

Version: 2.2.1
Status: Released as signed tag v2.2.1 on commit 68a4b12278c791e6718fdc132823e1f1a0959d60 after clean security retesting and green GitHub checks. Preparation notes below retain their historical context.

## Auth Security Corrections

LDAP/Kerberos mapping names now reject comma injection, empty/blank entries
and ASCII controls. LDAP, Kerberos and RADIUS use one checked encoder limited
to 4096 items and 1 MiB including separators, before allocating the wire string.
Empty lists still clear mappings, and valid ordering is preserved.

`OidcAuthUrlResponse::auth_url` and `user_code` now use `SecretString` and
`Option<SecretString>`, with redacted `Debug`. **This security correction is a
public source-compatibility change**: import `openbao::ExposeSecret` and expose
values only for the intended browser/user transfer, never for logging. See the
[migration guide](../docs/MIGRATION_GUIDE.md#from-openbao-220-to-221).
Dependency-owned Serde/HTTP/TLS scratch copies are not guaranteed erased.

Packaged security links now target this release's tag, with a metadata check
and mutation regressions preventing stale links. The tag must exist before
publication. Seven fresh SDK reports now cover the auth fixes: patch normal-build
reports are retained as `sdk-normal-tls-v3.json`, and the five affected 2.7.0
SDK reports as `-tls-v4.json`. Their predecessors remain unchanged and cannot
satisfy current-source gates. No source hashes are waived or rewritten.

Post-fix local verification passed: 657 all-feature Rust tests (18 deliberately
ignored live/external tests), 5 doctests, default/minimal suites, four isolated
auth-feature test configurations, all configured strict Clippy modes, Rust
1.90 MSRV, packaging/smoke/examples, all nine selected Kani harnesses, and all
three dependency-policy/RustSec checks. Four security-link mutation tests also
passed. Optional single-auth Clippy configurations still report pre-existing
dead-code warnings in shared helpers; their auth tests pass. Server-only
evidence remains current. The complete `scripts/checks.sh` rerun passed after
retaining the seven reports and correcting the security-link check's Python
invocation/shebang to the repository's isolated-interpreter convention. The
13 general evidence regressions and all new capture-rejection tests pass.
All three lockfiles passed RustSec checks against 1,288 advisories; the verified
crate archive is 508,282 bytes. Only the exact README status correction is
separately reviewed; its captured bytes remain in `sdk-capture-readme-v3.md`.

## Prior Dependency Refresh

A freshly updated registry index identified yanked `yoke-derive 0.8.3` after
the verification below. All three lockfiles now use non-yanked `0.8.4`.
Rebuilt binaries have now passed fresh live SDK checks on both patches and
the affected 2.7.0 paths. Seven new reports are independently pinned; old
captures are preserved but rejected as current evidence. Server-only captures
are unaffected. A separately pinned README status correction is the only
post-capture input difference; it never authorizes lockfile changes.

After the dependency update, Rust `1.90.0` MSRV, all configured Clippy modes,
649 all-feature tests, 5 doctests, default/minimal suites, fuzz target builds,
TLS feature unification, package smoke tests/examples and all selected Kani
harnesses passed again. All three lockfiles
passed `cargo deny` and fresh `cargo audit --deny warnings` checks (1,280
advisories). The normal SDK verifier accepts the new captures and rejects the
old dependency inputs, including when artifact/binary digests are allowed.

## Scope

- Validate the patched OpenBao `2.6.4` and `2.7.1` releases independently without changing historical
  exact-version contracts or silently selecting an untested server version.
- Use Rust `1.99.0` as the primary toolchain, retaining Rust `1.90.0` as MSRV.
- Fix RADIUS user-policy reads for the server's array response without changing
  the public `String` field. Both array and legacy string forms are bounded;
  ambiguous array entries are rejected.
- Extend workflow CAS and latest-plugin selection guards to exact verified
  `2.7.0` and `2.7.1` only. Reject older, assumed, range-selected and unknown
  versions; dispatch also checks the exact generated profile.

## Release Gates

OpenBao `2.6.4` is a separate maintenance-line profile, not a subset of the
`2.7.1` profile. Its exact source documentation, signed image/source chain and
TLS/API capture are retained. Its runtime contracts match `2.6.3` exactly apart
from the reported version. A non-routable candidate preserves all historical
cells. The passing strict-candidate public SDK run is now retained, including
the corrected RADIUS read-back, AppRole expiry, Transit, KV, wrapping and legacy
engine administration. Normal routing and its separate normal-build live SDK
verification are now complete. Candidate reports remain separately retained;
the final `sdk-normal-tls-v3.json` report, not a relabelled candidate, is required.
Its LDAP, Kerberos and RADIUS built-ins must retain their 2.6 contracts rather
than inherit the external-plugin exclusions from 2.7. See the
[2.6.4 review](../docs/OPENBAO_2_6_4_REVIEW.md).

Eight exact-version server suites have completed: API capture, external keys,
Transit, PKI, workflow CAS, control groups, system behavior and MFA TOTP. Their
retained evidence distinguishes server checks from public SDK integration.
Control-group replay remains a known upstream failure on `2.7.1`.

The staged candidate preserves historical contracts and is usable only in an
isolated verification build. It is not normal SDK support or a release approval.
The signed image/source chain, public-SDK candidate AppRole/Transit TLS test,
and server-side unseal/recovery backup regressions are retained. Three-node
server protocol and controlled-lag evidence is also retained. A combined
candidate SDK run covered AppRole, Transit, public backup decoding,
multi-node consistency, cancellation after transmission and independent-cluster
rejection. The initial AppRole/Transit SDK report is preserved as historical
evidence only. A refreshed advanced SDK candidate report was retained under
a new filename after the shared test updates, including public workflow CAS
checks; a separate normal-build report supplies the current executable evidence.
A signed-image `2.7.0` to `2.7.1` single-node Raft restart also
verified recovery-backup preservation, access controls and deletion; it is not
a general upgrade guarantee. The profile guards are now updated and locally
tested. Eleven source-bound server regression, backup and upgrade reports have
been freshly captured, validated and retained under new filenames; the separate
consistency-server report is unaffected. The combined patch candidate now
preserves all 19,796 operation/version cells across 28 profiles, with separate
legacy-engine availability for each branch. Normal routing is now wired to the
exact pinned combined registry. Final-source normal-build live evidence for
both patches is now retained. Local release-wide checks have passed.

Both OpenBao `2.6.4` and `2.7.1` are routable in the development build, but this
is not release approval. The separate normal-build public SDK TLS tests passed;
historical compatibility checks and local release checks also passed.
Pentesting and GitHub CI must still complete before this release is tagged.

The affected `2.7.0` evidence has been refreshed against the current sources:
workflow CAS, control groups, system behavior, MFA TOTP, unseal/recovery backups,
backup upgrade, SDK consistency baseline/controlled lag, and all three SDK
backup modes. Twelve `-tls-v2.json` reports were independently pinned; the five
SDK reports were superseded by `-tls-v3.json` dependency-refresh captures and
then `-tls-v4.json` auth-fix captures. The seven server-only reports remain current.
The original captures remain intact and regression tests reject their use as
current-source evidence, even when allowing their original artifact and binary
digests. No check is waived or satisfied by a different server's report.
Control-group replay remains a recorded upstream failure. The historical
25-release core matrix and 17,275-cell contract matrix still verify independently.

The normal-build patch reports retain the README as it existed during capture.
A separately pinned README-only correction updates the pending-refresh status;
no executable source, fixture, dependency or toolchain input changed after capture.
The evidence verifier rejects all other input changes. See the patch reviews
for the retained original README and the exact documentation-review boundary.

## Local Verification Before Auth Corrections

The complete `scripts/checks.sh` run passed after retaining all seven final
SDK reports. It includes the corrected candidate-inventory tests, Rust `1.99.0`
workflow digest, old-lockfile rejection tests and exact README-only correction
tests. Separate fresh-index audits of all three lockfiles also passed with
`--deny warnings`.

- Rust `1.99.0` formatting and all configured Clippy feature combinations.
- Rust `1.90.0` MSRV all-target/all-feature check.
- 649 all-feature Rust tests and 5 doctests, plus default and minimal-feature suites.
- Exact-version evidence, historical contracts, candidate dispatch and evidence tamper tests.
- ML-DSA maximum-input budget and reqwest TLS feature-unification checks.
- Packaged public-API smoke tests and examples; archive size 505,607 bytes,
  within the 512 KiB compressed limit.
- Dependency policy and fresh RustSec checks for primary, fuzz and native-TLS fixture lockfiles.
- All selected Kani harnesses, with no skipped proof stage.

The existing external-plugin exclusions and upstream control-group replay
warning are not removed merely because a new patch release exists. See
[the patch review](../docs/OPENBAO_2_7_1_REVIEW.md) for the current evidence
and outstanding checks.
