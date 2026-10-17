# OpenBao Rust SDK 2.2.4

Version: 2.2.4

This maintenance release updates the primary Rust toolchain to 1.99.1 and
refreshes dependency lockfiles and pinned CI tooling. The MSRV remains 1.90.0.
Notable dependency updates include Tokio 1.53.3, sanitization and
sanitization-secrecy 2.1.1, base64-ng 2.1.0 and serde_json 1.0.154.
The upstream-yanked inout 0.2.3 is replaced by non-yanked 0.2.4.

Public APIs, feature defaults, 28 exact OpenBao server profiles, and the
48 reviewed external-plugin operations are unchanged. No application migration
is required from 2.2.3. OpenBao 2.6.4, 2.7.0 and 2.7.1 retain their exact-version
contracts; plugins on 2.7 require explicit artifact and mount selection.

## Security And Evidence

Dependency-policy checks remain fail-closed. Historical fixture reports are
preserved, and current evidence validation binds reports to package inputs and
sealed executable digests. Previous-version captures cannot approve this version.
See [current status](../docs/CURRENT_STATUS.md) for verification records.

Fresh 2.2.4 live fixtures passed for the three current CI profiles, 2.6.4 SDK,
2.7.1 advanced SDK, 2.7.0 consistency and backups, and LDAP, Kerberos and
RADIUS SDKs on both 2.7.0 and 2.7.1. All 15 invocations produced validated
source-bound evidence, retained separately from prior-version captures.

Local validation passed the full CI script and 536 Python tests, including
669 all-feature Rust tests, five doctests, default-feature tests, Clippy, MSRV,
native-TLS unification, fuzz compilation, ML-DSA validation budgets, packaging,
dependency policy, fresh RustSec audits and Kani proofs. GitHub approval of
the final commit and publication remain separate from local verification.

External-plugin selection is an administrator assertion, not remote attestation.
The trusted local builder, dependency and native-code boundaries remain.
Disposable directory and RADIUS fixture images require explicit unsigned-image
acknowledgements. RADIUS still requires `radius-auth-acknowledged`; isolated UDP
fixtures do not establish RadSec support. The known upstream control-group
authorization-token replay limitation is not fixed by this release.
