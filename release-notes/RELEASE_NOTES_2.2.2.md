# OpenBao Rust SDK 2.2.2

Version: 2.2.2

Documentation and CI maintenance only. The SDK implementation, dependency
versions, feature defaults, Rust 1.99.0 primary toolchain and Rust 1.90.0 MSRV
are unchanged from 2.2.1. No new API migration is required.

The README now describes the current package, including the exact OpenBao
2.6.4, 2.7.0 and 2.7.1 profiles. Installation and security-document links use
2.2.2. The [2.2.1 security migration](../docs/MIGRATION_GUIDE.md#from-openbao-220-to-221)
continues to apply to applications upgrading from 2.2.0.

The historical 25-release compatibility matrix is preserved. Supplemental
CI jobs exercise the public SDK core flow over verified TLS on all three
additional profiles. A guard rejects supported profiles missing from CI.
These jobs do not replace the separately retained advanced, multi-node and
controlled-lag evidence or claim complete endpoint coverage.

Original 2.2.1 evidence remains immutable. Seven fresh SDK captures now bind
the 2.2.2 package metadata and README: the patch normal-build reports use
`sdk-normal-tls-v4.json`; the five 2.7.0 SDK reports use `-tls-v5.json`.
Their current-input validators accept no README exception or metadata waiver,
and regressions reject each obsolete metadata input individually. No old
capture is relabelled as a 2.2.2 execution. The supplemental CI runner passed
locally on all three profiles; the sanitized, source-bound reports are retained
under `compat/ci/2.2.2/`, with independently pinned validators and mutation
regressions. Green GitHub checks on the final commit remain a release gate.

Legacy LDAP auth/secrets, Kerberos and RADIUS remain supported on 2.6.4 and
excluded on 2.7 until external plugins are independently verified. The known
upstream control-group replay failure remains an explicit limitation on
2.7.0 and 2.7.1. Dependency, TLS, allocator and kernel memory are outside
the SDK's complete sanitization guarantee.
