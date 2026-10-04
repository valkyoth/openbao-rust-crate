# OpenBao Rust SDK 2.2.3

Version: 2.2.3

This release adds explicit support for the official v0.1.0 Linux amd64 LDAP
authentication, LDAP secrets, Kerberos authentication and RADIUS authentication
plugins on exact OpenBao 2.7.0 and 2.7.1. There are 48 reviewed operations across
eight plugin/server combinations. The 28 built-in server profiles and feature
defaults are unchanged. Tokio is updated from 1.53.1 to 1.53.2.

Select a verified exact server profile and explicitly declare the plugin kind,
version, mount and pinned binary digest. Selection is a deployment assertion,
not remote attestation; the SDK does not install plugins or discover them by
sending credentials. See [external plugins](../docs/OPENBAO_EXTERNAL_PLUGINS.md).

RADIUS still requires `radius-auth-acknowledged`. The fixture's isolated UDP
transport does not establish RadSec support or general network-level safety.
The known upstream control-group replay defect remains unchanged.

## Release Verification

Checkpoint results and trust limitations are documented in the
[2.2.3 plan](../docs/OPENBAO_2_2_3_PLAN.md) and linked plugin reviews. Fresh
Tokio-updated plugin, core SDK and current-profile CI captures are retained;
earlier reports remain historical and cannot satisfy current-input gates.

Local release checks pass: 669 all-feature Rust tests, 5 doctests, evidence
mutation tests, configured Clippy and MSRV checks, fuzz compilation, package
verification, dependency policy, fresh RustSec scans and Kani. The archive is
520,632 bytes compressed, below the 512 KiB limit. Twenty-one live/performance
tests are intentionally ignored by the all-feature test command; live fixture
evidence and the release-mode ML-DSA budget test are validated separately.

The user's full-range pentest and GitHub approval remain separate release
gates. No tag or publication has been performed for this checkpoint.
