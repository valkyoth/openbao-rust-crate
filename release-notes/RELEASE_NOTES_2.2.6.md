# OpenBao Rust SDK 2.2.6

Version: 2.2.6

The core registry adds exact profiles for OpenBao 2.6.6 and 2.7.3.
Strict detection still rejects unknown versions. The reviewed plugin/server
pairs are separate from the core registry: 2.7.3 plugin checks used the
candidate SDK and do not extend normal-build plugin support.

The primary Rust toolchain is 1.100.0. The minimum supported version remains
1.90.0. This maintenance update refreshes dependencies and CI tooling without
changing the default compatibility policy.
