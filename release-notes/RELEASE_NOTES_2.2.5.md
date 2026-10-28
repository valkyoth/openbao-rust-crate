# OpenBao Rust SDK 2.2.5

Version: 2.2.5

## Compatibility

- Adds exact OpenBao 2.6.5 and 2.7.2 profiles without regenerating historical
  capability cells.
- Adds the reviewed SSH identity-template wildcard override for the maintenance
  releases that expose it. The ordinary request type continues to omit it.
- Refreshes exact official external plugin support to LDAP auth 0.2.0, LDAP
  secrets 0.1.1, Kerberos auth 0.1.0 and RADIUS auth 0.2.0 on OpenBao
  2.7.0, 2.7.1 and 2.7.2.

## Plugin Policy

Plugin pins are normally refreshed and retested with an OpenBao compatibility
release. Routine plugin-only updates do not automatically cause an SDK release;
security fixes, revoked artifacts or incompatible behavior may require an
earlier review. The README table is the complete exact support claim.

## Security

Strict testing confirms that OpenBao 2.7.2 still lacks the required
single-use enforcement for the affected control-group workflow. This release
documents the result at the security-property and mitigation level without
publishing operational reproduction detail. Do not rely on affected versions
for single-use authorization of non-idempotent privileged actions.

The plugin release archives are pinned by version and binary digest and were
validated against the OpenBao release signing key, checksum inventories and
SBOMs. Plugin selection remains a deployment assertion, not remote attestation.
The disposable LDAP and RADIUS backend image trust exceptions remain explicit.

## Toolchain

The primary toolchain is Rust 1.99.1 and the minimum supported Rust version is
1.90.0. Dependency and GitHub Actions pins are checked by the release gates.
