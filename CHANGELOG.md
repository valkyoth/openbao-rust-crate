# Changelog

All notable changes to this project are documented here.

## Unreleased

### Added

- Initial secure OpenBao SDK scaffold.
- Typestate client with unauthenticated and authenticated states.
- Direct token authentication.
- AppRole login support.
- KV v2 read, write, check-and-set write, list, and latest-version delete support.
- System health and seal-status helpers.
- Raw JSON request escape hatch for unsupported endpoints.
- Local TLS OpenBao development instance on ports `9940` and `9941`.
- CI, GitHub CodeQL default setup compatibility, dependency review, release
  gates, and security documentation.

### Security

- Disabled HTTP redirect following to avoid forwarding token headers to another
  origin.
- Enforced TLS 1.2 minimum by default with configurable TLS version floor.
- Added default connection timeout.
- Added custom CA and root-only trust store configuration.
- Removed crate version from the default user agent.
- Zeroized intermediate bearer and JSON serialization buffers.
- Converted AppRole token accessors to `SecretString`.
- Validated AppRole mount paths at construction time.
- Expanded loopback HTTP detection to the full loopback address range.
