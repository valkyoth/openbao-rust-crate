# Contributing

Contributions must preserve the crate's security posture.

## Local Checks

Run:

```sh
scripts/checks.sh
```

For release candidates, run:

```sh
scripts/stable_release_gate.sh
```

## Code Rules

- Do not add unsafe Rust.
- Do not log tokens, secret IDs, client tokens, wrapping tokens, passwords, or
  unwrapped secret payloads.
- Do not add an external dependency unless it removes meaningful risk or
  complexity.
- Validate every OpenBao path through the shared path helpers.
- Keep feature flags narrow and documented.
- Prefer explicit structs over untyped `serde_json::Value` in public APIs.
- Use `serde_json::Value` only for raw extension points or plugin payloads.
- Add tests for both success and failure cases.

## Dependency Rules

Before adding a dependency:

1. Confirm the latest version.
2. Confirm license compatibility with `MIT OR Apache-2.0`.
3. Confirm the crate is maintained.
4. Update `deny.toml` only with a written reason in the release plan.
5. Run `cargo deny check` and `cargo audit`.

## Release Rules

Every release must have:

- a release-notes file under `release-notes/`;
- a passing release gate;
- generated SBOM evidence;
- reviewed `cargo audit` and `cargo deny` output;
- owner-provided pentest report before tagging.
