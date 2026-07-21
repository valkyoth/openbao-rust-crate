# Panic Policy

This policy applies to production library code in the `openbao` crate. A
malformed request, hostile OpenBao response, unavailable transport, cancelled
future, poisoned synchronization primitive, or exhausted configured budget must
produce a bounded, secret-free `Error`; it must not panic or abort the caller.

## Production Rules

- Public and internal fallible operations return `Result`.
- Production code must not call `panic!`, `unreachable!`, `unwrap`, or `expect`.
- Integer and allocation calculations derived from untrusted input use checked,
  saturating, or explicitly bounded arithmetic.
- Server-controlled lists, maps, and unstructured JSON enforce item, recursion,
  node, and byte budgets before retaining additional values.
- Lock poisoning and asynchronous cancellation are ordinary error paths. Error
  messages must not retain tokens, credentials, request bodies, response bodies,
  URLs containing sensitive queries, or server-reflected diagnostics.
- A supposedly unreachable state returns `Error::Internal` with a static
  message. It is not expressed as a panic.

These rules are enforced with `#![forbid(unsafe_code)]` and crate lints denying
Clippy's `panic`, `unwrap_used`, `expect_used`, `todo`, and `dbg_macro` checks.
The release gate runs those lints for default and all-feature builds.

## Approved Non-Production Boundaries

Tests may use `panic!` to fail an assertion or convert setup failures into test
failures. Such allowances must be scoped to `#[cfg(test)]` code or test targets;
they must not be placed on production modules or functions.

Kani proof harnesses may model an unreachable branch only when the harness
establishes the invariant and verification proves the branch unreachable. An
exception requires an adjacent `INVARIANT` comment and remains confined to
`#[cfg(kani)]` code.

No production exception is currently approved. Adding one requires a security
review, a narrowly scoped lint allowance, an adjacent `SAFETY` or `INVARIANT`
comment, and a regression test. The release checklist must be updated before
the exception can ship.

## Review Commands

```bash
cargo clippy --all-targets --all-features -- -D warnings
scripts/release_2_1_gate.sh
scripts/release_2_1_1_gate.sh
```

The patch release command also checks the MSRV build, package contents, compatibility
contracts, unit and integration tests, documentation, and Kani proofs.
