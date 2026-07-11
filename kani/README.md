# Kani Proof Harnesses

Kani proof harnesses live behind `#[cfg(kani)]` in `src/lib.rs` and are run
with a minimal feature set so they exercise the same pure helper code normal
builds compile.

Run them with:

```sh
scripts/check_kani.sh
```

The script uses Rust `1.90.0` by default because that is the supported Kani
toolchain pairing used by the sibling `base64-ng` crate. Override with
`OPENBAO_KANI_TOOLCHAIN` if a newer Kani release supports a newer Rust
toolchain.

Current proof harnesses cover bounded or fixed regression properties for:

- byte-level OpenBao path rejection policy;
- duration component parsing for symbolic one- and two-digit inputs;
- duration component rejection for symbolic non-digit input;
- documented duration parser examples;
- closed OpenBao version interval membership;
- capability-range selection cannot return a range that excludes the selected
  version.

These are intentionally small bounded proofs. They complement unit tests,
integration tests, fuzzing, Miri, and dependency policy checks. They are not a
whole-crate formal-verification claim and do not model reqwest, TLS, async
runtime behavior, OpenBao server behavior, or dependency internals.

The first harness set intentionally avoids symbolic full-path strings because
the current verifier expands Rust UTF-8 validation, allocation, and formatting
internals heavily for this dependency graph. Symbolic full-path proofs should
be added only after more allocation-light parser helpers are extracted or
Kani's standard-library modeling improves.
