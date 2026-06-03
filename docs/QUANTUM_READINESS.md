# Quantum-Readiness Design Note

This crate does not claim post-quantum safety for current OpenBao deployments.
The current OpenBao `2.5.x` API surface exposes classical TLS, Transit, PKI,
auth, and seal-management primitives. Until OpenBao publishes stable
post-quantum or hybrid primitives, the SDK can only help callers document and
avoid accidental weakening of the algorithms that are visible through the API.

## Current Scope

- Keep TLS verification enabled and prefer the default rustls transport stack.
- Use `OpenBaoConfig::only_root_certificates` with an internal CA or
  self-signed OpenBao certificate when the deployment needs a private trust
  anchor.
- Use Transit and PKI algorithms that are acceptable for the deployment's
  current policy, and record that policy outside the crate.
- Treat any FIPS-oriented or quantum-readiness report emitted by this crate as
  advisory deployment evidence, not a certification.

## What The Crate Must Not Claim

- No claim that OpenBao, this crate, or a specific Transit/PKI key is
  post-quantum secure.
- No claim that TLS 1.3 alone provides long-term confidentiality against a
  future quantum adversary.
- No claim that an advisory helper replaces HSM, KMS, compliance, or
  cryptographic review.

## Planned Exposure Model

If OpenBao adds stable post-quantum or hybrid cryptographic primitives before
the crate reaches `1.0.0`, the SDK should expose them as explicit typed
options. Any such API must:

- name the OpenBao primitive exactly;
- stay behind a feature gate if it pulls additional dependencies;
- treat key material as `SecretString` or `Zeroizing` data where applicable;
- document whether the primitive is experimental, hybrid, or stable in
  OpenBao's own documentation;
- avoid broad names such as `quantum_safe` unless OpenBao itself uses that term
  for a stable primitive.

For the current pre-`1.0.0` plan, quantum-readiness remains documentation and
posture guidance only.
