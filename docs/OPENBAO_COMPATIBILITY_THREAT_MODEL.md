# OpenBao Compatibility Threat Model

This document defines the security boundary for selecting and dispatching an
OpenBao server profile. It complements `docs/SECURITY_MODEL.md`; it is not a
claim that an older OpenBao release remains secure merely because its API
contract is known.

## Protected Properties

- A typed call selects exactly one method and route variant reviewed for the
  active exact profile before request serialization.
- An unavailable, malformed, overlapping, or security-blocked selection fails
  locally and cannot trigger historical-route probing.
- A compatibility report distinguishes verified, assumed, unverified, and
  acknowledged-unknown-newer states without including secrets or concrete
  request paths.
- Generated history is append-only. Onboarding a new release cannot change an
  older profile without changing checksum-anchored artifacts under review.
- Malformed release locks, snapshots, capability data, response fixtures, and
  version contracts fail closed under bounded duplicate-key-safe parsing.

## Trust Boundaries

| Input | Trust decision |
| --- | --- |
| Official source and OCI artifacts | Accepted only at locked identities after the documented signature and digest checks. Artifact identity is not API behavior or security proof. |
| Tagged API documentation | Primary route and field evidence for that exact release, but documentation can contain defects. |
| Normalized OpenAPI | Supporting exact-image evidence. It can omit runtime-only behavior and is not authoritative by itself. |
| `/sys/health` version | Trusted only through the configured TLS origin and terminating proxy. One response identifies one backend, not an entire cluster. |
| Generated Rust and JSON | Trusted only when deterministic regeneration and anchored checksums match. Generated prose cannot grant a capability. |
| External plugin responses | Outside the core profile. Plugin artifact, schema, upstream service, and version remain deployment-owned. |
| Raw transport calls | Outside typed capability selection even after compatibility preflight. The caller owns route and schema review. |

## Attacker Model

The boundary considers a malicious or corrupted workspace artifact, a stale or
compromised dependency/source artifact, malformed server-controlled health or
response data, a proxy that reports a misleading backend version, mixed
cluster routing, and accidental downgrade through an assumed or unknown-newer
policy. It also considers generated-data tampering intended to create a false
coverage report.

The boundary does not assume that the SDK can prove server patch integrity,
cluster homogeneity, external plugin behavior, an external service's protocol,
or the absence of a vulnerability in a historically compatible OpenBao build.

## Enforced Controls

- release and snapshot inputs use bounded, no-follow, non-blocking regular-file
  reads, duplicate-key rejection, strict schemas, canonical serialization, and
  separately anchored hashes;
- exact, strict, and range policies use one token-free, namespace-free health
  probe with cancellation-safe per-client caching;
- range endpoints must be locked releases, and unknown intermediate or older
  releases fail closed;
- operation ranges are complete, ordered, and non-overlapping; runtime lookup
  uses the same interval selector covered by focused Kani proofs;
- route templates, methods, query selectors, and versioned request fields are
  checked before sensitive body serialization;
- response aliases, bounds, duplicate handling, and representative historical
  shapes are validated by generated fixtures;
- deterministic mutation fuzzing covers snapshot normalization and version
  contract decoding, while cargo-fuzz targets cover version parsing, profile
  selection, capability lookup, and representative response envelopes;
- CI compiles every fuzz target and verifies the committed historical and
  malformed seed corpus.

## Residual-Risk Register

| Residual | Consequence | Required mitigation |
| --- | --- | --- |
| Supply-chain identity is not behavioral proof | A correctly signed source or image can still contain a defect or vulnerability. | Keep tagged docs, normalized OpenAPI, reviewed diffs, fixtures, live core tests, audits, and pentests as separate evidence. |
| Runtime detection observes one backend | A later request can reach a different version in a mixed cluster. | Use backend affinity or only the operation/field intersection for the configured range until rollout completion. |
| A TLS proxy can report a selected version | Dispatch can match the proxy's claim rather than the eventual backend. | Treat the proxy as part of the trusted computing base and bind its routing/version policy operationally. |
| Assumed mode has no runtime evidence | Misconfiguration can select routes absent from the server. | Restrict it to a trusted deployment pin when health is unavailable; monitor the visibly `Assumed` report status. |
| Unknown-newer mode uses the newest known profile | A new server may remove or change a route or response. | Use only as a temporary acknowledged emergency mode and onboard the exact release promptly. |
| External plugin versions are independent | A core profile cannot establish plugin schema or service compatibility. | Pin and test each plugin and external service for every deployed combination. |
| Locked profiles can become stale | Compatibility knowledge does not include later server fixes or newly disclosed vulnerabilities. | Prefer the newest reviewed patch, monitor OpenBao advisories, and onboard releases append-only. |
| Live coverage is representative | A classified operation may not have run live on every historical release. | Keep the generated matrix explicit about contract, serde, and live evidence levels; do not reinterpret 100% classification as 100% live execution. |
| Fuzzing and bounded proofs are incomplete methods | They cannot establish whole-program correctness or exhaust external stacks. | Retain ordinary tests, sanitizers where applicable, Kani scope statements, CodeQL, audits, and independent pentests. |

## Review Triggers

Revisit this model whenever a new OpenBao release is added, a compatibility
policy or report state changes, a raw transport becomes public, a plugin schema
is promoted into the core API, a generated artifact schema changes, or a new
server-side security deprecation blocks a formerly available operation.
