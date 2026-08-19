# OpenBao Server Version Selection

OpenBao documents its HTTP API below `/v1`, but that prefix is not a
backwards-compatibility guarantee. The SDK therefore selects an immutable
exact-release profile before a typed request is serialized. Active profiles
cover all 24 published stable releases from `2.0.0` through `2.6.2`. Exact,
assumed, range, strict-detection, and acknowledged-newer policies may select
`2.6.2`; generated route dispatch never probes or falls back to an older
profile after a server error.

The recommended policy for new applications is strict automatic detection:

```rust
use openbao::{Client, OpenBaoCompatibilityPolicy, OpenBaoConfig};

# fn build() -> openbao::Result<Client> {
let config = OpenBaoConfig::new("https://bao.example.com:8200")?
    .compatibility_policy(OpenBaoCompatibilityPolicy::automatic_strict());
Client::from_config(config)
# }
```

The first SDK operation performs one public, token-free, namespace-free
`/sys/health` request. The detected stable version must have a locked profile.
The result is cached only in that client instance. Typed dispatch then selects
one documented method and route before transmission; it never probes an old
route and falls back to another after an HTTP or decode failure.

## Policy Choice

### Exact

Use `exact` when every backend at the configured origin must run one release:

```rust
use openbao::{OpenBaoCompatibilityPolicy, OpenBaoVersion};

let target = OpenBaoVersion::new(2, 2, 0);
let policy = OpenBaoCompatibilityPolicy::exact(target)?;
# Ok::<_, openbao::Error>(policy)
```

Detection fails before the requested operation when the health response does
not report exactly `2.2.0`. See
[`examples/openbao_2_2.rs`](../examples/openbao_2_2.rs) for complete verified
client construction without printing the token or compatibility report.

### Inclusive Range

Use `range` only for a controlled rolling upgrade whose minimum and maximum
are both exact locked releases:

```rust
use openbao::{
    OpenBaoCompatibilityPolicy, OpenBaoVersion, OpenBaoVersionRequirement,
};

let requirement = OpenBaoVersionRequirement::inclusive(
    OpenBaoVersion::new(2, 4, 4),
    OpenBaoVersion::new(2, 5, 5),
)?;
let policy = OpenBaoCompatibilityPolicy::range(requirement)?;
# Ok::<_, openbao::Error>(policy)
```

The detected exact release selects the routing profile. A range does not build
or enforce the capability intersection across different backends.

For a load-balanced mixed-version cluster, one health probe proves only the
backend that answered that request. Until every node runs the same release:

- keep all backends inside the configured locked range;
- use load-balancer affinity so the health probe and later requests reach the
  same backend, or restrict the application to operations and fields present
  across the complete range;
- do not use a newly added operation during the rollout merely because one
  backend passed the probe;
- return to an exact or strict homogeneous policy after the rollout.

The SDK cannot prove cluster homogeneity through one public health response.

### Assumed

Use `assume` only when a trusted proxy blocks `/sys/health` and deployment
configuration already pins the exact server release:

```rust
use openbao::{OpenBaoCompatibilityPolicy, OpenBaoVersion};

let policy = OpenBaoCompatibilityPolicy::assume(OpenBaoVersion::new(2, 2, 0))?;
# Ok::<_, openbao::Error>(policy)
```

No server request verifies this value. Reports are always `Assumed`, never
`Verified`, and `detected_version()` remains `None`. Do not select an older
profile to force a removed endpoint against a newer server.

### Unknown Newer

Strict mode rejects a server newer than the registry. A temporary emergency
escape hatch requires an explicit acknowledgement:

```rust
use openbao::{
    OpenBaoCompatibilityPolicy, UnknownNewerOpenBaoAcknowledgement,
};

let policy = OpenBaoCompatibilityPolicy::automatic_allow_unknown_newer(
    UnknownNewerOpenBaoAcknowledgement::acknowledge(),
);
```

This detects the newer version but routes with the newest generated profile. Its
report is `AcknowledgedUnknownNewer`, not verified. It cannot prove that the
new server retained an endpoint, request field, response shape, or behavior.
Use it only while onboarding and reviewing the new release.

## Checking The Report

`compatibility_report()` is secret-free, but applications should make policy
decisions from its typed fields rather than logging it:

```rust
use openbao::OpenBaoCompatibilityStatus;

# async fn check(client: &openbao::Client<openbao::Authenticated>) -> openbao::Result<()> {
let report = client.compatibility_report().await?;
if report.status() != OpenBaoCompatibilityStatus::Verified {
    return Err(openbao::Error::Internal("OpenBao profile was not verified"));
}
# Ok(())
# }
```

An unconfigured client remains `Unverified` and assumes the newest reviewed
profile for dispatch compatibility. This preserves migration compatibility,
but it is not a server-version check. Select a strict policy for production.

## Raw APIs And External Plugins

Acknowledged raw JSON and byte transports still perform the configured version
preflight, TLS checks, path validation, response limits, and error redaction.
They bypass typed capability selection and operation-specific feature gates.
The caller must verify that each fixed raw route and body is valid for every
permitted server version.

`PluginMount` provides validated paths for deployment-specific wrappers, but an
OpenBao core profile cannot prove the schema or version of an external plugin.
Pin and test the plugin artifact separately against every OpenBao release used
by the deployment. Never infer external database, directory, cloud, OIDC, MFA,
DNS, or broker compatibility from the built-in core-flow matrix.

## Compatibility Is Not Security Support

The generated [version support matrix](OPENBAO_VERSION_SUPPORT_MATRIX.md)
reports contract classification for exact historical releases and a
representative live core-flow subset. It is not a security endorsement.
Historical OpenBao releases can lack later security fixes even when their wire
behavior remains compatible. Use the newest reviewed OpenBao patch for new and
production deployments; retain an older profile only under an explicit
organizational risk and patch-management decision.

## Onboarding A Future OpenBao Release

Support is append-only. A new release must not regenerate old profiles from
current documentation.

1. Append the exact published source and OCI identities to the release lock.
2. Verify signatures and capture exact tagged documentation and normalized
   OpenAPI into a new immutable snapshot directory.
3. Generate and review the adjacent-release API diff. Resolve every added,
   removed, or changed route and field deliberately.
4. Add typed helpers or a security block for every new operation. No
   `unlinked`, `partial`, `raw`, `external`, `planned`, or `decision` state may
   enter the finalized registry.
5. Add request-field boundaries and response fixtures for changed schemas.
6. Run the isolated live core-flow harness against the exact image digest.
7. Regenerate the capability registry, all operation/profile cells, and the
   user-facing support matrix.
8. Run the full release gate and an exact-commit pentest before advertising the
   profile.

The candidate registry may expose reviewed route variants during ordered
development commits. Candidate-only operation identities remain explicitly
pending and are omitted from the public operation iterator until their typed
implementation lands. The generator rejects gaps, overlaps, unknown operation
IDs, historical cell drift, and any candidate output whose anchored checksum
changes unexpectedly. It separately generates the runtime-approved profile
inventory from the active registry so staged evidence cannot silently widen
the policy or dispatch trust boundary.

Rendered current documentation is only a secondary cross-check. Exact tagged
source, locked artifacts, reviewed diffs, fixtures, and live evidence remain
the compatibility inputs.
