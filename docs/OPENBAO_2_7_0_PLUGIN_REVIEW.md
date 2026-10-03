# OpenBao 2.7 Plugin And Fixture Checkpoint

Checkpoint 03, observed 2026-09-27. This is not SDK 2.7 support, plugin
verification, or a successful skipped integration test. The live staged TLS
fixture passed; checkpoint 03 is complete under the approved exclusions below.

## Availability Update: 2026-10-03

The official catalog now contains non-prerelease `v0.1.0` releases for
[LDAP auth](https://github.com/openbao/openbao-plugins/releases/tag/auth-ldap-v0.1.0),
[Kerberos auth](https://github.com/openbao/openbao-plugins/releases/tag/auth-kerberos-v0.1.0),
[RADIUS auth](https://github.com/openbao/openbao-plugins/releases/tag/auth-radius-v0.1.0)
and [LDAP secrets](https://github.com/openbao/openbao-plugins/releases/tag/secrets-ldap-v0.1.0),
all published on 2026-10-02. Each has Linux amd64 binaries, checksums,
signature files and an SPDX SBOM. Their presence is an artifact-review
candidate, not a verification result: signatures/provenance, extracted binary
digests, catalog registration and positive/negative SDK tests still need review.
SDK 2.2.2 remains documentation/CI-only and preserves the 2.7 exclusions.
The immutable September observation below remains historical evidence.

## Approved Release Scope

The maintainer approved built-in-only 2.7 support for 2.2.0. LDAP auth/secrets,
Kerberos and RADIUS typed engine routes are explicitly excluded on 2.7, even
if a deployment has installed a plugin with a matching name. Their older built-in profiles remain
unchanged. The capability resolver has a version-specific exclusion guard;
retained upstream documentation cannot by itself enable these routes. A detected
2.7-or-newer server is also blocked from these routes when unknown-newer
acknowledgement selects an older fallback profile. An explicitly assumed older
profile or unverified client makes no server probe: callers remain responsible
for the server-version assertion in those modes.

Verified external-plugin support is deferred until suitable artifacts are
available, not promised by this release. It requires independent artifact,
provenance and contract review and positive/negative integration tests. The
`--require-verified` command remains a failing plugin-support gate, but is not
a blocker for the explicitly narrower built-in-only 2.2.0 release.

## Upstream Availability

The official [plugin repository](https://github.com/openbao/openbao-plugins)
was inspected at commit `93abe36c053ce018af1d276d5b4b66575c7de10f` alongside
its public release and Git-tag catalogs. The bounded normalized observation
is hash-anchored in `compat/onboarding/2.7.0/plugin-availability.json`.

| Engine removed from the main binary | Source directory at inspected commit | Matching published release/tag observed |
| --- | --- | --- |
| LDAP auth | `auth/ldap` present | None |
| LDAP secrets | `secrets/ldap` present | None |
| Kerberos auth | Absent | None |
| RADIUS auth | Absent | None |

This records what the public HTTPS API returned at observation time. It is
not signed plugin provenance, an exhaustive search of every external publisher
or registry, or a guarantee that a release cannot appear later. No binary was
downloaded, installed or executed, and unreleased source was not substituted
for a verified release artifact. Plugin version, binary digest/provenance and
runtime contract must all be reviewed separately from the server version.

The observational verifier can pass while plugin support remains blocked:

```sh
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_plugins.py
/usr/bin/python3 -E -s -S -B scripts/test_openbao_2_7_plugins.py
```

`--require-verified` deliberately exits unsuccessfully today. `--observe`
writes a fresh observation into a new temporary file; it cannot overwrite the
committed observation or promote support. New candidate tags are classified
as requiring review, never automatically accepted. Installed-plugin absence,
unverified artifact identity and unsupported SDK behavior must remain distinct;
none of them may be silently converted into a passing plugin test.

## Fixtures

The historical, hash-bound TLS harness already uses `storage "inmem"`; its
bytes and all 25 active profiles remain unchanged. The local developer stack
uses Raft. Thus the plan's anticipated `file`-storage replacement was not
necessary in either fixture. The 2.7 built-in API capture from checkpoint 02
is still dev-mode API evidence, separate from the staged TLS fixture proof.

The optional Podman developer stack now selects 2.6.3 from a single profile
file. Its image digest comes from the verified active release inventory, not
another copied image pin. Server version, Compose project, volume and TLS
directory are resolved together. Unknown, floating and staged-only versions
are rejected, and inherited image/project environment variables are ignored
by the wrapper. Version-specific storage avoids automatic upgrades of old
2.5.5 data. See [local usage and migration](../deploy/podman/README.md).

Tests cover observation tampering, inventory bounds, contradictory statuses,
future tags remaining unverified, promotion rejection, exact dev-version
selection, separate storage, image overrides and wrapper arguments with a
mock Podman executable. The real Compose provider successfully rendered the
new configuration. No persistent local instance was started or upgraded as
part of these checks; fixture rendering is not live-server verification.

## Staged TLS Fixture

The successful operator-run result is retained as
`compat/onboarding/2.7.0/tls-fixture.json`, with hash-anchored input identities.
Offline verification checks both the result and the exact fixture inputs:

```sh
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_plugins.py --verify-tls
```

This is a reviewed local test record, not a signed remote attestation or a new
live run during offline CI verification. New fixture changes require fresh
live evidence before updating the retained result.

Run from the repository on a host with rootful Podman, trusted system tools
and network access for image-signature verification:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_tls.py
```

This uses the signed staged amd64 image, supported in-memory storage, an
ephemeral CA and TLS 1.3, an isolated bridge without a default route or DNS,
and a loopback-only random published port,
read-only container storage and bounded CPU/memory/process resources. It tests
initialization/unsealing, certificate and hostname rejection, TLS 1.2 rejection,
unauthenticated mount denial, built-in Transit setup and the four absent
external plugins. Missing plugins must return catalog/mount errors and remain
absent from the mount inventory; they are not skipped successes. Label-checked
resource removal and private-key cleanup must succeed before a result is emitted.

The staged fixture does not use `--internal`: this host refused connections to
published ports on that network. The replacement explicitly sets strict bridge
isolation and `no_default_route=true`, disables DNS, and verifies both network
configuration and the container's IPv4/IPv6 route tables before initialization.
All container capabilities remain dropped, including network administration.
This restricts routed egress, not access to the directly connected host bridge;
the test container is not claimed to be isolated from the host itself.

This is server-fixture evidence, not an SDK integration test. Python's temporary
initialization token and unseal-share allocations are not guaranteed erased;
they belong only to this disposable in-memory test server, never production.
No credentials are printed or saved in the result. Forced termination may leave
resources behind; inspect the run's ownership labels before manual cleanup.

The offline regression suite also exercises real loopback TLS handshakes with
an ephemeral test server, including all three rejection cases. That test
validates the probe itself; it is not substituted for the OpenBao container run.

## Future Plugin Work (Outside 2.2.0)

- Obtain and independently verify official or explicitly approved external
  plugin artifacts; pin their versions, source/provenance and binary identities.
- Capture and compare their APIs, then run positive and negative tests for
  installation, mount availability, credentials and engine-specific behavior.
- Update plugin-aware routing/field gates before enabling excluded engines. The SDK
  must not infer external-plugin compatibility solely from a 2.7 server version.

This is the sole checkpoint 03 scope deferral approved for a later release.
All remaining built-in 2.7 onboarding checkpoints still target 2.2.0.
