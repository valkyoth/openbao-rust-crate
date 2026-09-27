# OpenBao 2.7 Plugin And Fixture Checkpoint

Checkpoint 03a, observed 2026-09-27. This is partial checkpoint work, not SDK
2.7 support, plugin verification, or a successful skipped integration test.

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
is still dev-mode API evidence, not the pending staged TLS integration proof.

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

## Remaining Checkpoint 03 Work

- Obtain and independently verify official or explicitly approved external
  plugin artifacts; pin their versions, source/provenance and binary identities.
- Capture and compare their APIs, then run positive and negative tests for
  installation, mount availability, credentials and engine-specific behavior.
- Establish the staged 2.7 TLS fixture and retain cleanup/resource/TLS gates.
- Update plugin-aware routing/field gates before profile promotion. The SDK
  must not infer external-plugin compatibility solely from a 2.7 server version.

These remain release conditions for 2.2.0, not work deferred beyond this release.
