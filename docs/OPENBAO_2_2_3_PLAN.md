# SDK 2.2.3 External Plugin Support Plan

Development target: 2.2.3. The package remains at the published 2.2.2 version
until the final release checkpoint. No external-plugin route is promoted by
checkpoint 1. Existing 28 exact server profiles and historical evidence remain
unchanged.

## Checkpoints

1. Artifact verification: completed. Pin four official v0.1.0 Linux amd64
   releases, archive/signature/checksum/SBOM digests, extracted binary digests,
   source tag commit and the published release signing key. Retain bounded,
   artifact-only evidence and trust-boundary regression tests.
2. Plugin-aware compatibility: pending. Explicitly select verified plugin
   contracts independently of the server profile. Preserve older built-ins
   and reject absent, unknown or mismatched plugins before typed transport.
3. LDAP auth and secrets: pending. Real directory services, successful and
   rejected authentication, mappings, generated credentials, rotation,
   revocation and cleanup on both 2.7.0 and 2.7.1.
4. Kerberos: pending. Real KDC authentication, mapping and rejection tests on
   both server releases.
5. RADIUS: pending. Real authentication, policy mapping and rejection tests on
   both server releases; retain the existing explicit protocol-risk gate.
6. Release integration: pending. Eight plugin/server combinations, CI, refreshed
   SDK evidence, full regressions, documentation and package bump to 2.2.3.

## Artifact Checkpoint

The reviewed upstream
[release workflow](https://github.com/openbao/openbao-plugins/blob/6951cf4b452e918e5b27b9aab0cbbf494d0d613c/.github/workflows/release.yaml)
uses GPG detached signatures for archives. The pinned primary fingerprint is
`66D15FDD87287219C8E15478D200CD702853E6D0`; its signing subkey is
`E617DCD4065C2AFC0B2CF7A7BA8BC08C0F691F94`. The public key is published in
[OpenBao's installation instructions](https://openbao.org/docs/next/install/).
No ambient user keyring, GPG configuration, proxy or keyserver is used.

All four tags resolve to commit `6951cf4b452e918e5b27b9aab0cbbf494d0d613c`:

| Plugin | Release |
| --- | --- |
| LDAP auth | [auth-ldap-v0.1.0](https://github.com/openbao/openbao-plugins/releases/tag/auth-ldap-v0.1.0) |
| Kerberos auth | [auth-kerberos-v0.1.0](https://github.com/openbao/openbao-plugins/releases/tag/auth-kerberos-v0.1.0) |
| RADIUS auth | [auth-radius-v0.1.0](https://github.com/openbao/openbao-plugins/releases/tag/auth-radius-v0.1.0) |
| LDAP secrets | [secrets-ldap-v0.1.0](https://github.com/openbao/openbao-plugins/releases/tag/secrets-ldap-v0.1.0) |

`compat/plugins/artifacts.lock.json` pins every selected asset and binary digest.
The checksum and SBOM files are hash-pinned observations, not separately signed
attestations. Despite their `.spdx.sbom.json` filenames, these SBOMs contain
CycloneDX 1.7, as produced by upstream's Makefile. This checkpoint checks their
format and identity, not a complete Go dependency vulnerability/license audit.

The verifier runs unprivileged, downloads bounded HTTPS responses only from
GitHub and its release-asset host, verifies the detached signature, then checks
the binary against the pinned digest. Archive expansion, file sizes and ELF
architecture are bounded. Only two uniquely named regular members are accepted;
links, device files, extra paths, writeable group/other permissions and special
permission bits are rejected. No tar extraction API or plugin execution occurs.
Private temporary downloads are removed after capture.

`compat/plugins/artifact-review-v1.json` records the successful local review.
The offline validator anchors its bytes and current verifier inputs. It checks
the retained observation, not a fresh cryptographic execution. Reproduce with:

```sh
/usr/bin/python3 -E -s -S -B scripts/openbao_plugin_artifacts.py --capture
/usr/bin/python3 -E -s -S -B scripts/verify_openbao_plugin_artifacts.py
/usr/bin/python3 -E -s -S -B scripts/test_openbao_plugin_artifacts.py
/usr/bin/python3 -E -s -S -B scripts/test_verify_openbao_plugin_artifacts.py
```

This proves signed artifact identity under the pinned OpenBao key. The tag/source
association is retained GitHub metadata, not signed source-to-binary provenance,
a reproducible build, server/plugin protocol compatibility or full functional
SDK coverage. Local host, Python, GPG and TLS trust remain prerequisites. Future
privileged fixtures must independently protect tool paths and install the exact
verified binary without a hash-to-execution race.
