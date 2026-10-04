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
2. Plugin-aware compatibility foundation: implemented with closed contracts.
   Select exact artifact/server identities per mount independently of the
   built-in server profile; reject unknown identities and duplicate mounts.
   Preserve older built-ins. All plugin contracts remain closed until their
   positive/negative SDK fixtures pass in checkpoints 3-5.
3. LDAP auth and secrets: completed. The isolated, digest-pinned directory
   server fixture and offline trust-boundary regressions are implemented;
   live server and 33-operation public-SDK candidate checks passed on both
   releases. Candidate reports and mounted schemas are retained as historical evidence.
   Server evidence is refreshed; 33 exact LDAP contracts are enabled in source.
   Normal-build live verification passed on both releases; independently anchored
   reports validate against the current production source and fixture inputs. See
   [the LDAP review](OPENBAO_2_2_3_LDAP_REVIEW.md). Real directory services, successful and
   rejected authentication, mappings, generated credentials, rotation,
   revocation and cleanup on both 2.7.0 and 2.7.1.
4. Kerberos: completed. A signed Wolfi base, retained signed repository index
   and 31 hash-pinned packages build a disposable MIT KDC offline. Local ticket
   generation and invalid-keytab rejection pass. Server and nine-operation
   candidate SDK fixtures passed on both releases, and their reports and mounted
   schemas are retained with independent anchors. Nine exact contracts are now
   enabled in source; normal-build live acceptance passed on both releases.
   Retained normal-build reports validate against current SDK and fixture inputs. See
   [the Kerberos review](OPENBAO_2_2_3_KERBEROS_REVIEW.md).
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

## Compatibility Foundation

`plugin::ExternalPluginSelection` records an expected v0.1.0 Linux amd64
artifact, exact 2.7.0 or 2.7.1 target and canonical mount. Construction rejects
unreviewed versions, digests, platforms and server targets. The generated Rust
binary digest constants are checked against the immutable artifact lock.
`OpenBaoConfig::external_plugin` accepts at most 32 selections, rejects duplicate
mounts within auth/secret scope and redacts mount names in diagnostics. Cloned
clients retain the same namespace-bound configuration.

This selection is a caller deployment assertion, not remote attestation. A
server health response does not prove which plugin is installed. Checkpoints
3-5 must establish installation checks and the trust boundary for login clients
that cannot query privileged catalog APIs. No release claim may silently treat
an assertion as server-verified binary identity.

The typed route resolver binds actual mounts separately from documented mount
names. Its plugin branch requires the selected engine and mount, matching
detected and routing server versions, verified compatibility status and an
explicit per-operation reviewed contract. The contract table is deliberately
empty at this checkpoint. There is no fallback to old built-in route evidence,
wildcard approval, or permission gained from merely selecting a plugin. Assumed,
unverified and unknown-newer clients cannot satisfy this branch. Existing feature
acknowledgements and typed dispositions remain enforced.

The production-source edits invalidate affected current-input SDK evidence.
Historical captures remain unchanged; fresh SDK/CI evidence will be collected
after implementation stabilizes, before checkpoint 6 release approval. A stale
capture must fail validation, not be repinned or exempted to keep CI green.
