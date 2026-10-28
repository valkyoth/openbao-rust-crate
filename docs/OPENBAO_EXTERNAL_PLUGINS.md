# External Plugin Selection

SDK 2.2.5 supports the exact official Linux amd64 v1 artifacts below on exact
OpenBao 2.7.0, 2.7.1 and 2.7.2. Built-in compatibility remains separate from
plugin selection.

| Plugin | Version | Binary SHA-256 | Feature | Operations | Tested servers |
| --- | --- | --- | --- | ---: | --- |
| LDAP authentication | `v0.2.0` | `b323b200b2dec50199f36de7dc95a661ce6662da3d53905973c0d7700b4185bb` | `ldap-auth` | 11 | `2.7.0`, `2.7.1`, `2.7.2` |
| LDAP secrets | `v0.1.1` | `4b24d4deec624d76bd8f950dfaf6f59822de14cfb9bd344e2e7c4c492cc77789` | `ldap` | 22 | `2.7.0`, `2.7.1`, `2.7.2` |
| Kerberos authentication | `v0.1.0` | `57ac030fea755adf791600eb2b30aa410d2e848ab7ec7bb54cc515cdce4b89ae` | `kerberos-auth` | 9 | `2.7.0`, `2.7.1`, `2.7.2` |
| RADIUS authentication | `v0.2.0` | `ae2ac43287ed297a9536456b0cbb79c8749a82ffe74a54e3fe886d3285443f07` | `radius-auth`, `radius-auth-acknowledged` | 6 | `2.7.0`, `2.7.1`, `2.7.2` |

## Update Policy

Plugin versions are reviewed, pinned and retested as part of OpenBao
compatibility releases. The SDK does not issue a maintenance release for every
routine upstream plugin patch. A plugin security fix, incompatible contract
change, revoked artifact, or other material risk can trigger an earlier review.
Until a new row is published, the table above remains the complete support
claim; newer plugin versions are not inferred compatible.

## Configuration

Use `OpenBaoCompatibilityPolicy::exact` for the server and add an
`ExternalPluginSelection` to `OpenBaoConfig` with `external_plugin`. Supply the
plugin kind, exact server version, mount, the kind-specific version above and
the reviewed binary SHA-256.
`ExternalPluginKind::binary_sha256()` exposes the pinned digest. Use the typed
client's `_at` helper for a non-default mount. Unknown versions, digests,
operations, conflicting mounts and unverified or assumed profiles fail closed.

Selection asserts what the administrator deployed. It does not attest to the
remote executable, install a plugin, or prove that a load balancer routes to the
same cluster. Administrators must verify the signed archive, install the exact
binary, register it and confirm the mounted identity. Protect the server and
plugin catalog against unauthorized replacement. No plugin selection is inferred
from a successful login or a built-in server version.

## Evidence And Limits

The [LDAP](OPENBAO_2_2_3_LDAP_REVIEW.md),
[Kerberos](OPENBAO_2_2_3_KERBEROS_REVIEW.md) and
[RADIUS](OPENBAO_2_2_3_RADIUS_REVIEW.md) reviews describe real backend tests,
mounted schemas, negative cases and normal-build SDK captures. Candidate runs
are historical evidence, not substitutes for current-source normal-build gates.
Core profile coverage is not a claim that every operation has a live plugin test.

Plugin archives require the pinned OpenBao GPG signing identity. The disposable
OpenLDAP and FreeRADIUS backend images are reviewed and digest-pinned but lack
established publisher signatures; their fixtures require explicit acknowledgement.
The MIT KDC derives from a signed base and signed package repository, but its
locally built image has no independent build attestation. These exceptions are
fixture boundaries, not approvals for production deployments.

The sealed executable runner binds a digest to executed bytes, not source to
binary provenance. The compiler, dependency cache, host and dynamic libraries
remain trusted. RADIUS uses legacy UDP/PAP inside an isolated fixture namespace;
this does not demonstrate RadSec or Message-Authenticator protection. Its explicit
protocol-risk feature gate remains mandatory. Kerberos tests do not establish
PAC or cross-realm coverage. Existing TLS and secret-memory limitations in the
[security model](SECURITY_MODEL.md) still apply.
