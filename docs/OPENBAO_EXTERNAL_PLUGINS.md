# External Plugin Selection

SDK 2.2.3 supports these official v0.1.0 Linux amd64 artifacts on exact OpenBao
2.7.0 and 2.7.1. Built-in compatibility remains separate from plugin selection.

| Plugin | Feature | Reviewed operations |
| --- | --- | --- |
| LDAP authentication | `ldap-auth` | 11 |
| LDAP secrets | `ldap` | 22 |
| Kerberos authentication | `kerberos-auth` | 9 |
| RADIUS authentication | `radius-auth`, `radius-auth-acknowledged` | 6 |

## Configuration

Use `OpenBaoCompatibilityPolicy::exact` for the server and add an
`ExternalPluginSelection` to `OpenBaoConfig` with `external_plugin`. Supply the
plugin kind, exact server version, mount, `v0.1.0` and the reviewed binary SHA-256.
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
