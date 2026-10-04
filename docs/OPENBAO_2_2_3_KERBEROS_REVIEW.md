# External Kerberos Fixture Review

Checkpoint 4 is complete. Nine exact Kerberos contracts are enabled after
successful server, candidate SDK and normal-build SDK runs on both releases.
The server fixture and a candidate public SDK fixture target the exact signed
`auth-kerberos-v0.1.0` Linux amd64 artifact on OpenBao 2.7.0 and 2.7.1.
No compatibility promotion follows from building the fixtures or their images.

## KDC Build

The MIT Kerberos 1.22.2-r4 fixture is built locally from
`cgr.dev/chainguard/wolfi-base@sha256:fbcaceb3a1eedec23eb80df9328f9be4a438546836ec15a67df39a104096d44a`.
Its signed index is
`sha256:9c2092b053779e14c82fb50f77b37bcc38b7d2c83972352d5813280f9d035b03`.
Cosign verifies the exact index digest using the GitHub Actions OIDC issuer and
`https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`
identity, following the publisher's
[verification instructions](https://images.chainguard.dev/directory/image/wolfi-base/provenance).
The index must identify the pinned Linux amd64 manifest.

`compat/plugins/kerberos/packages.lock.json` pins all 31 added packages by size
and SHA-256. The 10 MiB `APKINDEX.tar.gz` is retained because the upstream index
changes over time. Its bytes have an independent SHA-256 anchor. APK checks its
RSA256 signature using the Wolfi key already present in the signed base and
authenticates packages through the signed index. The individual package files
are not claimed to have separate publisher signatures.

Downloads allow only the fixed HTTPS Wolfi repository, reject redirects and
ambient proxies, and enforce per-file and aggregate bounds. Build installation
uses only the retained local repository with networking disabled and signature
verification enabled. The package repository is mounted read-only into the
build step. The local derived image has no publisher signature or independent
build attestation. Podman, APK, the signed base, repository key and local host
remain trusted. This is fixture provenance, not a complete dependency audit.

## Runtime

The KDC runs as UID 65532 with a read-only filesystem, all capabilities dropped,
no new privileges, and enforced memory, CPU and PID limits. Its only writable
database is a private directory in a bounded, noexec tmpfs. It shares only the
owned OpenBao container's isolated network namespace. The KDC listens on
127.0.0.1:1188 inside that namespace and has no published host port.

Realm discovery and reverse DNS are disabled. Principals and keys are created
anew for every invocation. KDC administration is local; no network kadmin service
is started. The fixture explicitly selects AES128/AES256 CTS HMAC-SHA1-96
Kerberos enctypes for interoperability with the plugin's gokrb5 implementation.
It does not enable DES, 3DES or RC4, and makes no SHA-2-enctype, Active Directory
PAC, cross-realm, renewal or replay-prevention assurance claim.

The helper uses MIT `kinit` and the installed MIT GSSAPI library for SPNEGO
generation. Python ctypes declares the small required GSSAPI ABI explicitly;
no ticket encoder or Kerberos cryptography is implemented by the fixture.
GSSAPI buffers and contexts are released, and ticket caches are destroyed after
use. Disposable keytabs remain only in the KDC tmpfs until container removal.
The Python process, pipes, cryptographic libraries and kernel buffers do not
provide complete secret-zeroization guarantees.

The existing reviewed, unsigned directory image is still used only for LDAP
group lookup over verified LDAPS and requires the existing explicit
`--acknowledge-unsigned-directory-image` option. Its trust limits remain those
in the [LDAP review](OPENBAO_2_2_3_LDAP_REVIEW.md).

## Acceptance

Server checks configure the actual mounted plugin, verify its running version
and binary digest, and pass an Authorization header through the mount's explicit
header allowlist. They check keytab omission on reads, LDAP group mappings,
mapped and unmapped user policies, least privilege, malformed and wrong-service
tickets, configured realm mismatch, and policy removal after deleting a mapping.
Negative HTTP responses require the expected status; reflected bodies are
discarded. Progress messages contain only fixed stage names.

The candidate Rust test exercises all nine registered typed Kerberos operations
through public SDK methods, including passwordless configuration reads and the
PAC configuration flag. Real MIT service tickets are sent to an unprivileged
test process over stdin. They never enter argv, environment variables or retained
reports. Execution uses the existing sealed-memfd runner and privilege dropping.
The candidate build opened only the nine explicit operation IDs. These are now
enabled in source for the two exact reviewed releases; RADIUS and other server
versions remain closed. This binds a tested executable digest to
execution, not independently attested source-to-binary provenance.

Local KDC checks have passed for startup, both user identities, both service
principals and invalid-keytab rejection. Live server and candidate public SDK
checks passed on both releases. Unmodified reports and mounted API schemas are
retained under `compat/plugins/kerberos/{2.7.0,2.7.1}` with independently anchored
report digests. Server validation binds current fixture inputs. Candidate reports
under `sdk-candidate` are historical evidence only and cannot satisfy the separate
current-source normal-build acceptance gate. Normal-build captures are retained
under `sdk-normal` and pass that separate gate for both releases. Validators reject identity, scope,
stage, schema, input and executable-digest drift. All nine typed operations must
have matching captured paths and methods, including the LIST query contract.

The first live attempt exposed an object-only parser being used
for Cosign's JSON array; the corrected bounded parser and its regression test
pass, as does fresh signature/platform verification.

Shared fixture and Rust input changes invalidate earlier current-input LDAP
and release SDK evidence. Historical captures are preserved. Refreshes remain
required before final release integration; no old report is repinned or exempted.
