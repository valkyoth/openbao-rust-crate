# External LDAP Fixture Review

Checkpoint 3 is complete. The 33 reviewed LDAP contracts are enabled in the
source for the exact v0.1.0 artifacts on 2.7.0 and 2.7.1. Normal-build live
acceptance passed on both releases; Kerberos and RADIUS remain closed.
The server fixture is not public-SDK integration evidence and cannot promote a
route by itself. The older built-in LDAP profiles remain unchanged.

## Directory Backend

The disposable test backend is the Linux amd64 image
`docker.io/chrroessner/openldap@sha256:b34d863b73dc1105044c8b589450d15a8d235215723fdcadaf4028d9fbf57a56`.
Its parent index is
`sha256:f6015ce5a66fd1be22d54cebc2c2db9d976a7690d199e5058954128f38454536`.
The observed release is OpenLDAP 2.6.15-r3, with source-revision label
`8f782df51305a3ee38d29b7bd5039ec3ff9e1057`.

The reviewed
[Dockerfile](https://github.com/croessner/docker-openldap/blob/8f782df51305a3ee38d29b7bd5039ec3ff9e1057/Dockerfile)
uses a digest-pinned Alpine base and checksum-pinned OpenLDAP source. The
[workflow](https://github.com/croessner/docker-openldap/blob/8f782df51305a3ee38d29b7bd5039ec3ff9e1057/.github/workflows/docker-publish.yml)
publishes BuildKit provenance and SBOMs. These are not independently signed
publisher attestations. No publisher signature was found for this image.
Labels and source association are registry observations, not verified
source-to-binary provenance. Dependency versions installed during the upstream
build are not independently rebuilt or audited by this fixture.

The user accepted this unsigned, reviewed, digest-pinned image for the disposable
directory backend only. Every invocation still requires
`--acknowledge-unsigned-directory-image`. This does not relax verification of
the signed OpenBao server image or signed plugin archives. The runner verifies
the exact index, amd64 manifest and raw config digest before
pulling the amd64 digest; it also checks the pulled image digest and platform.
Retained registry observations are under `compat/plugins/ldap-directory`.

## Isolation And Secrets

OpenBao and OpenLDAP run as separate unprivileged, read-only containers with
all capabilities dropped, no new privileges, and independently enforced
CPU, memory and PID limits. The directory bypasses the image's bootstrap
entrypoint and healthcheck, using a fixture-owned configuration and a bounded
tmpfs database. An unprivileged startup shell creates the mode-0700 database
directory with umask 077, then replaces itself with slapd. The private tmpfs
parent is group-writable for the explicitly selected GID 0; unsupported tmpfs
`uid`/`gid` options are not required. Logging is disabled. The directory shares only the disposable
OpenBao container's network namespace, not the host namespace. The namespace
has no default route, and published ports bind only to host loopback.
Capability verification checks Podman's bounding-capability metadata and the
actual process UID, all five capability sets, and `NoNewPrivs` in
`/proc/1/status`. Podman's unpopulated `EffectiveCaps` field is not used as
runtime privilege evidence. Empty bounding metadata may render as `null`;
missing metadata or nonzero process capabilities still fails the fixture.

Only LDAPS is enabled. OpenBao's API requires TLS 1.3. Directory transport
accepts TLS 1.2 or 1.3 because the secrets plugin's default maximum is TLS 1.2;
auth is explicitly configured for TLS 1.3. Verified positive handshakes precede
negative CA and hostname checks. Directory credentials are random per run.
The bootstrap DN is separate from the mutable management entry used to test
root-password rotation. Client passwords travel through anonymous descriptors,
not command arguments or environment variables. Child output is discarded.
Seeding invokes the protected `ldapmodify` executable with explicit `-a`
add mode. On distributions where `ldapadd` is an executable-name-dependent
symlink, resolving that symlink must not switch the operation into modify mode.
Regression tests cover this distinction. Directory readiness, negative binds,
certificate rejection and seeding have separate fixed progress labels; client
failures expose only a fixed status classification, never their raw stderr.

TLS keys and the private directory configuration are wiped before removal;
container resources are removed only after matching the run's ownership label.
This is best-effort cleanup of fixture-controlled files, not process-memory,
kernel, allocator, filesystem-journal or physical-media erasure.

## Evidence Gates

The server fixture checks mounted `running_sha256` and
`running_plugin_version` against the pinned plugin identities. Auth login
clients cannot query these privileged APIs: `ExternalPluginSelection` remains
a trusted deployment assertion, not remote binary attestation. An administrator
must install and verify the catalog and mount identity. A health response alone
does not establish the plugin binary identity.

Completed server checks on both 2.7.0 and 2.7.1 include successful authentication with exact user/group
policies, invalid passwords, an LDAP-filter-like username, least-privilege
denials, real static-password rotation, generated credentials that successfully
bind, revocation that prevents binding, and management-password rotation that
preserves credential generation. Runtime mounted API schemas are also captured.
Reports contain fixed check labels and hashes, not passwords, tokens or LDIF
credentials. A failure produces no success report and no compatibility promotion.

The retained reports and mounted schemas are under
`compat/plugins/ldap/2.7.0` and `compat/plugins/ldap/2.7.1`.
`scripts/verify_openbao_ldap_plugins.py` checks independently anchored report
digests, canonical JSON, current fixture-input hashes, exact artifact identities,
schema hashes, required LDAP paths, completed cleanup, and the server-only scope.
Seven regression tests reject report tampering, omitted or changed inputs,
altered schemas, unsupported versions, and inflated assurance claims.
The 21 captured LDAP path contracts are identical between these two server
releases. This schema comparison is not proof of SDK serialization or decoding.

Run independently for each exact server release:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_ldap_plugins.py \
  --version 2.7.0 --acknowledge-unsigned-directory-image
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_ldap_plugins.py \
  --version 2.7.1 --acknowledge-unsigned-directory-image
```

## Public SDK Candidate

`scripts/openbao_ldap_sdk.py --build` builds a disposable source copy with the
pinned toolchain and an allowlisted offline Cargo environment. The initial
candidate opened only the 33 explicit LDAP operations exercised by
`ldap_plugin_live::public_ldap_tls`, for exactly 2.7.0 and 2.7.1. The extended
candidate fixture passed on both exact server releases, including library coverage.
Kerberos,
RADIUS and other server versions remain closed. This is
local trusted-builder provenance, not an independently attested build.

The privileged runner verifies installation and container isolation, freezes the
selected executable in a sealed memfd, verifies its test inventory, and executes
it as the invoking unprivileged user with no capabilities or ambient credentials.
The public SDK checks auth configuration, group/user mapping CRUD and lists,
exact login policies, rejected passwords and filter-like names, least privilege,
secret configuration, static-role CRUD/list and rotation, dynamic-role CRUD,
credential decoding, lease revocation and management-password rotation.
The extended fixture also checks library CRUD/list/status, checkout exhaustion,
unprivileged forced-check-in denial, normal and forced check-in, and real binds
before and after password invalidation. Library check-in enforcement remains
enabled throughout.
SDK-decoded passwords are checked with a protected LDAP client against the real
directory. Passwords travel through stdin, not argv or environment. Only the
public CA certificate is exposed outside the root-private fixture directory.
The runner bounds child output and time, reports only ordered literal stages,
and reaps the entire owned process group on success and failure.

The pinned secrets plugin's configuration-read handler deliberately uses a
passwordless map. `LdapConfig` now decodes an omitted bind password into an
empty `SecretString`, while configuration writes reject an empty password before
transport. Callers must explicitly supply the password when reusing a read
configuration for a write. Regression tests cover passwordless reads, malformed
password values, preserved explicit secrets, redacted diagnostics, and the
pre-transport write rejection. This does not recover or infer the server's
stored password.

Static-role listing uses the registered GET operation with the required
`list=true` query flag. The captured plugin schema requires that flag; a plain
GET is a read operation, not a list operation. The HTTP regression checks the
exact request target, while other LDAP list methods retain their registered
LIST method. Live stages distinguish static creation, role reading, listing,
credential decoding, binds, rotation and post-rotation binds without exposing
returned values.

Candidate SDK reports have a distinct candidate-only scope and cannot substitute for the
server-only evidence. Both live candidate runs passed for all 33 selected
operations. Their reports and schemas are retained under each server directory's
`sdk-candidate` subdirectory as historical decision evidence. Current normal-build
reports and schemas are retained under `sdk-normal`.
`scripts/verify_openbao_ldap_sdk.py` anchors exact normal-build
report bytes and the sealed executable digest, requires the exact stage inventory
and execution-assurance labels, validates every current source/fixture input,
and checks artifact identities, cleanup and captured schemas. Seven tampering
regressions cover source omission/mutation, binary identity, scope inflation,
missing stages, altered schemas and extra assurance claims. All selected
operation IDs must have matching typed registry entries, mounted schema paths
and HTTP methods. List contracts must declare the required `list=true` flag.

LDAP library set/status, checkout, check-in and forced check-in operations passed
in both extended runs. The retained reports were replaced only after verifying
the fresh source hashes, complete stage inventory and schema digests. No stale
report was relabeled as library evidence. The reviewed operations are now listed
explicitly in `src/plugin/ldap_contracts.rs`, selected only for these two exact
server releases. A strict deployment must still select the exact expected plugin,
version, binary digest and mount and use a verified compatibility policy (for
example, `OpenBaoCompatibilityPolicy::automatic_strict()`). A default assumed
profile, a missing selection or an acknowledged newer server does not qualify.

The normal-build runner (`--normal`) executes the unchanged production sources,
without candidate-only contract substitutions. `--build --normal` builds through
the same isolated toolchain/environment path into `target/debug/deps`; sealed
execution and privilege dropping remain mandatory. Normal-build reports use the
distinct `public-sdk-normal-build` scope. Promotion edits change Rust input
hashes; candidate evidence is retained as the decision baseline, not treated as
current-input normal-build acceptance. Fresh normal-build reports now pass all
33 operations on both releases and close checkpoint 3. The validator rejects
candidate-scoped reports in place of normal-build acceptance.
Passing candidate tests does not approve other server versions or different
plugin binaries.

Library status is decoded from the actual direct account map. The required
`available` boolean is inverted into the SDK's `checked_out` field, and each
account name comes from its map key. Missing/malformed availability, duplicate
keys (including escaped equivalents), and excess account counts fail closed.
The account limit is checked before decoding an overflow value. Borrower tokens
are stored as `SecretString` and remain redacted in diagnostics. Unit and HTTP
tests cover the real shape instead of the previously inaccurate wrapped mock.

The server-only reports have been refreshed against the SDK-capable shared
harness and pass current-input validation. No hash bypass is introduced.

Normal-build live verification is complete for the explicitly listed LDAP
operations, exact signed v0.1.0 Linux amd64 artifacts and these two server
releases. This is not approval of arbitrary plugin binaries, other platforms,
other server versions or untested LDAP operations. Final 2.2.3 release integration
and refreshed cross-feature evidence remain checkpoint 6 gates.
