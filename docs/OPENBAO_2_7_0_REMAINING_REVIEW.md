# OpenBao 2.7.0 Remaining Behavior Review

Checkpoint 09 is in progress, based on `e8d2402`. The checkpoint 08 pentest and
GitHub checks passed, including closure of the test-harness CodeQL findings.
No 2.7 profile is promoted. All active historical workflow CAS blocks and the
independent prefix-listing block remain enforced.

## Exact Source Review

The local source checkout reports tagged commit
`ca305a02daa68b203325daa1b25c18d7a252d4b3`. The staged adjacent API delta has 189
records; those records do not capture all behavior changes in the release.
This review supplements the checkpoint 02 inventory, not replaces it.

| Item | Finding / checkpoint 09 work |
| --- | --- |
| OCI digest and default command | Declarative server configuration changes, not optional SHA-256/command fields on catalog HTTP registration. `internal/vault/logical_system.go::handlePluginCatalogUpdate` still rejects missing SHA-256 and command, and requires a decoded 32-byte digest. Keep SDK registration validation. Server provisioning is not an SDK download/execution feature. |
| Plugin prune | `internal/command/plugin_prune.go` is local configuration/storage administration. Do not invent an HTTP route. |
| Latest plugin selection | 09e stages an exact-verified-2.7 guard on the existing mount/auth enable and tune configuration field. Explicit versions and omission remain unchanged. External artifact execution/selection evidence and public 2.7 dispatch are not claimed. |
| Sanitized configuration | Existing `sanitized_config_state_json` accommodates additive JSON fields. 09c verifies the three new explicit boolean defaults live; non-default combinations and public 2.7 SDK dispatch are not claimed. |
| Envoy certificate decoder | `internal/http/handler.go` and `internal/http/util.go` implement listener-side XFCC decoding. This is not a cert-auth role/config field. Do not add an SDK header-spoofing path; server administrators own trusted proxy configuration. |
| Wrapping-token revoke-self | 09c verifies immediate accessor removal and subsequent unwrap/reuse rejection live, with a successful independent unwrap control. Existing SDK methods remain unchanged; no automatic retries. |
| Raw backup reads | 09f retains passing real unseal-backup raw/dedicated API equivalence, deletion, ACL and protected-path evidence. Recovery/upgrade scenarios are not verified. Operator gates and secret-aware SDK results are unchanged. |
| MFA TOTP | Existing `IdentityMfaTotpSecret` stores URL/barcode as secrets; admin method/entity IDs are already modeled. 09d retains passing generation, denial, association removal and fresh-enrollment evidence. Stored-key erasure, QR decoding and login enforcement are not claimed. |
| Workflow CAS | Handler now passes the supplied CAS to the store. Require exact-version adversarial evidence before adding a version-scoped SDK exception. See below. |
| Workflow prefix listing | The tagged handler reads `data.Get("parent").(string)` although its route declares `path`, not `parent`. Source review does not justify lifting the independent prefix block. Keep the block; any live diagnostic is separate from CAS evidence. |
| Remaining inventory | Reconcile all staged operation/schema/documentation deltas and the six recovered historical route identities before checkpoint 10. No aggregate 100% coverage claim is made here. |

## 09a Workflow CAS Evidence

`internal/vault/logical_system_workflows.go::handleWorkflowsUpdate` uses
`GetOk("cas")`, which preserves an explicitly supplied zero in the tagged
`sdk/framework/field_data.go`. The store acquires its lock before reading the
existing entry and checking CAS. `-1` means create-only; a supplied nonnegative
version must match an existing entry. The existing or desired `cas_required`
flag requires CAS, preventing omission from clearing that requirement.

`scripts/openbao_2_7_workflow_cas.py` stages a constrained, disposable server
using the signed image and existing certificate-verified TLS 1.3 harness. It
checks absent-entry zero/positive rejection, create-only semantics, missing,
zero, stale and future CAS, full readback after rejection, matching updates,
required-to-optional transitions, two simultaneous writes with exactly one
winner, and delete/recreate. It does not execute the workflows. It rejects
unexpected errors instead of treating arbitrary failures as CAS enforcement.

The fixture emits a report only after successful checks and cleanup. Input
hashes include its implementation, shared transport/harness and `src/sys.rs`.
Credentials remain out of arguments, logs and reports; Python-managed copies
are not claimed to be sanitizing allocations. The report explicitly sets
`sdk_cas_enabled`, `prefix_listing_verified` and `routable` to false. A passing
Python fixture is not public SDK dispatch evidence.

Run as the repository operator:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_workflow_cas.py
```

The live run passed. Its report is retained in
`compat/onboarding/2.7.0/workflow-cas-tls.json`, with an independent digest pin
and current-source validation in `scripts/verify_openbao_2_7_workflow_cas.py`.
Offline regression tests reject modified claims, missing or changed source
hashes, altered report bytes and noncanonical encoding. They also exercise ignored CAS,
mutation on rejection, multiple winners, strict response state and errors,
partial resource cleanup, redacted diagnostics and refusal to emit a report
after failure. Later 09 work can use this evidence when implementing a narrowly
version-gated CAS exception, with SDK request and historical-profile tests. Older server
profiles and prefix listing remain blocked regardless of this fixture result.

## 09b Staged SDK CAS Guard

Based on `2615d7e`, `Sys::write_workflow` now has a narrow profile-dependent CAS
guard instead of unconditional CAS rejection. Only an exact verified 2.7.0
profile selected through automatic-strict or exact policy qualifies. Assumed,
unverified, rolling-range and unknown-newer fallback reports are rejected, as
are historical releases and unreviewed future patch versions. The operation
still goes through the existing generated routing registry; the currently
unpromoted 2.7 profile cannot send a public workflow request.

Definitions and paths are validated before compatibility probing. Existing
non-CAS writes retain their normal dispatch path. Secret-aware serialization,
response decoding and single-attempt transport are unchanged. CAS versions
`-1`, zero and positive values, as well as `cas_required` without a CAS value,
all trigger the guard. Invalid or stale CAS is never automatically retried.

Unit tests exercise the report boundary, while HTTP regressions verify all
historical assumed profiles perform no I/O, verified old and acknowledged-newer
profiles send only an unauthenticated health probe, and strict detection of
unpromoted 2.7 still fails before a workflow write. Positive public SDK dispatch
remains a checkpoint 10 obligation, not a claim of these tests.

The `src/sys.rs` change invalidated the prior CAS, control-group and SDK
consistency evidence inputs. Fresh live captures are retained and independently
digest-pinned against the current sources and SDK test executable. Their scope
is unchanged: CAS server behavior and SDK consistency checks passed, while the
control-group report still records the known upstream replay failure. No
validator was relaxed and no public profile was promoted.

## 09c Sanitized Configuration And Wrapping Revocation

Based on `55015ec`, the next fixture checks two server behavior changes without
changing production Rust code. The tagged `internal/command/server/config.go`
adds `disable_standby_reads`, `allow_unauthenticated_workflows` and
`unsafe_relative_paths` to sanitized configuration. The fixture requires all
three explicit boolean defaults in the returned data, rather than accepting
missing fields or JSON decoding alone. Non-default configuration combinations
are not claimed by this check.

The tagged `internal/vault/request_handling.go` synchronously revokes a token
on its final use when the request is `auth/token/revoke-self`. The fixture
mirrors the upstream wrapping-token regression: verify a separate wrapping
token can unwrap, look up the test token by accessor, revoke it using itself,
require immediate accessor removal, then require unwrap and reuse to fail.
It accepts only the expected denial status and cause, not arbitrary errors.
The first live run reached post-revocation checks but exposed an incorrect
fixture expectation: wrapping validation rejects a revoked token with HTTP 400
and the invalid-wrapping-token error before ordinary ACL handling. The fixture
now distinguishes that from revoke-self's HTTP 403 permission denial, matching
the tagged request handler and response-status mapping. Offline regressions
reject swapped statuses, swapped causes and unrelated errors. The corrected
fixture subsequently passed its fresh live run.
This is ordinary response wrapping, not a fix for the distinct control-group
replay defect.

`scripts/openbao_2_7_system_behavior.py` uses the existing signed image,
constrained container, isolated network and certificate-verified TLS 1.3
harness. Reports bind the fixture, shared harness and relevant SDK source,
contain no returned credentials or configuration, and are emitted only after
checks and cleanup. Python secret copies are not claimed to be sanitized.
Offline tests cover mutated evidence claims and inputs, incomplete or mistyped
configuration, revocation defects, bounded responses, token header validation
and partial-setup/probe/cleanup failure without a success report.

The passing live report is retained at
`compat/onboarding/2.7.0/system-behavior-tls.json`. The verifier
`scripts/verify_openbao_2_7_system_behavior.py` requires its independent digest,
canonical encoding and exact current source/scope contract. CI tests reject
changed claims, omitted or changed inputs, altered bytes and noncanonical JSON.
To repeat the live capture:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_system_behavior.py
```

This is server-fixture evidence, not public SDK dispatch evidence. Existing SDK
methods and historical profiles are unchanged; 2.7 promotion remains blocked.

## 09d MFA TOTP Enrollment Lifecycle

Based on `904abb4`, this slice verifies the existing admin-generate/admin-destroy
wire contract rather than adding another SDK API. The tagged
`internal/vault/login_mfa.go::HandleMFAGenerateTOTP` returns both `url` and
`barcode`, already modeled as secret strings by `IdentityMfaTotpSecret`.
Repeated generation returns a warning without redisclosing the secret.
Both admin operations already send the documented method and entity IDs.

An important limitation appears explicitly in the tagged
`internal/vault/identity/mfa.go::handleLoginMFAAdminDestroyUpdate`: it removes
the MFA association from the entity but does not remove the stored TOTP key.
The SDK operation name mirrors the server endpoint; it is not a secure-erasure
guarantee. The fixture does not read raw storage or claim that historical secret
material is erased.

`scripts/openbao_2_7_mfa_totp.py` creates a disposable SHA-256 TOTP method and
two entities. It checks the bounded enrollment URL's account, issuer, algorithm,
digits, period and base32 secret, plus the bounded barcode's PNG header and
dimensions. It checks warning-only duplicate generation, denies administrative
operations to an explicitly deny-only token, removes one association and verifies fresh
enrollment with a different secret while the control entity remains enrolled.
The resource lifecycle uses the existing signed-image, isolated-network,
constrained-container and certificate-verified TLS 1.3 harness.

This is server-fixture coverage, not public SDK dispatch, TOTP login-enforcement,
QR decoding or storage-erasure evidence. Those exclusions are explicit report
fields. Returned secrets never enter reports or diagnostic output; Python
allocations are not claimed to sanitize secret bytes. Reports bind the fixture,
shared transport and relevant SDK sources, and require successful cleanup.
Offline tests reject claim/input tampering, malformed enrollment metadata,
duplicate secret disclosure, path-injecting IDs, removal/regeneration defects,
permission failures with the wrong cause and partial resource cleanup failures.

The initial live run stopped at the child-token policy assertion: an empty
policy list inherits the parent's policies in the tagged token store.
The fixture now creates a deny-all ACL policy and verifies that the child's
returned policies contain exactly that policy before any negative MFA probe.
Offline regressions reject inherited root, extra default and missing policies.
The corrected live run passed. Its report is retained at
`compat/onboarding/2.7.0/mfa-totp-tls.json`; the verifier
`scripts/verify_openbao_2_7_mfa_totp.py` checks an independent digest pin,
canonical JSON and exact current source/scope fields. CI tests reject changed
claims, missing or changed inputs, altered bytes and noncanonical encoding.
To repeat the live capture:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_mfa_totp.py
```

## 09e Dynamic Plugin Version Selection

Based on `26a90ec`, the tagged `logical_system.go::validateVersion` distinguishes
an omitted version (select now and pin) from `latest` (resolve dynamically when
setting up the backend). The tune handler also handles that exact selector.
`plugin_catalog.go::getExternal` lists installed versions and chooses the
highest semantic version; this is not downloading or authenticating an artifact.

The existing `MountConfig.plugin_version` already represents the wire field.
Enable requests serialize it within `config`, and tune requests serialize it
at the top level. All four mount/auth enable/tune methods now require an exact
verified 2.7.0 profile when selecting `latest`. Assumed, unverified, range,
historical and acknowledged-unknown-newer fallback profiles fail closed.
The generated registry still independently blocks unpromoted 2.7 dispatch.
Paths are validated before compatibility probing. Omitted and explicitly
versioned requests keep their existing dispatch and serialization behavior.

Unit tests cover the report boundary. HTTP tests cover rejection without I/O
on every historical assumed profile, health-only probing for verified older
and fallback profiles, and unchanged explicit/omitted request payloads on the
historical 2.6.3 profile. These are not external plugin execution tests. The
separately excluded LDAP, Kerberos and RADIUS plugins remain excluded; catalog
SHA-256 and command requirements are not relaxed. Database plugin configuration
is a separate engine contract, not covered by these mount/auth checks.

This production source change invalidated the previous source-bound CAS,
control-group, SDK consistency, system-behavior and MFA reports. Fresh live
captures are now retained with independent digest pins and verified current
source inputs; both SDK reports match the test executable. Evidence scope is
unchanged, including the known upstream control-group replay failure. No old
report was edited to substitute current source hashes. Raw backup reads and
final delta reconciliation remain checkpoint 09 obligations.

## 09f Raw Unseal Backup Reads

Based on `d324862`, the tagged `logical_raw.go::storageByPath` now includes
`core/unseal-keys-backup` and `core/recovery-keys-backup` among the special
upper-barrier paths. The root namespace reads these through physical storage;
an ordinary raw entry does not test this change. `core/keyring` and
`core/cluster/local/info` remain protected.

`scripts/openbao_2_7_raw_backup.py` enables raw storage only in its own disposable
in-memory TLS server. It initializes and unseals that server, then uses the
authenticated root rotation ceremony with a PGP public test recipient and backup enabled.
This creates a real physical unseal-share backup rather than injecting one
through raw writes. The fixture compares the raw JSON nonce and encrypted
shares with the rotation result, checks base64 read equivalence, checks the modern
dedicated backup API and rereads raw storage after that handler runs.
It denies a raw read to an explicitly deny-only token, checks exact protected
path errors even for the root token, deletes the backup through the dedicated
API and requires a subsequent raw read to return absent.

The attributed public recipient is from the exact tagged upstream test suite.
Its private counterpart is public test material upstream: this recipient must
never be used for a real deployment. No private key is imported into this
repository, and no generated shares, backup contents or credentials are logged
or retained. Python copies are not claimed to sanitize secret memory.
The temporary root is private, the server uses the signed image with existing
resource/network/TLS checks, and reports require completed cleanup.

The report is deliberately limited to a newly created unseal backup and
server-fixture behavior. Recovery backup, cross-release upgrade, backup
decryption and public SDK dispatch are not verified by this fixture.
Production raw-access acknowledgement gates and secret response types are
unchanged. Offline regressions cover scope/input tampering, wrong backup data,
encoding mismatch, ineffective deletion, ACL/protected-path bypass, and
partial-setup/probe/cleanup failure without emitting success.

The first live run stopped with HTTP 405 on the legacy rekey route, whose
unauthenticated handlers are disabled by default in 2.7. The fixture now uses
authenticated POSTs to `sys/rotate/root/init` and `sys/rotate/root/update`
and requires their data envelopes. Tests assert both the methods and the root
credential context; server listener defaults are not weakened.
The corrected live run passed. Its report is retained at
`compat/onboarding/2.7.0/raw-backup-tls.json`. The verifier
`scripts/verify_openbao_2_7_raw_backup.py` requires the independent digest pin,
canonical encoding and exact current source/scope fields. CI regressions reject
changed claims, omitted or changed inputs, changed bytes and noncanonical JSON.
To repeat the live capture:

```sh
sudo /usr/bin/python3 -E -s -S -B scripts/openbao_2_7_raw_backup.py
```
