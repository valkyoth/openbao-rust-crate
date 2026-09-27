# OpenBao 2.7.0 Onboarding For openbao 2.2.0

Status: checkpoints 01 and 02 implemented; remaining checkpoints are required before
release. The active supported server range remains 2.0.0 through 2.6.3.
Do not publish 2.2.0 or promote 2.7.0 routing from this checkpoint.

## Source Baseline

- [Official release](https://github.com/openbao/openbao/releases/tag/v2.7.0),
  published 2026-09-23T17:39:54Z.
- Reviewed tag commit: `ca305a02daa68b203325daa1b25c18d7a252d4b3`.
- Predecessor: OpenBao 2.6.3, not the 2.7 beta.
- Tagged API root: `website/content/docs/api`.
- `compat/onboarding/2.7.0/source-inventory.json` locks all 122 API source
  files and the 14 added/modified files relative to the locked 2.6.3 snapshot.
  This is source evidence only, not image-signature or runtime evidence.
- Reproduce with `python3 -B scripts/openbao_2_7_source_inventory.py --write
  --source-repository /path/to/openbao`; the repository must contain the exact
  official tag. The generator refuses output differing from its reviewed hash.
- Offline verification: `python3 -B scripts/openbao_2_7_source_inventory.py
  --verify` and the corresponding `--self-test`.

The existing documentation extractor accepts slash-separated HTTP methods but
not the comma-separated method cells used by external-key config/key writes.
Those APIs also group multiple operations under a level-two heading. Checkpoint
02 adds a separately versioned extractor and rebaselines 2.6.3 in the staging
directory without regenerating historical evidence. Its capture scope and
discrepancies are in [OPENBAO_2_7_0_REVIEW.md](OPENBAO_2_7_0_REVIEW.md).

## Commit Checkpoints

Each checkpoint is a reviewable commit on main. Run its regression tests,
record its commit range for pentesting, and resolve findings before proceeding.
All checkpoints target the same 2.2.0 release, not intermediate releases.

| Commit | Goal | Required verification and stop condition |
| --- | --- | --- |
| 01 | Development baseline and source inventory | Version manifests/locks agree on 2.2.0; locked source inventory and tamper tests pass; all 25 active profiles remain unchanged and 2.7.0 remains rejected. |
| 02 | Signed artifacts and complete staged API evidence | Verify exact image signature identity, index/child/provenance relationships; capture bounded runtime OpenAPI; fix comma-separated method and nested operation parsing in a versioned extractor; diff all fields, methods, routes and responses against 2.6.3. Record source/runtime/doc discrepancies explicitly. No active routing promotion. |
| 03 | External-plugin and server-fixture compatibility | Retain older built-in LDAP auth/secrets, Kerberos and RADIUS profiles. Separately pin and verify 2.7 external-plugin artifacts and contracts; distinguish plugin-not-installed from unsupported SDK behavior. Replace removed server `file` storage only in the new fixture with a tested supported backend. No silent mount skips or claims that server version alone proves an external-plugin version. |
| 04 | External-key system administration | Typed config/key/grant CRUD, LIST and PATCH, built-in Transit provider and PKCS#11 schemas, and an explicitly bounded secret-aware path for custom provider options. Review grant privileges, verify=false, merge-patch deletion, endpoint validation, credentials, redaction, request limits and profile rejection. Live delegation tests must prove denied mounts cannot use keys. |
| 05 | Transit ML-DSA and external keys | Create/read/import/export/sign/verify for the three ML-DSA parameter sets; external-key create/rotation and provider-dependent operations; external-mu/prehashed validation, batch variants, import restrictions and response additions. Use additive options/details APIs where existing exhaustive enums or struct literals prevent compatible extension. Live positive and negative crypto tests plus old-profile rejection. |
| 06 | PKI ML-DSA, KMS and RSA-PSS changes | All affected root, rotate, intermediate, key, role, issue and sign paths, external_key_ref and kms mode, parameter-set checks, use_pss, and additive response types. Test PSS defaults, invalid trailing-dot names and unsupported ML-DSA OCSP behavior without weakening existing validation. Do not claim SDK TLS support for ML-DSA certificates merely because the server supports them. |
| 07 | Control groups and approval-aware wrapping | Typed authorize/status APIs with secret accessors and secret-aware bounded request_data; original request responses, authorization tokens and unwrap lifecycle; audit metadata redaction, namespace binding, denial, expiration, replay and cancellation. Review whether a narrowly typed ACL builder extension is safe; opaque PolicyWriteRequest remains available. Do not auto-approve or auto-replay requests. |
| 08 | Explicit consistency controls | Bounded typed X-Vault-Index response capture and X-Vault-Inconsistent request options, profile gating, namespace/cluster scoping, header validation, await-state timeout, forwarding and 429 handling. Preserve non-idempotent retry restrictions. Prove behavior with multi-node live tests, not single-node success alone. |
| 09 | Remaining behavior/field gaps and old security blocks | Catalog OCI digest/default command/latest version support, plugin prune, sanitized config additions, cert Envoy decoder, wrapping-token revoke-self, raw backup reads, MFA TOTP responses, and every other source/runtime delta. Re-review workflow CAS and prefix listing independently; retain blocks on older profiles and require exact 2.7 adversarial tests before lifting either. |
| 10 | Profile promotion and release assurance | Every inventory item has implemented/tested or explicitly justified unsupported/security-blocked disposition. Promote 2.7.0 only after routes, field rules, fixtures, plugin contracts and gates are wired. Regenerate registry/contracts/fixtures; test all historical versions against their own API and mixed-version intersections; update docs/migration/examples, audit dependencies, run full release gate and pentests, then await exact-commit GitHub checks before tagging. |

If a checkpoint needs multiple commits to keep review manageable, record the
subcommits and audit range here. No release capability is considered complete
merely because its planning row exists or its documentation was extracted.

## Security And Compatibility Rules

- Preserve every released exact profile and immutable historical snapshot.
  Removing a built-in engine in 2.7 must not remove its 2.2 server support.
- No new operation or field becomes routable through an assumed profile,
  rolling interval or latest-version fallback before explicit promotion.
- The existing explicitly acknowledged unknown-newer mode still selects only
  the latest reviewed 2.6.3 profile. That is not verified 2.7.0 support; the
  strict, exact, assumed and range policies do not accept a 2.7.0 profile yet.
- Use semver-compatible additions: do not add mandatory fields to existing
  public struct literals or variants to exhaustive enums without an API review.
- External-key configuration can contain tokens, PINs and client keys. Keep
  it out of Debug, tracing, error messages and nonsanitizing intermediate maps.
- Control-group status may reveal the original request body. Treat it as
  sensitive even when a documentation example contains only public fields.
- Source-only, mock, single-node TLS, multi-node and provider-backed evidence
  must be labeled separately. PKCS#11/HSM guarantees require actual provider
  evidence; a Transit provider does not prove hardware memory properties.
- PQC signing support and TLS negotiation are distinct. Do not advertise pure
  PQC transport unless the SDK backend and tested server configuration support
  it; never disable certificate validation to make a new certificate work.
- The 2.7 release reports a workflow CAS fix. Source changes and adversarial
  live tests, not release prose alone, determine whether a security block lifts.

## First Review Findings

The tagged documentation changes include external keys, control groups, PKI,
Transit, Identity MFA TOTP, SSH, namespaces, policies, password policies and
workflows. Small documentation changes can be response-contract corrections,
so they must be reviewed rather than discarded as editorial changes.

The release also removes `file` server storage and built-in external engines;
the current runtime evidence harness cannot simply be run unchanged on 2.7.
The source has moved under `internal/`, and plugin distribution identity is
now a separate compatibility input. These are fixture/evidence changes, not
reasons to weaken production dispatch or erase historical engine APIs.

Checkpoint 02's pentest follow-up hardens acquisition tool execution, adds
aggregate documentation expansion limits, and canonicalizes duplicate ACME
records while rejecting conflicts. The staged documentation and its lock were
corrected; active historical evidence and runtime captures were not rewritten.

The immutable checkpoint 01 source inventory intentionally asserts no endpoint
coverage count. Checkpoint 02 separately locks signed-image evidence, v2
documentation, built-in-only runtime OpenAPI and an adjacent diff. External
plugin capture is pending checkpoint 03; request-field rules, typed APIs,
behavior tests and profile promotion remain pending later checkpoints. Neither
source inventory nor staged API evidence claims usable SDK 2.7.0 support.
