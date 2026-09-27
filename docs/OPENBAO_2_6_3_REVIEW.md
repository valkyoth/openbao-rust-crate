# OpenBao 2.6.3 Review For openbao 2.1.9

Reviewed 2026-09-27. Source, signed-image, provenance, and exact runtime API
evidence have been captured and verified. Exact 2.6.3 TLS integration passes.
The release remains subject to final release checks, pentesting, and GitHub CI.

## Source And Artifact Identity

- [Official release](https://github.com/openbao/openbao/releases/tag/v2.6.3),
  published 2026-09-23T17:06:02Z; neither draft nor prerelease.
- Source commit: `63a65e6b907589dbb952c371a70260a065bf8bd7`.
- [Changes since 2.6.2](https://github.com/openbao/openbao/compare/v2.6.2...v2.6.3).
- Tagged API documentation: `website/content/docs/api`.
- OCI index: `sha256:a60afafda36337abe833c4a63894bf1095098f29abea4091e7e555a33dd52889`.
- Linux amd64 descriptor: `sha256:99c8dd178200d9a5f1a0420d6b1923514280e31e9271bdd92c69f765738c42aa`.
- Index verified with Cosign 3.1.2 against the exact certificate identity
  `https://github.com/openbao/openbao/.github/workflows/release-images.yml@refs/tags/v2.6.3`
  and issuer `https://token.actions.githubusercontent.com`. Signature claims,
  transparency-log inclusion, and the certificate chain passed verification.
  The child has no separately published Cosign signature. The index-bound
  SLSA provenance subject matches the child digest and its source revision
  matches the locked commit; the child is not independently signed.

## Reviewed Changes And Required Work

| Change | SDK assessment and verification |
| --- | --- |
| Raw storage `compression_type="none"` | Added profile-gated `raw_write_uncompressed`. Live normal-mode creation returns 400 because upstream normalizes `none` only in UpdateOperation; existing entries accept it. Existing `raw_write` with `RawCompression::None` (`""`) creates entries in normal mode. Both behaviors are tested. No retry or alternate write occurs. |
| Raw storage read response | Live testing found the SDK decoded a flat object instead of `data.value`. Fixed the envelope decoder and mock, with real TLS create/update/read/delete coverage. |
| `sys/leader` emits `is_self=false` | Existing `LeaderStatus` accepts it. Add regression coverage for explicit false, true, and historical absence; do not claim a live HA regression from a single-node fixture. |
| Recovery-token status works after unsealing in recovery mode | Existing routes and types remain applicable. Review status decoding and retain the operator gate; distinguish mock coverage from a real recovery-mode ceremony. |
| ACL canonicalization for cert, Kubernetes, userpass, PKI, policies, workflows | Server now resolves canonical resources before ACL checks. A live restricted-token regression proves lowercase and uppercase userpass paths both respect a deny policy. Caller paths are not lowercased globally. This is representative coverage, not a live test of each affected backend. |
| Plugin catalog namespace restrictions | Tagged `vault/logical_system_paths.go` wraps catalog read, update, and delete in `handleRootNamespaceOnly`. Release prose mentions writes only, so document the source-observed read restriction too. Do not auto-retry in the root namespace. |
| Internal `ResolvePathOperation` | Classified as an internal operation in `sdk/logical/request.go`, not a new public HTTP method. Retain workflow/internal-operation rejection. |
| Agent/proxy quit and cache-clear request-header enforcement | These local agent APIs have no wrappers here. No new endpoint or unconditional header behavior is required for this patch. |
| PKI ACME SAN validation and removal of OIDC UI `prompt=none` redirects | Server/UI security changes. Keep the existing ACME protocol handoff; do not simulate these protections client-side. |
| Policy template errors, namespace cache traversal, malformed-value audit redaction | Server-side fixes, not guarantees the SDK can backport to old servers. Preserve secret-safe diagnostics and existing acknowledgements. |
| HA forwarding, mount/auth invalidation, MFA deletion, configuration merging | Server runtime fixes with no identified new typed request fields. Exact runtime OpenAPI comparison and live tests remain required. |

The only tagged file changed inside the API documentation tree is
`system/raw.mdx`. The normalized adjacent API diff has zero structural
changes; it omits prose and does not capture the new compression value or
authorization semantics. The source review and live regressions therefore
remain necessary alongside the snapshot comparison.

## Verification And Scope

- Runtime OpenAPI was captured with rootful Podman and enforced memory, CPU,
  task, network, and filesystem restrictions. The rootless service on this
  host lacked delegated memory/CPU controllers; limits were not relaxed.
- Release and API evidence append the new profile and preserve the existing
  snapshots. The rendered cross-check uses `/docs/2.6.x/api/`, not the current
  website's 2.7 documentation.
- Wire tests reject explicit `none` on all older profiles before transport,
  preserve legacy compression values, and cover invalid paths and encoding.
- The live TLS flow covers normal-mode raw storage, canonical userpass ACLs,
  and the existing 2.6 workflow, PKI, Transit, and JWT regressions.
- HA standby behavior and an actual recovery-mode token ceremony are not
  demonstrated by the single-node live fixture. Leader response parsing has
  explicit true, false, historical omission, and invalid-type unit tests.
- The server's two existing workflow security blocks and JWT CEL
  acknowledgements remain enforced. The source changes do not fix the blocked
  workflow CAS or prefix-list implementations.
- OpenBao 2.7.0 is not promoted by this release.
