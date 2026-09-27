# openbao 2.2.0

Version: 2.2.0
Status: unreleased development; OpenBao 2.7.0 is not yet supported

This release is being developed in pentestable commit checkpoints described in
[the OpenBao 2.7.0 plan](../docs/OPENBAO_2_7_0_PLAN.md).

## Completed

- Development manifests and maintained lockfiles identify 2.2.0.
- Hash-locked inventory of the exact 2.7.0 tagged API source files, with
  predecessor comparison and offline tamper checks.
- Existing 25 server profiles remain unchanged, through OpenBao 2.6.3.
- Staged signed-image/provenance evidence, bounded built-in-only runtime API
  capture, a versioned documentation extractor and like-for-like 2.6.3 delta.
  See the [checkpoint 02 review](../docs/OPENBAO_2_7_0_REVIEW.md) for scope and
  discrepancies. This is not profile promotion or application integration.
- Checkpoint 02 pentest hardening: controlled evidence-tool paths and
  environments, verified-signature claim checks, aggregate documentation
  expansion budgets and duplicate/conflict handling with regression tests.
- Isolated system-Python invocation prevents caller-provided import paths and
  startup customization from bypassing evidence verification.
- Checkpoint 03a records the missing external-plugin release artifacts and
  updates the local dev fixture without touching historical server profiles.
  The approved 2.2.0 scope explicitly excludes LDAP auth/secrets, Kerberos and
  RADIUS on 2.7 pending separately verified plugins (target 2.2.1 when available).
  Historical built-in support is unchanged. See the
  [plugin/fixture review](../docs/OPENBAO_2_7_0_PLUGIN_REVIEW.md).
- Checkpoint 03 completes the staged TLS fixture with verified network/resource
  restrictions, TLS rejection tests, initialization/unsealing, built-in Transit
  creation and explicit absent-plugin checks. Retained evidence is bound to its
  fixture inputs. This is server evidence, not SDK 2.7 profile promotion.

## Required Before Release

Built-in typed APIs and field rules,
security review, live regression coverage, profile
promotion, complete documentation and the final release gate remain pending.
Do not publish or tag this development checkpoint. The stable release is
2.1.9; its security and compatibility guarantees have not been extended to
OpenBao 2.7.0 by this preparation work.
