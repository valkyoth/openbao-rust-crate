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

## Required Before Release

Signed-image and runtime evidence, external-plugin compatibility, new typed
APIs and field rules, security review, live regression coverage, profile
promotion, complete documentation and the final release gate remain pending.
Do not publish or tag this development checkpoint. The stable release is
2.1.9; its security and compatibility guarantees have not been extended to
OpenBao 2.7.0 by this preparation work.
