# OpenBao 2.7 Candidate Registry

Checkpoint 10b1 generates `compat/onboarding/2.7.0/candidate-capability-registry.json`
from the pinned active registry, staged v2 documentation/runtime OpenAPI and
reviewed delta. Its separate schema is intentionally rejected by the active
registry validator. It is not consumed by production Rust dispatch.

The candidate contains 707 identities: all 691 active identities, unchanged for
all 25 historical profiles, plus 16 candidate-only identities. These additions
are 13 external-key operations, two control-group operations and the corrected
internal request-inspection route. Every addition is unavailable on historical
profiles. Existing root-token logical endpoint variants are extended only in
this candidate file, without changing the active variants.

## Explicit Decisions

- LDAP auth/secrets, Kerberos and RADIUS remain unavailable on the 2.7 candidate,
  regardless of stale documentation. Their historical cells are preserved.
- External-key PUT aliases are represented by POST, matching runtime OpenAPI
  and SDK methods. External-key LIST entries require the runtime list query
  projection. Placeholders are normalized to existing registry semantics;
  grant mount paths use the existing multi-segment `:path` placeholder.
- `/sys/internal/inspect/request` is the runtime identity. The documented `/root`
  suffix remains in the historical inventory but is unavailable on the candidate.
  The existing SDK inspection method still needs version-aware route wiring.
- SSH issuer PATCH is not invented from its combined documentation table.
  Runtime PATCH appearing later requires new review.
- Workflow LIST and SCAN remain separate identities despite their shared GET
  OpenAPI projection. No ordinary GET-list SDK identity is added. Both prefix
  variants remain security-blocked.
- OIDC public keys retain their reviewed runtime supplement.

Candidate availability is documentation/runtime contract evidence, not proof
that an operation succeeds on the live server. Inherited historical quirks are
not silently repaired. This artifact does not assert complete field coverage,
SDK method coverage, plugin availability, replay safety or strict 2.7 support.

## Verification

```bash
python3 -B scripts/generate_openbao_2_7_candidate.py
python3 -B scripts/test_openbao_2_7_candidate.py
```

Generation uses the existing bounded readers and atomic writer. Verification
requires byte-for-byte reproduction from anchored inputs plus an independent
output digest. Mutation tests reject changed evidence, new unreviewed identities,
lost runtime methods, changed projections, historical-cell changes, missing
exclusions and promotion flags. All checks run in CI without a new container run.

## Still Required

10b must wire the candidate contracts into generation and test strict SDK
dispatch, including request-field rules, internal inspection route variants,
workflow LIST/SCAN and legacy versus external-reference Transit rotation.
Historical exact profiles and mixed-profile intersections must continue to pass.
The live backup fixture must then be repeated under strict 2.7 selection before
promotion. Public promotion and final release assurance remain blocked.
