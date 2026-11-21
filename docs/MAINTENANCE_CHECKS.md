# Maintenance checks

Run `bash scripts/maintenance_batch.sh --plan` to see the local check scope.
Run `bash scripts/maintenance_batch.sh` to execute it. Each run writes its
logs and a summary to a private directory under `/tmp`. Neither command signs,
tags, publishes, or starts privileged server fixtures.

The comparison includes committed, staged, unstaged and non-ignored untracked
paths relative to the nearest reachable stable release tag. No usable baseline,
an empty comparison, a major/minor SDK release or an unclassified change selects
the full local gate. Use `--full` to select that gate explicitly.

| Change | Local checks |
| --- | --- |
| Release documentation or package version alone | Release metadata, immutable evidence, defensive control-group regression, public package smoke test |
| Timestamp module or isolated patch bump of the time crate | Baseline plus timestamp tests, dependency policy and MSRV |
| Isolated aes-kw patch bump | Baseline plus Transit import helper tests, dependency policy and MSRV |
| Isolated Tokio patch bump | Baseline plus all-features Rust tests, dependency policy and MSRV; Tokio is shared |
| Unmapped dependency, changed dependency edges, TLS, authentication, build scripts, CI, profile tables or evidence | Full local checks and separate review of the affected live fixtures |

This selection is for local maintenance, not a substitute for hosted release
checks. Live fixture refreshes are explicit (`--release-refresh` for the broad
matrix). Do not use a focused result to claim server support for a new profile.

## Historical control-group evidence

`bash scripts/maintenance_batch.sh --control-groups` checks the three pinned
2.2.5 server reports and runs the current SDK's one-attempt regression against
a local mock. The reports retain the known server-side limitation. They are
not evidence of a new server test or an upstream fix. The exception covers
only the reviewed workflow-CAS edit in `src/sys.rs`; another source digest,
another changed fixture input, or modified historical bytes fails verification.
