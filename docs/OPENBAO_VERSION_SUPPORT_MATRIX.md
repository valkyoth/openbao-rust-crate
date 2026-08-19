# OpenBao Version Support Matrix

This table is generated from committed compatibility evidence. `100.00%` means
every documented operation for that exact profile is classified as typed,
typed-gated, or security-blocked. It does not mean every operation was exercised
live. Live tests cover eight representative built-in core flows on every profile
and six additional 2.6-only flows on 2.6.0, 2.6.1, and 2.6.2; serde fixtures
cover five representative response families.

| OpenBao | Documented operations | Typed | Typed-gated | Security-blocked | Unavailable inventory operations | Classified coverage | Live core flows | Response fixture families |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `2.0.0` | 623 | 551 | 72 | 0 | 68 | 100.00% | 8 | 5 |
| `2.0.1` | 623 | 551 | 72 | 0 | 68 | 100.00% | 8 | 5 |
| `2.0.2` | 623 | 551 | 72 | 0 | 68 | 100.00% | 8 | 5 |
| `2.0.3` | 623 | 551 | 72 | 0 | 68 | 100.00% | 8 | 5 |
| `2.1.0` | 626 | 554 | 72 | 0 | 65 | 100.00% | 8 | 5 |
| `2.1.1` | 626 | 554 | 72 | 0 | 65 | 100.00% | 8 | 5 |
| `2.2.0` | 635 | 563 | 72 | 0 | 56 | 100.00% | 8 | 5 |
| `2.2.1` | 635 | 563 | 72 | 0 | 56 | 100.00% | 8 | 5 |
| `2.2.2` | 635 | 563 | 72 | 0 | 56 | 100.00% | 8 | 5 |
| `2.3.1` | 643 | 571 | 72 | 0 | 48 | 100.00% | 8 | 5 |
| `2.3.2` | 643 | 571 | 72 | 0 | 48 | 100.00% | 8 | 5 |
| `2.4.0` | 660 | 578 | 82 | 0 | 31 | 100.00% | 8 | 5 |
| `2.4.1` | 660 | 578 | 82 | 0 | 31 | 100.00% | 8 | 5 |
| `2.4.3` | 660 | 578 | 82 | 0 | 31 | 100.00% | 8 | 5 |
| `2.4.4` | 660 | 578 | 82 | 0 | 31 | 100.00% | 8 | 5 |
| `2.5.0` | 661 | 580 | 81 | 0 | 30 | 100.00% | 8 | 5 |
| `2.5.1` | 661 | 580 | 81 | 0 | 30 | 100.00% | 8 | 5 |
| `2.5.2` | 661 | 580 | 81 | 0 | 30 | 100.00% | 8 | 5 |
| `2.5.3` | 661 | 580 | 81 | 0 | 30 | 100.00% | 8 | 5 |
| `2.5.4` | 661 | 580 | 81 | 0 | 30 | 100.00% | 8 | 5 |
| `2.5.5` | 665 | 580 | 85 | 0 | 26 | 100.00% | 8 | 5 |
| `2.6.0` | 688 | 592 | 93 | 3 | 3 | 100.00% | 14 | 5 |
| `2.6.1` | 689 | 594 | 93 | 2 | 2 | 100.00% | 14 | 5 |
| `2.6.2` | 689 | 594 | 93 | 2 | 2 | 100.00% | 14 | 5 |

## Evidence Boundary

- Endpoint presence and request-shape evidence comes from exact tagged
  documentation, locked normalized OpenAPI, and reviewed current-contract
  corrections.
- Destructive live tests run only against a fresh ephemeral OpenBao server for
  the selected exact release.
- No external database, directory, cloud, OIDC, MFA, DNS, or message-broker
  service is exercised by the historical core matrix.
- The complete machine-readable operation/profile cells are in
  `compat/version-contract-matrix.json`.
- Compatibility evidence is not a security endorsement of an old OpenBao
  release. Deploy the newest reviewed patch whenever possible.
