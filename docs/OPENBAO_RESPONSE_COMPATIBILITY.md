# OpenBao Response Compatibility

This policy governs reviewed response decoding across every exact OpenBao
release locked under `compat/api-snapshots/`, currently `2.0.0` through
`2.6.0`. Response compatibility is evidence-based: optional fields and aliases
are added only when tagged documentation or the checksum-locked normalized
OpenAPI snapshots show the shape.

## Compatibility Rules

- Additive response fields are ignored by default. Public response structs do
  not use `deny_unknown_fields` unless a separate security invariant requires
  an exact object.
- Fields absent from older releases use `Option<T>` or a documented empty
  collection. A missing field must not silently grant a capability or weaken a
  security decision.
- Historical aliases are accepted individually. Where OpenBao returns both
  the current and legacy alias, the current field has explicit, tested
  precedence (`policies` over `keys` and `rules` over `policy`).
- Server-controlled enums reject unknown values. They do not map future values
  to a permissive default.
- Lists and maps use bounded visitors before reading beyond the configured item
  limit. Bounded maps reject duplicate keys rather than overwriting an earlier
  value or allowing duplicates to evade a unique-key count.
- Schema-free system JSON and Identity/PKI extension values use a recursive
  decoder with depth, total-node, and aggregate string-byte budgets. One shared
  budget covers each complete extension map or vector. These limits apply in
  addition to the raw response byte cap and reject duplicate object keys;
  primitive-only PKI metadata rejects arrays and objects before retaining
  their contents.
- Credentials, private keys, accessors, plugin arguments, and plugin
  environment values retain `SecretString` storage and redacted `Debug`
  behavior across every accepted response variant.

## Locked Fixtures

Run the offline fixture checks with:

```sh
python3 -B scripts/generate_openbao_response_fixtures.py --verify
python3 -B scripts/generate_openbao_response_fixtures.py --self-test
cargo test --test serde_fixtures --all-features
```

The generator validates the API snapshot lock first, verifies each OpenAPI
file against its recorded SHA-256, and emits
`tests/fixtures/openbao_response_profiles.json`. Each of its 22 profiles
records its source digest and exercises reviewed response transitions such as:

- PKI certificate `not_before` from OpenBao `2.1.0`;
- ACL policy metadata and rate-limit inheritance from `2.3.1`;
- PKI role IP-SAN CIDR constraints and plugin declarative/OCI markers from
  `2.5.0`;
- numeric PKI role durations returned by all locked lines.

The fixture manifest is generated evidence, not a claim that every helper has
been exercised live on every release. Endpoint presence, request fields,
response decoding, and live behavior are tracked as separate compatibility
dimensions.
