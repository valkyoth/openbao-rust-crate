# OpenBao Dev Podman Stack

This directory is for local development only. Generated state under
`deploy/podman/dev-state/` is ignored and must not be committed.

This is an optional persistent developer server, **not** the version-locked
compatibility test harness. `profile.json` selects OpenBao 2.6.3, the newest
active verified SDK profile. `scripts/openbao_dev_config.py` obtains its exact
image digest from the verified release inventory. Staged 2.7.0 is not selectable
until its compatibility profile is promoted.

From the repository root:

```sh
scripts/openbao_dev.sh prepare
scripts/openbao_dev.sh up
scripts/openbao_dev.sh status
scripts/openbao_dev.sh down
```

Use the wrapper, not direct Compose commands: it resolves and exports the
image and project together, ignoring inherited overrides. The API is bound
to `https://127.0.0.1:9940`, uses TLS 1.3, and persists state in Raft. A new
server still requires intentional initialization and unsealing; credentials
and shares are local development secrets, not production material.

## Existing 2.5.5 Installations

The new project is `openbao-rust-crate-2-6-3`, with volume
`openbao-rust-crate-2-6-3_openbao_data` and TLS files under
`dev-state/2.6.3/tls/`. The former `openbao-rust-crate_openbao_data` volume and
`dev-state/tls/` are not reused or deleted. Stop the old container
`openbao_rust_crate_dev` yourself before starting the new instance because
they share loopback ports. This creates a separate server, not an automatic
data migration. Preserve or back up old data and credentials as appropriate.

`scripts/openbao_dev.sh clean` **destroys the selected version's dev volume
and TLS state**. It does not clean up the legacy volume. Certificates are
short-lived development certificates; regenerate them intentionally when
expired, without discarding Raft data that you need to keep.

Development TLS keys generated before the 2026-06-02 audit were rotated for
local use and are not trusted production material. If a future workflow needs
real credentials, generate fresh keys outside the repository and treat them as
secrets.
