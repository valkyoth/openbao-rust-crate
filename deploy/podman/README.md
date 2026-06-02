# OpenBao Dev Podman Stack

This directory is for local development only. Generated state under
`deploy/podman/dev-state/` is ignored and must not be committed.

Development TLS keys generated before the 2026-06-02 audit were rotated for
local use and are not trusted production material. If a future workflow needs
real credentials, generate fresh keys outside the repository and treat them as
secrets.
