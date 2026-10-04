# External RADIUS Fixture Review

Checkpoint 5 is complete. Six exact RADIUS contracts are enabled after successful
server, candidate SDK and normal-build SDK runs on both releases. The
server and candidate SDK fixtures target the signed `auth-radius-v0.1.0` Linux
amd64 artifact on exact OpenBao 2.7.0 and 2.7.1 servers.

## Backend Trust

The user approved the official FreeRADIUS 3.2.10 image as a digest-pinned,
unsigned disposable backend. Every live invocation requires the explicit
`--acknowledge-unsigned-radius-image` flag. The manifest is
`sha256:cc7fd136e7b03e7b332d94297530318e824a4ecfedbce54562cced723e71e812`
under `docker.io/freeradius/freeradius-server`. The independently pinned config
digest is `sha256:801bb663071f6230612cd2ca43cbc3ebd9ba7887b32a6716d632ce2d847c6c9d`.
The verifier hashes both documents and checks Linux amd64 platform identity.
Podman pulls the exact digest using an empty registry credential file and checks
the resulting digest and platform before execution.

No publisher signature, independently attested source-to-binary relationship,
or complete dependency audit is claimed. The upstream
[Dockerfile](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/scripts/docker/dists/ubuntu22/Dockerfile)
and [image instructions](https://github.com/FreeRADIUS/freeradius-server/blob/release_3_2_10/scripts/docker/README.md)
were reviewed. This additional backend exception does not relax signature checks
for OpenBao or its plugin. The existing LDAP bootstrap fixture is reused and
retains its separate unsigned-directory acknowledgement.

## Protocol Boundary

The [pinned OpenBao plugin login implementation](https://github.com/openbao/openbao-plugins/blob/6951cf4b452e918e5b27b9aab0cbbf494d0d613c/auth/radius/path_login.go)
uses UDP RADIUS with an MD5-based authenticator and does not add a
Message-Authenticator. The fixture therefore explicitly disables the backend's
Message-Authenticator requirement for its one 127.0.0.1 client. Proxy-State
limiting remains enabled. This is not a claim of BlastRADIUS resistance or a
recommendation for unprotected deployment.

FreeRADIUS binds only to 127.0.0.1:11812 inside the owned OpenBao network
namespace. No UDP port is published. It runs as UID 65532, with all capabilities
dropped, no new privileges, a read-only filesystem, bounded writable tmpfs, and
the existing CPU, memory and PID limits. No host network or network discovery
is used. The crate's `radius-auth-acknowledged` compile-time gate remains
mandatory. Real deployments require their separately audited transport controls;
these fixtures do not test RadSec or add RadSec support to the plugin.

## Checks And Limits

Random shared secrets and passwords are regenerated for each run. Configuration
interpolation accepts only distinct fixed-length hexadecimal values. FreeRADIUS
performs real PAP verification; there is no unconditional accept rule or custom
RADIUS encoder. Backend probes use its `radclient`, requiring received
Access-Accept or Access-Reject responses, not just an exit code or timeout.
Wrong passwords and unknown users have separate negative controls.

The server fixture checks mounted plugin digest/version, omission of the shared
secret from configuration reads, user mapping CRUD, exact mapped and fallback
token policies, least privilege, mapping removal, shared-secret mismatch and
successful recovery after restoration. The public SDK test covers six typed
operation IDs, including the username-in-path login actually used by the SDK.
The separate body-username login contract is not promoted without typed SDK
coverage. Backend secrets enter the unprivileged SDK process over stdin, never
argv or environment variables. The sealed-executable runner binds the recorded
digest to execution but does not attest source-to-binary provenance.

Backend password logging and container logs are disabled. Progress contains
fixed stage names only. Temporary files and containers are removed; complete
zeroization of Python, HTTP, TLS, allocator, filesystem or kernel buffers is not
claimed. Retained reports contain digests, stage names and public API schemas,
not passwords, tokens or shared secrets.

Local constrained-backend positive and negative controls and offline regression
tests pass. Live server checks passed on both exact releases. Unmodified reports
and mounted schemas are retained under `compat/plugins/radius/{2.7.0,2.7.1}`;
`scripts/verify_openbao_radius_plugins.py` validates independent report anchors,
current fixture inputs, exact backend/plugin identities, protocol limitations,
cleanup and captured API methods. Server evidence cannot satisfy SDK acceptance.
Candidate SDK checks passed on both releases. Unmodified reports and schemas
are retained under `sdk-candidate` with independent report and executable digest
anchors. They are historical candidate evidence, not current normal-build
acceptance. The validator checks all six operations against captured paths,
methods and the LIST query flag. Normal-build reports and schemas are retained
under `sdk-normal` and pass the independent current-source SDK acceptance gate
for both releases. No compatibility promotion follows from server-only evidence.
SDK source additions make earlier
current-input SDK captures stale; the planned final release refresh remains
mandatory and historical captures are not rewritten.
