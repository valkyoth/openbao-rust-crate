#!/usr/bin/env bash
# Keep stdout and Cargo's exit status intact, including for package --list.
set -eu
case ${1-} in
  package|publish) ;;
  *) echo "Usage: bash scripts/package_cargo.sh {package|publish} [cargo options]" >&2; exit 2 ;;
esac
cargo "$@" 2> >(awk '
  BEGIN {
    n = split("candidate_dispatch http_client openbao_integration serde_fixtures tracing_secrets version_contract", names)
    for (i = 1; i <= n; i++) {
      t = names[i]
      expected["warning: ignoring test `" t "` as `tests/" t ".rs` is not included in the published package"] = 1
    }
  }
  !($0 in expected) { print; fflush() }
' >&2)
