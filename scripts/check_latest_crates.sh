#!/usr/bin/env sh
set -eu

echo "latest rustc in use:"
rustc --version

cargo_search_crate_version() {
  crate=$1
  cargo search "$crate" --limit 1 \
    | sed -n "s/^${crate} = \"\\([^\"]*\\)\".*/\\1/p" \
    | head -1
}

crates_io_api_crate_version() {
  crate=$1
  json=$(
    curl -fsSL \
      --retry 3 \
      --retry-delay 2 \
      -A openbao-rust-crate-checks \
      "https://crates.io/api/v1/crates/${crate}" \
      2>/dev/null || true
  )

  if [ -z "$json" ]; then
    return 0
  fi

  version=$(printf '%s\n' "$json" | sed -n 's/.*"max_stable_version":"\([^"]*\)".*/\1/p' | head -1)
  if [ -z "$version" ]; then
    version=$(printf '%s\n' "$json" | sed -n 's/.*"newest_version":"\([^"]*\)".*/\1/p' | head -1)
  fi
  printf '%s\n' "$version"
}

latest_crate_version() {
  crate=$1
  version=$(cargo_search_crate_version "$crate" 2>/dev/null || true)
  if [ -z "$version" ]; then
    version=$(crates_io_api_crate_version "$crate")
  fi
  printf '%s\n' "$version"
}

manifest_crate_version() {
  crate=$1
  sed -n \
    -e "s/^${crate} = \"\\([^\"]*\\)\".*/\\1/p" \
    -e "s/^${crate} = { version = \"\\([^\"]*\\)\".*/\\1/p" \
    Cargo.toml \
    | head -1
}

check_manifest_crate_version() {
  crate=$1
  expected=$(latest_crate_version "$crate")

  if [ -z "$expected" ]; then
    echo "failed to resolve latest ${crate} crate version" >&2
    exit 1
  fi

  echo "${crate} latest ${expected}"

  actual=$(manifest_crate_version "$crate")
  if [ "$actual" != "$expected" ]; then
    echo "Cargo.toml: ${crate} is pinned to ${actual:-missing}, expected latest ${expected}" >&2
    exit 1
  fi
}

check_workflow_tool_version() {
  tool=$1
  expected=$(latest_crate_version "$tool")
  workflow=.github/workflows/ci.yml

  if [ -z "$expected" ]; then
    echo "failed to resolve latest ${tool} crate version" >&2
    exit 1
  fi

  actual=$(
    sed -n "s/.*${tool}@\\([^,[:space:]]*\\).*/\\1/p" "$workflow" \
      | head -1
  )

  echo "${tool} latest ${expected}"

  if [ "$actual" != "$expected" ]; then
    echo "${workflow}: ${tool} pin is ${actual:-missing}, expected ${expected}" >&2
    exit 1
  fi
}

echo "checking current crates.io versions used by this crate"
check_manifest_crate_version aes-kw
check_manifest_crate_version base64-ng
check_manifest_crate_version bytes
check_manifest_crate_version futures-core
check_manifest_crate_version getrandom
check_manifest_crate_version openssl
check_manifest_crate_version rand
check_manifest_crate_version reqwest
check_manifest_crate_version secrecy
check_manifest_crate_version serde
check_manifest_crate_version serde_json
check_manifest_crate_version subtle
check_manifest_crate_version time
check_manifest_crate_version tokio
check_manifest_crate_version tracing
check_manifest_crate_version sanitization

echo "checking CI cargo tool versions"
check_workflow_tool_version cargo-deny
check_workflow_tool_version cargo-audit
check_workflow_tool_version cargo-sbom

echo "checking OpenBao latest GitHub release"
curl -s https://api.github.com/repos/openbao/openbao/releases/latest \
  | sed -n 's/.*"tag_name": "\(v[^"]*\)".*/latest OpenBao release: \1/p' \
  | head -1

check_github_action_pin() {
  action=$1
  repo=$2
  major=$3
  workflow=$4

  latest_tag=$(
    git ls-remote --tags --sort=version:refname "$repo" "refs/tags/v${major}.*" \
      | sed -n "s#^[0-9a-f][0-9a-f]*[[:space:]]refs/tags/\(v${major}\.[0-9][0-9]*\.[0-9][0-9]*\)\$#\1#p" \
      | tail -1
  )

  if [ -z "$latest_tag" ]; then
    echo "failed to resolve latest ${action} v${major} tag" >&2
    exit 1
  fi

  tag_refs=$(git ls-remote --tags "$repo" "refs/tags/${latest_tag}" "refs/tags/${latest_tag}^{}")
  latest_sha=$(
    printf '%s\n' "$tag_refs" \
      | sed -n "s#^\([0-9a-f][0-9a-f]*\)[[:space:]]refs/tags/${latest_tag}\^{}\$#\1#p" \
      | head -1
  )
  if [ -z "$latest_sha" ]; then
    latest_sha=$(
      printf '%s\n' "$tag_refs" \
        | sed -n "s#^\([0-9a-f][0-9a-f]*\)[[:space:]]refs/tags/${latest_tag}\$#\1#p" \
        | head -1
    )
  fi

  echo "${action} latest ${latest_tag} (${latest_sha}) in ${workflow}"

  if ! awk -v action="$action" -v expected="$latest_sha" '
    $0 ~ "uses: " action "@" {
      found += 1
      value = $0
      sub(".*@", "", value)
      sub(/[[:space:]].*/, "", value)
      if (value != expected) {
        invalid = 1
      }
    }
    END { exit(found == 0 || invalid != 0) }
  ' "$workflow"; then
    echo "${workflow}: one or more ${action} uses are missing or not pinned to ${latest_sha}" >&2
    exit 1
  fi

  if ! awk -v action="$action" -v expected="$latest_tag" '
    $0 ~ "# " action " v" {
      found += 1
      value = ""
      for (field = 1; field <= NF; field += 1) {
        if ($field ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/) {
          value = $field
        }
      }
      if (value != expected) {
        invalid = 1
      }
    }
    END { exit(found == 0 || invalid != 0) }
  ' "$workflow"; then
    echo "${workflow}: one or more ${action} comments do not name ${latest_tag}" >&2
    exit 1
  fi
}

echo "checking pinned GitHub Actions"
check_github_action_pin actions/checkout https://github.com/actions/checkout.git 7 .github/workflows/ci.yml
check_github_action_pin Swatinem/rust-cache https://github.com/Swatinem/rust-cache.git 2 .github/workflows/ci.yml
check_github_action_pin taiki-e/install-action https://github.com/taiki-e/install-action.git 2 .github/workflows/ci.yml
check_github_action_pin actions/checkout https://github.com/actions/checkout.git 7 .github/workflows/openbao-compatibility.yml
check_github_action_pin actions/upload-artifact https://github.com/actions/upload-artifact.git 7 .github/workflows/openbao-compatibility.yml
check_github_action_pin actions/download-artifact https://github.com/actions/download-artifact.git 8 .github/workflows/openbao-compatibility.yml
