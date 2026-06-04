#!/usr/bin/env sh
set -eu

echo "latest rustc in use:"
rustc --version

echo "checking current crates.io versions used by this crate"
cargo search reqwest --limit 1
cargo search base64-ng --limit 1
cargo search secrecy --limit 1
cargo search serde --limit 1
cargo search serde_json --limit 1
cargo search time --limit 1
cargo search tokio --limit 1
cargo search zeroize --limit 1

echo "checking OpenBao latest GitHub release"
curl -s https://api.github.com/repos/openbao/openbao/releases/latest \
  | sed -n 's/.*"tag_name": "\(v[^"]*\)".*/latest OpenBao release: \1/p' \
  | head -1

check_github_action_pin() {
  action=$1
  repo=$2
  major=$3
  workflow=.github/workflows/ci.yml

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

  actual_sha=$(
    awk -v action="$action" '
      $0 ~ "uses: " action "@" {
        sub(".*@", "", $0);
        sub(/[[:space:]].*/, "", $0);
        print;
        exit;
      }
    ' "$workflow"
  )
  comment_tag=$(
    awk -v action="$action" '
      $0 ~ "# " action " v" {
        for (field = 1; field <= NF; field += 1) {
          if ($field ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/) {
            print $field;
            exit;
          }
        }
      }
    ' "$workflow"
  )

  echo "${action} latest ${latest_tag} (${latest_sha})"

  if [ "$comment_tag" != "$latest_tag" ]; then
    echo "${workflow}: ${action} comment is ${comment_tag:-missing}, expected ${latest_tag}" >&2
    exit 1
  fi

  if [ "$actual_sha" != "$latest_sha" ]; then
    echo "${workflow}: ${action} pin is ${actual_sha:-missing}, expected ${latest_sha} for ${latest_tag}" >&2
    exit 1
  fi
}

echo "checking pinned GitHub Actions"
check_github_action_pin actions/checkout https://github.com/actions/checkout.git 6
check_github_action_pin Swatinem/rust-cache https://github.com/Swatinem/rust-cache.git 2
check_github_action_pin taiki-e/install-action https://github.com/taiki-e/install-action.git 2
