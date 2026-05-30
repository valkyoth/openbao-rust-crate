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
cargo search tokio --limit 1
cargo search zeroize --limit 1

echo "checking OpenBao latest GitHub release"
curl -s https://api.github.com/repos/openbao/openbao/releases/latest \
  | sed -n 's/.*"tag_name": "\(v[^"]*\)".*/latest OpenBao release: \1/p' \
  | head -1
