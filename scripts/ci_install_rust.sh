#!/usr/bin/env sh
set -eu

rustup toolchain install 1.96.1 --profile minimal --component clippy --component rustfmt
rustup default 1.96.1
rustup show
