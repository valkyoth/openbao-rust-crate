#!/usr/bin/env sh
set -eu

rustup toolchain install 1.98.1 --profile minimal --component clippy --component rustfmt
rustup toolchain install 1.90.0 --profile minimal
rustup default 1.98.1
rustup show
