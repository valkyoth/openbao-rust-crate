#!/usr/bin/env sh
set -eu

rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt
rustup toolchain install 1.90.0 --profile minimal
rustup default 1.97.1
rustup show
