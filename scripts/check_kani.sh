#!/usr/bin/env sh
set -eu

if [ ! -d kani ]; then
    echo "Kani checks: skipping; kani/ is not present"
    exit 0
fi

kani_toolchain="${OPENBAO_KANI_TOOLCHAIN:-1.90.0-x86_64-unknown-linux-gnu}"

if ! rustup toolchain list | grep -q "^$kani_toolchain"; then
    echo "Kani checks: skipping; Rust toolchain $kani_toolchain is not installed"
    exit 0
fi

cargo_kani() {
    rustup run "$kani_toolchain" cargo kani "$@"
}

if ! cargo_kani --version >/dev/null 2>&1; then
    echo "Kani checks: skipping; cargo kani is not installed"
    exit 0
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

echo "Kani checks: using Rust toolchain $kani_toolchain"

run_kani() {
    name="$1"
    shift
    echo "Kani checks: $name"
    if cargo_kani "$@" >"$log" 2>&1; then
        cat "$log"
    else
        status="$?"
        if grep -q "Kani Rust Verifier" "$log" && grep -q "requires rustc" "$log"; then
            echo "Kani checks: skipping; installed Kani compiler is older than this crate's rust-version"
            exit 0
        fi
        cat "$log"
        exit "$status"
    fi
}

common_args="--no-default-features --features rustls-tls,kani --output-format terse"

run_kani "codegen" $common_args --only-codegen
run_kani "closed version interval" $common_args --harness closed_version_interval_matches_ordering
run_kani "capability interval selection" $common_args --harness capability_selection_never_escapes_selected_interval
run_kani "root-generation profile ranges" $common_args --harness root_generation_profile_ranges_never_overlap
run_kani "path forbidden byte helper" $common_args --harness path_forbidden_byte_helper_matches_documented_policy
run_kani "duration component single digits" $common_args --harness duration_component_parser_accepts_single_digits
run_kani "duration component two digits" $common_args --harness duration_component_parser_accepts_two_digits
run_kani "duration component non-digits" $common_args --harness duration_component_parser_rejects_non_digits
run_kani "duration component empty input" $common_args --harness duration_component_parser_rejects_empty_input
run_kani "duration parser examples" $common_args --harness duration_parser_accepts_documented_examples
