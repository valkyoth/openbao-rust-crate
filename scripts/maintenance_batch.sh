#!/usr/bin/env bash
# Collect local maintenance checks and outstanding SDK fixtures. Never retain,
# promote or publish evidence automatically.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$(pwd -P)
if (( EUID == 0 )); then echo "Run as the workspace owner, without sudo." >&2; exit 2; fi
if (( $# == 0 )) || [[ $# == 1 && ( $1 == --plan || $1 == --full || $1 == --control-groups ) ]]; then
  exec /usr/bin/python3 -E -s -S -B scripts/maintenance_checks.py "$@"
fi
case "$#:${1-}" in
  1:--prior-patch-sdk|1:--remaining-sdk|1:--maintenance-normal|1:--maintenance-core|1:--maintenance-patches|1:--release-refresh) ;;
  *) echo "Usage: bash scripts/maintenance_batch.sh [--plan|--full|--control-groups|--prior-patch-sdk|--remaining-sdk|--maintenance-normal|--maintenance-core|--maintenance-patches|--release-refresh]" >&2; exit 2 ;;
esac
# mktemp creates a private directory. Do not change the umask inherited by fixtures.
dir=$(mktemp -d /tmp/openbao-maintenance-batch-XXXXXXXX)
summary=$dir/summary.tsv
printf 'Results: %s\n' "$dir"
printf 'status\tstep\texit_code\n' > "$summary"
failed=0
record() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" | tee -a "$summary"
  if [[ $1 != PASS ]]; then failed=1; fi
}
step() {
  local label=$1 rc
  shift
  printf 'Running %s\n' "$label"
  if "$@" > "$dir/$label.log" 2>&1; then record PASS "$label" 0; return 0; else rc=$?; record FAIL "$label" "$rc"; return "$rc"; fi
}

py=(/usr/bin/python3 -E -s -S -B)
sdk_job() {
  local label=$1 builder=$2 runner=$3 mode=$4 build_flag=$5
  shift 5
  local -a flags=()
  [[ $mode != normal ]] || flags+=(--normal)
  if ! step "$label-build" "${py[@]}" "scripts/$builder.py" "$build_flag" "${flags[@]}"; then
    record BLOCKED "$label-live" -
    return
  fi
  local dest
  if ! dest=$(stage_binary "$label" "$mode"); then record FAIL "$label-artifact" -; return; fi
  step "$label-live" sudo "${py[@]}" "scripts/$runner.py" "${flags[@]}" --test-binary "$dest" "$@" || :
}

stage_binary() {
  local label=$1 mode=$2 target=$root/target binary hash dest
  [[ $mode == normal ]] || target+=/candidate-sdk
  # Builders emit either a bare executable path or a labelled path.
  local -a paths
  mapfile -t paths < <(sed -nE 's/^(.*binary: )?(\/.*\/openbao-[0-9a-f]{16})$/\2/p' "$dir/$label-build.log")
  if (( ${#paths[@]} != 1 )); then return 1; fi
  binary=${paths[0]}
  if [[ ! -f $binary || ! -O $binary || ! -x $binary || $(realpath -e "$binary") != "$binary" ||
        $binary != "$target/debug/"* ]]; then return 1; fi
  hash=$(sha256sum "$binary") || return 1
  hash=${hash%% *}
  dest=$target/debug/deps/openbao-${hash:0:16}
  if [[ ! -e $dest ]]; then
    ln -- "$binary" "$dest" || return 1
  fi
  if [[ -L $dest || ! -O $dest ]] || ! printf '%s  %s\n' "$hash" "$dest" | sha256sum -c - >&2; then
    return 1
  fi
  printf '%s\n' "$dest"
}

maintenance_pair() {
  local mode=$1 label=maintenance-$1 version dest
  local -a runner=("${py[@]}" scripts/openbao_maintenance_sdk.py)
  [[ $mode != normal ]] || runner+=(--normal)
  if step "$label-build" "${runner[@]}" --build; then
    if ! dest=$(stage_binary "$label" "$mode"); then record FAIL "$label-artifact" -; dest=; fi
  else
    dest=
  fi
  for version in 2.6.6 2.7.3; do
    if [[ -z $dest ]]; then record BLOCKED "$version-$mode-live" -; continue; fi
    step "$version-$mode-live" sudo "${runner[@]}" --version "$version" --test-binary "$dest" || :
  done
}

initial_checks() {
step released-evidence "${py[@]}" scripts/check_released_evidence.py || :
step python-verifiers "${py[@]}" -m unittest discover -s scripts -p 'test_*.py' -q || :
if ! step release-checks bash scripts/checks.sh; then
  # checks.sh is intentionally fail-fast. Still capture independent results.
  step rust-tests cargo test --locked --all-features || :
  step clippy cargo clippy --locked --all-targets --all-features -- -D warnings || :
  step dependency-policy cargo deny check || :
fi
sdk_job 270-backup-candidate check_openbao_2_7_candidate_sdk openbao_2_7_backup_sdk candidate --build-backup-test --strict-candidate
}

patch_refresh() {
  local suite
  maintenance_pair normal
  maintenance_pair candidate
  sdk_job 273-advanced-candidate openbao_2_7_3_sdk_advanced openbao_2_7_3_sdk_advanced candidate --build
  sdk_job 273-plugin-candidate openbao_2_7_3_plugin_sdk openbao_2_7_3_plugin_sdk candidate --build \
    --acknowledge-unsigned-directory-image --acknowledge-unsigned-radius-image
  for suite in external-keys transit pki workflow-cas system mfa-totp; do
    step "273-$suite" sudo "${py[@]}" scripts/openbao_2_7_3_regressions.py --suite "$suite" || :
  done
  step 273-backups sudo "${py[@]}" scripts/openbao_2_7_3_backups.py || :
  step 273-backup-upgrade sudo "${py[@]}" scripts/openbao_2_7_3_backup_upgrade.py || :
}

patch_sdk_jobs() {
  local mode suite
  for mode in normal candidate; do
    for suite in "$@"; do
      sdk_job "$suite-$mode" "openbao_$suite" "openbao_$suite" "$mode" --build
    done
  done
}

remaining_sdk() {
  patch_sdk_jobs 2_6_5_sdk 2_7_2_sdk 2_7_1_sdk_advanced 2_7_2_sdk_advanced
}

current_ci_live() {
  sudo "${py[@]}" scripts/openbao_current_ci.py --version "$1" --test-binary "$2" > "$dir/ci-$1.json"
}

current_ci_refresh() {
  local version binary=
  if step current-ci-build "${py[@]}" scripts/openbao_current_ci.py --build; then
    local -a paths
    mapfile -t paths < <(sed -n 's/^Current-profile CI test binary: //p' "$dir/current-ci-build.log")
    if (( ${#paths[@]} == 1 )) && [[ ${paths[0]%/*} == "$root/target/debug/deps" &&
          ${paths[0]##*/} =~ ^openbao_integration-[0-9a-f]{16}$ ]]; then
      binary=${paths[0]}
    else
      record FAIL current-ci-artifact -
    fi
  fi
  for version in 2.6.4 2.6.5 2.6.6 2.7.0 2.7.1 2.7.2 2.7.3; do
    if [[ -z $binary ]]; then record BLOCKED "ci-$version" -; continue; fi
    step "ci-$version" current_ci_live "$version" "$binary" || :
  done
}

prior_refresh() {
  local suite patch plugin version dest
  local -a args
  for suite in workflow_cas system_behavior mfa_totp raw_backup recovery_backup backup_upgrade; do
    step "270-$suite" sudo "${py[@]}" "scripts/openbao_2_7_$suite.py" || :
  done
  for patch in 1 2; do
    for suite in api external-keys transit pki workflow-cas system mfa-totp; do
      step "27$patch-$suite" sudo "${py[@]}" "scripts/openbao_2_7_${patch}_regressions.py" --suite "$suite" || :
    done
    for suite in backups backup_upgrade consistency; do
      step "27$patch-$suite" sudo "${py[@]}" "scripts/openbao_2_7_${patch}_$suite.py" || :
    done
  done
  # The preceding normal advanced build includes the backup and consistency tests.
  dest=
  if [[ -f $dir/2_7_2_sdk_advanced-normal-build.log ]]; then
    dest=$(stage_binary 2_7_2_sdk_advanced-normal normal) || dest=
  fi
  for suite in consistency_sdk_lag backup_sdk backup_sdk-strict; do
    if [[ -z $dest ]]; then record BLOCKED "270-$suite" -; continue; fi
    args=()
    [[ $suite != backup_sdk-strict ]] || args+=(--strict)
    step "270-$suite" sudo "${py[@]}" "scripts/openbao_2_7_${suite%-strict}.py" --test-binary "$dest" "${args[@]}" || :
  done
  for plugin in ldap kerberos radius; do
    dest=
    if step "$plugin-normal-build" "${py[@]}" "scripts/openbao_${plugin}_sdk.py" --build --normal; then
      dest=$(stage_binary "$plugin-normal" normal) || record FAIL "$plugin-normal-artifact" -
    fi
    args=(--acknowledge-unsigned-directory-image)
    [[ $plugin != radius ]] || args+=(--acknowledge-unsigned-radius-image)
    for version in 2.7.0 2.7.1 2.7.2; do
      if [[ -z $dest ]]; then record BLOCKED "$version-$plugin-sdk" -; continue; fi
      step "$version-$plugin-sdk" sudo "${py[@]}" "scripts/openbao_${plugin}_sdk.py" \
        --normal --version "$version" --test-binary "$dest" "${args[@]}" || :
    done
  done
}

# Parse the complete run before starting any long-running command.
main() {
  git rev-parse HEAD > "$dir/commit.txt"
  git status --short > "$dir/worktree.txt"
  trap 'record INTERRUPTED batch -; exit 130' INT TERM HUP
  if [[ ${1-} == --release-refresh ]]; then
    current_ci_refresh
    remaining_sdk
    sdk_job 270-backup-candidate check_openbao_2_7_candidate_sdk openbao_2_7_backup_sdk candidate --build-backup-test --strict-candidate
    prior_refresh
    patch_refresh
  elif [[ ${1-} == --maintenance-normal ]]; then
    maintenance_pair normal
  elif [[ ${1-} == --maintenance-patches ]]; then
    patch_refresh
  elif [[ ${1-} == --maintenance-core ]]; then
    maintenance_pair normal
    maintenance_pair candidate
  elif [[ ${1-} == --prior-patch-sdk ]]; then
    patch_sdk_jobs 2_7_2_sdk 2_7_1_sdk_advanced 2_7_2_sdk_advanced
  elif [[ ${1-} == --remaining-sdk ]]; then
    printf 'Continuation only: earlier results remain in the original run directory.\n' | tee "$dir/scope.txt"
    remaining_sdk
    sdk_job 273-plugin-candidate openbao_2_7_3_plugin_sdk openbao_2_7_3_plugin_sdk candidate --build \
      --acknowledge-unsigned-directory-image --acknowledge-unsigned-radius-image
  else
    initial_checks
    remaining_sdk
    patch_refresh
  fi
  step diff-check git diff --check || :
  printf 'Finished; summary: %s\n' "$summary"
  return "$failed"
}
main "$@"
