#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Runs the receipt-load harness across CPU quotas and receipt chain counts and
# writes summary.csv. Every cell warms up inside the same proxy process that it
# then measures, so no separate warmup process or cell exists.
#
# Optional environment:
#   RECEIPT_LOAD_PROFILE full (default) or release (24 results; fixed counts)
#   RECEIPT_LOAD_MODES   comma-separated modes (default off,best,required)
#   RECEIPT_LOAD_RULES   "empty" (default) or a directory of rule bundles
#   RECEIPT_LOAD_SEED    workload seed (default 1)
#   RECEIPT_LOAD_WINDOW  per-window rate width (default 5s)
#   RECEIPT_LOAD_RESTART_AFTER  restart once after N measured requests (default disabled)
#   RECEIPT_LOAD_VERIFY_TIMEOUT  per-cell receipt verification limit (default: receipt-load's)
#   RECEIPT_LOAD_LOCK    advisory lock file that serializes cells on one machine
set -euo pipefail

if [[ $# -lt 3 || $# -gt 5 ]]; then
  echo "usage: $0 PIPELOCK_BINARY RECEIPT_LOAD_BINARY NEW_OUTPUT_DIRECTORY [REQUESTS=20000] [SAMPLES=3]" >&2
  exit 2
fi

pipelock=$1
load=$2
out=$3
requests=${4:-20000}
samples=${5:-3}
profile=${RECEIPT_LOAD_PROFILE:-full}
modes=${RECEIPT_LOAD_MODES:-off,best,required}
rules=${RECEIPT_LOAD_RULES:-empty}
seed=${RECEIPT_LOAD_SEED:-1}
window=${RECEIPT_LOAD_WINDOW:-5s}
lock=${RECEIPT_LOAD_LOCK:-}
if [[ ! -x $pipelock || ! -x $load || -e $out || ! $requests =~ ^[1-9][0-9]*$ || ! $samples =~ ^[1-9][0-9]*$ || ! $seed =~ ^[0-9]+$ ]]; then
  echo "binaries must be executable, output must be new, requests/samples must be positive integers, and the seed must be a non-negative integer" >&2
  exit 2
fi
case "$profile" in
  full) chain_list=(1 2 4 8); chain_csv=1,2,4,8 ;;
  release)
    if [[ $requests != 20000 || $samples != 3 || $modes != off,best,required ]]; then
      echo "release profile requires 20000 requests, 3 samples and modes off,best,required" >&2
      exit 2
    fi
    chain_list=(1 8)
    chain_csv=1,8
    ;;
  *) echo "unknown receipt-load profile: $profile" >&2; exit 2 ;;
esac
if ! command -v systemd-run >/dev/null; then
  echo "systemd-run is required" >&2
  exit 2
fi

mkdir -p "$out"
printf '%s\n' "$profile" >"$out/profile"
runtime_dir=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
bus=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$runtime_dir/bus}
warmup_requests=$requests
if ((warmup_requests > 1000)); then
  warmup_requests=1000
fi

# Exit codes 1 (integrity), 2 (usage), 3 (performance), and 4 (harness)
# all fail a cell; scope.exit retains the exact status. A cell that fails
# integrity, performance, or harness setup still has a result.json worth
# keeping, so a failing cell is recorded and the matrix carries on. The script
# exits non-zero at the end if any cell failed.
failed=0

run_cell() {
  local cell=$1
  mkdir -p "$cell"
  local lock_args=()
  if [[ -n $lock ]]; then
    lock_args=(--lock-file "$lock")
  fi
  local restart_args=()
  if [[ -n ${RECEIPT_LOAD_RESTART_AFTER:-} ]]; then
    restart_args=(--restart-after "$RECEIPT_LOAD_RESTART_AFTER")
  fi
  local verify_args=()
  if [[ -n ${RECEIPT_LOAD_VERIFY_TIMEOUT:-} ]]; then
    verify_args=(--verify-timeout "$RECEIPT_LOAD_VERIFY_TIMEOUT")
  fi
  local scope_status=0
  if /usr/bin/env XDG_RUNTIME_DIR="$runtime_dir" DBUS_SESSION_BUS_ADDRESS="$bus" \
    systemd-run --user --scope -p "CPUQuota=$((cores*100))%" \
    /usr/bin/env GOMAXPROCS="$cores" "$load" \
    --binary "$pipelock" --out "$cell" --requests "$requests" --warmup "$warmup_requests" \
    --concurrency 128 --modes "$cell_modes" --chains "$chains" \
    --rules "$rules" --seed "$seed" --window "$window" ${lock_args[@]+"${lock_args[@]}"} ${restart_args[@]+"${restart_args[@]}"} \
    ${verify_args[@]+"${verify_args[@]}"} >"$cell/scope.log" 2>&1; then
    scope_status=0
  else
    scope_status=$?
    echo "cell $cell failed; see $cell/scope.log" >&2
    tail -n 20 "$cell/scope.log" >&2 || true
    failed=1
  fi
  printf '%s\n' "$scope_status" >"$cell/scope.exit"
}

for cores in 2 4 8; do
  for chains in "${chain_list[@]}"; do
    for ((sample=1; sample<=samples; sample++)); do
      cell_modes=$modes
      if [[ $profile == release ]]; then
        cell_modes=required
        if ((sample == 1)); then
          if ((chains == 1)); then cell_modes=off,required; else cell_modes=best,required; fi
        fi
      fi
      run_cell "$out/cpu-$cores/chains-$chains/sample-$sample"
    done
  done
done

# summary.csv is written by the harness binary so the aggregation is tested
# with the rest of it. A cell without a readable result.json counts as failed.
"$load" summarize --profile "$profile" --root "$out" --samples "$samples" --modes "$modes" --cpus 2,4,8 --chains "$chain_csv"
exit "$failed"
