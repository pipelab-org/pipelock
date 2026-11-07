#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

# Install traps before any setup command. Cancellation survives until either
# pre-launch cleanup or forwarding to the known harness PID.
harness_pid=""
pending_signal=""
interrupted=0
forward_signal() {
  pending_signal="$1"
  interrupted=$((interrupted + 1))
  if [[ -n "$harness_pid" ]]; then
    kill -s "$1" "$harness_pid" 2>/dev/null || true
  fi
}
exit_if_cancelled() {
  case "$pending_signal" in
    TERM) exit 143 ;;
    INT) exit 130 ;;
  esac
}
trap 'forward_signal TERM' TERM
trap 'forward_signal INT' INT

repo=$(cd "$(dirname "$0")/../.." && pwd)
make -C "$repo" build || { exit_if_cancelled; exit 4; }
exit_if_cancelled
cd "$repo"
lock_args=()
if [[ -n ${RECEIPT_LOAD_LOCK:-} ]]; then
  lock_args=(--lock-file "$RECEIPT_LOAD_LOCK")
fi
restart_args=()
if [[ -n ${RECEIPT_LOAD_RESTART_AFTER:-} ]]; then
  restart_args=(--restart-after "$RECEIPT_LOAD_RESTART_AFTER")
fi
verify_args=()
if [[ -n ${RECEIPT_LOAD_VERIFY_TIMEOUT:-} ]]; then
  verify_args=(--verify-timeout "$RECEIPT_LOAD_VERIFY_TIMEOUT")
fi
# go run collapses every program failure to 1. Execute the built harness so
# callers receive integrity=1, usage=2, performance=3, or harness error=4.
scratch=""
trap 'if [[ -n "$scratch" ]]; then rm -rf "$scratch"; fi' EXIT
scratch=$(mktemp -d "${TMPDIR:-/tmp}/receipt-load.XXXXXX") || { exit_if_cancelled; exit 4; }
exit_if_cancelled
go build -o "$scratch/receipt-load" ./scripts/receipt-load || { exit_if_cancelled; exit 4; }
exit_if_cancelled
"$scratch/receipt-load" --binary "$repo/pipelock" --out "$1" \
  --requests "${RECEIPT_LOAD_REQUESTS:-1000000}" \
  --warmup "${RECEIPT_LOAD_WARMUP:-1000}" \
  --concurrency "${RECEIPT_LOAD_CONCURRENCY:-128}" \
  --chains "${RECEIPT_LOAD_CHAINS:-1}" \
  --destinations "${RECEIPT_LOAD_DESTINATIONS:-single}" \
  --modes "${RECEIPT_LOAD_MODES:-off,best,required}" \
  --rules "${RECEIPT_LOAD_RULES:-empty}" \
  --seed "${RECEIPT_LOAD_SEED:-1}" \
  --window "${RECEIPT_LOAD_WINDOW:-5s}" \
  ${lock_args[@]+"${lock_args[@]}"} ${restart_args[@]+"${restart_args[@]}"} ${verify_args[@]+"${verify_args[@]}"} &
harness_pid=$!
# A signal between the pre-launch check and PID assignment is still pending.
if [[ -n "$pending_signal" ]]; then
  kill -s "$pending_signal" "$harness_pid" 2>/dev/null || true
fi
# A trapped signal interrupts wait before the child finishes. Repeat the wait
# until the child has exited so reports and child cleanup finish before scratch.
while true; do
  status=0
  observed_signals=$interrupted
  wait "$harness_pid" || status=$?
  if ((interrupted == observed_signals)); then
    break
  fi
done
exit "$status"
