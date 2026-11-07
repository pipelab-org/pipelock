#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

repo=$(cd "$(dirname "$0")/../.." && pwd)
make -C "$repo" build || exit 4
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
scratch=$(mktemp -d "${TMPDIR:-/tmp}/receipt-load.XXXXXX") || exit 4
trap 'rm -rf "$scratch"' EXIT
go build -o "$scratch/receipt-load" ./scripts/receipt-load || exit 4
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
  ${lock_args[@]+"${lock_args[@]}"} ${restart_args[@]+"${restart_args[@]}"} ${verify_args[@]+"${verify_args[@]}"}
