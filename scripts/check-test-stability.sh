#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Tripwire: forbid known flaky-test root causes (fixed wall-clock sleeps, fixed
# local ports, and port retry callbacks that cannot retry) from re-entering the
# test suite. Runs in CI and via
# `make lint`, so it must FAIL CLOSED: a runner that cannot actually scan has
# to error loudly, never report "clean" by scanning nothing.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Include tracked and new, non-ignored tests in every directory. Keep filenames
# NUL-delimited so spaces cannot split a path into separate search arguments.
test_list=$(mktemp)
trap 'rm -f "$test_list"' EXIT
if ! git ls-files -z --cached --others --exclude-standard -- '*_test.go' >"$test_list"; then
  echo "check-test-stability: cannot discover Go tests." >&2
  exit 2
fi
# Avoid mapfile so discovery also works with older Bash installations.
test_files=()
while IFS= read -r -d '' test_file; do
  test_files+=("$test_file")
done <"$test_list"
if [[ ${#test_files[@]} -eq 0 ]]; then
  echo "check-test-stability: no Go tests found; refusing an empty scan." >&2
  exit 2
fi

allowlist="scripts/test-stability-allowlist.txt"
status=0

filter_allowlist() {
  if [[ -f "$allowlist" ]]; then
    grep -F -x -v -f <(grep -vE '^[[:space:]]*(#|$)' "$allowlist") || true
  else
    cat
  fi
}

# scan runs a real recursive search and leaves the allowlist-filtered matches in
# scan_result. It distinguishes "no matches" (exit 1, clean) from a real search
# error and exits the whole script on the latter — `|| true` alone would mask
# errors as clean, the fail-open trap this gate exists to prevent.
scan_result=""
scan() {
  local pattern out rc
  pattern="$1"
  set +e
  if command -v rg >/dev/null 2>&1; then
    out="$(rg -nH -- "$pattern" "${test_files[@]}")"
  elif command -v grep >/dev/null 2>&1; then
    out="$(grep -nHE -- "$pattern" "${test_files[@]}")"
  else
    echo "check-test-stability: neither ripgrep (rg) nor grep is on PATH." >&2
    echo "The stability gate must fail closed when it cannot scan." >&2
    exit 127
  fi
  rc=$?
  set -e
  if [[ "$rc" -gt 1 ]]; then
    echo "check-test-stability: search exited with $rc while scanning for: $pattern" >&2
    echo "If a tracked test was intentionally removed, stage its deletion before rerunning." >&2
    echo "The stability gate must fail closed on scan errors, not pass with zero scans." >&2
    exit "$rc"
  fi
  scan_result="$(printf '%s' "$out" | filter_allowlist)"
}

scan 'time\.Sleep\('
if [[ -n "$scan_result" ]]; then
  echo "check-test-stability: time.Sleep is forbidden in tests; use testwait, channels, or a fake clock." >&2
  echo "$scan_result" >&2
  status=1
fi

scan 'Listen(Context)?\([^)]*"(tcp|tcp4|tcp6)"[^)]*"(127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\]|:)[^"]*:[1-9][0-9]*"'
if [[ -n "$scan_result" ]]; then
  echo "check-test-stability: fixed local ports in test Listen calls are forbidden; bind :0 and read back the assigned address." >&2
  echo "$scan_result" >&2
  status=1
fi

# A test-ending call on a run-exit path, or a test server the readiness wait
# does not exclude, inside a testport.WithRetry callback turns a lost port race
# into a failed run instead of a retry. The analyzer parses the same file list.
# It ships in this tree; only a copy of this script without it skips the check.
if [[ -f scripts/teststability/main.go ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "check-test-stability: go is not on PATH; cannot run the port retry analyzer." >&2
    echo "The stability gate must fail closed when it cannot scan." >&2
    exit 127
  fi
  retry_dir=$(mktemp -d)
  retry_err="$retry_dir/stderr"
  trap 'rm -f "$test_list"; rm -rf "$retry_dir"' EXIT
  # Build first: go run reports every non-zero exit as 1, which would hide the
  # analyzer's distinct scan-error status.
  if ! go build -o "$retry_dir/teststability" ./scripts/teststability; then
    echo "check-test-stability: cannot build the port retry analyzer." >&2
    echo "The stability gate must fail closed when it cannot scan." >&2
    exit 2
  fi
  set +e
  retry_out="$("$retry_dir/teststability" "${test_files[@]}" 2>"$retry_err")"
  rc=$?
  set -e
  if [[ "$rc" -gt 1 ]]; then
    echo "check-test-stability: port retry analyzer exited with $rc." >&2
    cat "$retry_err" >&2
    echo "The stability gate must fail closed on scan errors, not pass with zero scans." >&2
    exit "$rc"
  fi
  retry_result="$(printf '%s' "$retry_out" | filter_allowlist)"
  if [[ -n "$retry_result" ]]; then
    echo "check-test-stability: testport.WithRetry callbacks must return run errors and exclude their own test servers so a port collision retries; see scripts/teststability." >&2
    echo "$retry_result" >&2
    echo "Details:" >&2
    cat "$retry_err" >&2
    status=1
  fi
fi

exit "$status"
