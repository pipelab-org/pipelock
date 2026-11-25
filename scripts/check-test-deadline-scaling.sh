#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Refuse a NEW unscaled deadline in a test that waits on a subprocess.
#
# internal/testwait.Deadline multiplies a wait by four when CI is set, because
# a shared runner under load is slower than a developer laptop by roughly that
# much. A test that waits on a subprocess with a raw duration therefore runs at
# 1x on the machine that needs the headroom most. When that clock expires first
# it kills exec.CommandContext, the child dies, and the failure surfaces as an
# assertion rather than as the timeout it actually is: the MCP sandbox environ
# proof reported "exit status 10", which is ExitSubprocess, and read as a
# broken security property rather than a starved runner.
#
# This class was already fixed once, on 2026-09-06, in three teardown waits.
# Nothing stopped it regrowing, and by 2026-09-22 the repository held 439 raw
# time.After waits and 184 raw context.WithTimeout calls against 17 uses of the
# helper, with main red from one of them. A mechanism that is adopted and then
# forgotten needs a guard or it decays back.
#
# SCOPE IS DELIBERATELY NARROW. It covers only test files that start a
# subprocess, because those are the waits whose failure mode is a killed child
# and a misleading assertion. A sub-second wait is exempt everywhere: in this
# codebase those are poll ticks inside a loop, and scaling a tick slows the
# loop without making anything more reliable. Widening this to every wait in
# every test would flag hundreds of legitimate lines, and an over-strict guard
# gets deleted rather than obeyed.
#
# A second rule, enforced by scripts/deadlinescaling, covers every tracked
# *_test.go file except internal/testwait (the helper's own tests). It flags
# only a select receive from time.After, from an identifier assigned from
# time.After in the same function, or from a time.NewTimer channel, when that
# case body fails the test. Expiry there is the test result, so a raw duration
# turns runner load into a red build. A poll tick, an absence check, and a
# receive whose case does not fail the test are not flagged at any duration.
# That is why this does not widen the subprocess rule into the over-strict
# scan the paragraph above refuses: those waits stay legal, and the regex
# checks below are unchanged.
#
# The forms below are the ones that appear in this tree. Extend the list rather
# than adding a second pattern beside it.
#   context.WithTimeout(parent, 30*time.Second)
#   context.WithTimeout(parent, time.Minute)
#   context.WithTimeout(parent, time.Hour)
#   <-time.After(5 * time.Second)
#   <-time.After(time.Second)
#   context.WithTimeout(parent, 1500*time.Millisecond)
#
# A deadline written in milliseconds is still a deadline once it reaches a
# second, so the millisecond form is matched from 1000 upward and left alone
# below that. Forms this still does NOT see, because they need a Go parser
# rather than a line matcher: a named constant such as seccompChildTimeout, a
# duration built by arithmetic, and a call split across lines. Those are
# recorded here rather than implied to be covered.

set -euo pipefail

cd "$(dirname "$0")/.."

violations=0
scanned=0
file_list=$(mktemp)
analyzer_dir=$(mktemp -d)
trap 'rm -f "$file_list"; rm -rf "$analyzer_dir"' EXIT

# git ls-files quotes a path containing a newline, so a file could otherwise be
# skipped in silence. -z keeps the names intact.
if ! git ls-files -z 'internal/**/*_test.go' >"$file_list"; then
	echo "check-test-deadline-scaling: could not enumerate tracked test files" >&2
	exit 1
fi

if [ ! -s "$file_list" ]; then
	echo "check-test-deadline-scaling: no tracked internal test files found; refusing to pass" >&2
	exit 1
fi

while IFS= read -r -d '' file; do
	if [ ! -f "$file" ] || [ ! -r "$file" ]; then
		printf 'check-test-deadline-scaling: cannot read tracked test file: %s\n' "$file" >&2
		exit 1
	fi
	grep -q 'exec\.CommandContext' "$file" || continue
	scanned=$((scanned + 1))

	# A deadline of a second or more, not already wrapped in the helper.
	matches=$(grep -nE '(<-time\.After\(|context\.WithTimeout\([^,]+,)[[:space:]]*\(?([0-9]+[[:space:]]*\*[[:space:]]*)?time\.(Second|Minute|Hour)' "$file" || true)

	# Milliseconds of a second or more. Written separately because the bound is
	# on the NUMBER here, not on the unit: four or more digits, or a leading
	# digit followed by three, is >= 1000ms.
	ms=$(grep -nE '(<-time\.After\(|context\.WithTimeout\([^,]+,)[[:space:]]*\(?[0-9]{4,}[[:space:]]*\*[[:space:]]*time\.Millisecond' "$file" || true)
	if [ -n "$ms" ]; then
		matches=$(printf '%s\n%s' "$matches" "$ms" | grep -v '^$' || true)
	fi

	if [ -n "$matches" ]; then
		while IFS= read -r line; do
			printf '%s:%s\n' "$file" "$line"
			violations=$((violations + 1))
	done <<<"$matches"
	fi
done <"$file_list"

if [ "$scanned" -eq 0 ]; then
	echo "check-test-deadline-scaling: no subprocess test files found; refusing to pass" >&2
	exit 1
fi

if [ "$violations" -gt 0 ]; then
	cat >&2 <<'MSG'

Unscaled deadline in a test that starts a subprocess.

Wrap the duration in the helper so a loaded CI runner gets four times the
budget, which is the difference between a real failure and a starved one:

    context.WithTimeout(ctx, testwait.Deadline(30*time.Second))
    case <-time.After(testwait.Deadline(5 * time.Second)):

    import "github.com/luckyPipewrench/pipelock/internal/testwait"

A wait under one second is a poll tick and is not flagged. If this fires on a
wait that must stay unscaled, say why in a comment on the line and widen the
grep here rather than removing the check.
MSG
	exit 1
fi

# Select waits whose expiry fails the test. The regex above stays as it is.
# This pass is every tracked test file, not only subprocess tests, because the
# failure mode is a red test rather than a killed child. internal/testwait is
# the helper under test and is excluded. Poll ticks and absence checks have no
# failing call in the timer case, so the analyzer leaves them alone.
if [[ ! -f scripts/deadlinescaling/main.go ]]; then
	echo "check-test-deadline-scaling: the failing-wait analyzer (scripts/deadlinescaling) is missing." >&2
	echo "The deadline gate must fail closed when it cannot scan." >&2
	exit 2
fi
if ! command -v go >/dev/null 2>&1; then
	echo "check-test-deadline-scaling: go is not on PATH; cannot run the failing-wait analyzer." >&2
	echo "The deadline gate must fail closed when it cannot scan." >&2
	exit 127
fi
all_list="$analyzer_dir/files"
if ! git ls-files -z -- '*_test.go' >"$all_list"; then
	echo "check-test-deadline-scaling: could not enumerate tracked test files for the failing-wait scan" >&2
	exit 1
fi
fail_files=()
while IFS= read -r -d '' file; do
	case "$file" in
	internal/testwait | internal/testwait/*) continue ;;
	esac
	if [[ ! -f "$file" || ! -r "$file" ]]; then
		printf 'check-test-deadline-scaling: cannot read tracked test file: %s\n' "$file" >&2
		exit 1
	fi
	fail_files+=("$file")
done <"$all_list"
if [[ ${#fail_files[@]} -eq 0 ]]; then
	echo "check-test-deadline-scaling: no tracked test files found; refusing to pass" >&2
	exit 1
fi
# Build first: go run reports every non-zero exit as 1, which would hide the
# analyzer's distinct scan-error status.
if ! go build -o "$analyzer_dir/deadlinescaling" ./scripts/deadlinescaling; then
	echo "check-test-deadline-scaling: cannot build the failing-wait analyzer." >&2
	echo "The deadline gate must fail closed when it cannot scan." >&2
	exit 2
fi
set +e
fail_out="$("$analyzer_dir/deadlinescaling" "${fail_files[@]}")"
fail_rc=$?
set -e
if [[ "$fail_rc" -gt 1 ]]; then
	echo "check-test-deadline-scaling: failing-wait analyzer exited with $fail_rc." >&2
	printf '%s\n' "$fail_out" >&2
	echo "The deadline gate must fail closed on scan errors, not pass with zero scans." >&2
	exit "$fail_rc"
fi
if [[ -n "$fail_out" ]]; then
	cat >&2 <<'MSG'

Unscaled failing wait. The timer case fails the test, so a loaded CI runner
needs the same four-times headroom Deadline already applies. Poll ticks and
absence checks are not this pattern and are not flagged.

    case <-time.After(testwait.Deadline(5 * time.Second)):
    case <-timer.C: // timer := time.NewTimer(testwait.Deadline(5 * time.Second))

    import "github.com/luckyPipewrench/pipelock/internal/testwait"

MSG
	printf '%s\n' "$fail_out" >&2
	exit 1
fi

printf 'check-test-deadline-scaling: %d subprocess test file(s) scanned, no unscaled deadlines\n' "$scanned"
printf 'check-test-deadline-scaling: %d test file(s) scanned, no unscaled failing waits\n' "${#fail_files[@]}"
