#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BENCH_BASELINE="${BENCH_BASELINE:-bench/scanner-baseline.txt}"
BENCH_BASELINE_DIR="${BENCH_BASELINE_DIR:-}"
BENCH_REGRESSION_THRESHOLD_PCT="${BENCH_REGRESSION_THRESHOLD_PCT:-50}"
BENCH_COUNT="${BENCH_COUNT:-6}"
BENCH_TIME="${BENCH_TIME:-100ms}"
DEFAULT_BENCH_PATTERN="."
BENCH_PATTERN="${BENCH_PATTERN:-$DEFAULT_BENCH_PATTERN}"
DEFAULT_BENCH_PACKAGES="./internal/scanner/ ./internal/mcp/"
BENCH_PACKAGES="${BENCH_PACKAGES:-$DEFAULT_BENCH_PACKAGES}"
BENCHSTAT_ALPHA="${BENCHSTAT_ALPHA:-1.0}"

export TMPDIR="${TMPDIR:-$HOME/.cache/pipelock-tmp}"
export GOTMPDIR="${GOTMPDIR:-$HOME/.cache/pipelock-tmp}"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"

read -r -a packages <<<"$BENCH_PACKAGES"

bench_cmd=(
	go test
	-bench="$BENCH_PATTERN"
	-benchmem
	-count="$BENCH_COUNT"
	-benchtime="$BENCH_TIME"
	-run='^$'
	"${packages[@]}"
)

benchstat_path() {
	if command -v benchstat >/dev/null 2>&1; then
		command -v benchstat
		return 0
	fi

	local gopath
	gopath="$(go env GOPATH 2>/dev/null || true)"
	if [[ -n "$gopath" && -x "$gopath/bin/benchstat" ]]; then
		printf '%s\n' "$gopath/bin/benchstat"
		return 0
	fi

	return 1
}

write_baseline() {
	local baseline_tmp
	baseline_tmp="$(mktemp "$TMPDIR/pipelock-bench-baseline.XXXXXX")"
	mkdir -p "$(dirname "$BENCH_BASELINE")"
	{
		printf '# Pipelock scanner/MCP benchmark baseline\n'
		printf '# Historical measurement; regenerate with `make bench-baseline`.\n'
		printf '# Generated: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf '# Machine: %s\n' "$(uname -srmo)"
		if [[ -r /proc/cpuinfo ]]; then
			awk -F': ' '/^model name[[:space:]]*:/ { print "# CPU: " $2; exit }' /proc/cpuinfo
		fi
		printf '# Go: %s\n' "$(go version)"
		printf '# Command:'
		printf ' %q' "${bench_cmd[@]}"
		printf '\n'
		"${bench_cmd[@]}"
	} >"$baseline_tmp"
	mv "$baseline_tmp" "$BENCH_BASELINE"
	printf 'bench-baseline: wrote %s\n' "$BENCH_BASELINE"
}

# Sourced by synthetic comparison tests; normal execution always captures a pair.
compare_measurements() (
	local baseline="$1" current="$2" capture_dir="$3" benchstat_bin="$4"
	local summary failures benchstat_warnings baseline_normalized missing current_normalized
	local threshold="${BENCH_REGRESSION_THRESHOLD_PCT%\%}"
	summary="$(mktemp "$capture_dir/summary.XXXXXX")"
	failures="$(mktemp "$capture_dir/failures.XXXXXX")"
	benchstat_warnings="$(mktemp "$capture_dir/warnings.XXXXXX")"
	baseline_normalized="$(mktemp "$capture_dir/baseline-normalized.XXXXXX")"
	missing="$(mktemp "$capture_dir/missing.XXXXXX")"
	current_normalized="$(mktemp "$capture_dir/current-normalized.XXXXXX")"
	trap 'rm -f "$summary" "$failures" "$benchstat_warnings" "$baseline_normalized" "$current_normalized" "$missing"' EXIT

	# Benchmark names end in the effective GOMAXPROCS (for example -4 or -16).
	# The paired runner has already required matching effective CPU counts.
	# Normalize only for display and the existing numerical comparator.
	awk '{ if ($1 ~ /^Benchmark/) sub(/-[0-9]+$/, "", $1); print }' "$baseline" >"$baseline_normalized"
	awk '{ if ($1 ~ /^Benchmark/) sub(/-[0-9]+$/, "", $1); print }' "$current" >"$current_normalized"

	# Optional human-readable summary; display-only, never gates the result.
	if [[ -n "$benchstat_bin" ]]; then
		if "$benchstat_bin" -alpha "$BENCHSTAT_ALPHA" "$baseline_normalized" "$current_normalized" >"$summary" 2>"$benchstat_warnings"; then
			cat "$summary"
		else
			echo "bench-regression: benchstat summary unavailable (continuing with raw comparison):" >&2
			cat "$benchstat_warnings" >&2
		fi
	fi

	# Decision: compare the fastest (min) ns/op per benchmark between baseline and
	# current, straight from the raw `go test -bench` output. Min-of-N is the most
	# noise-resistant single statistic (the least-contended run) and needs no
	# benchstat. A benchmark must appear in BOTH files to be compared.
	#
	# awk exit contract (distinct sentinels so an awk fatal error is never mistaken
	# for a valid outcome): 0 = comparison done (regressions, if any, are in
	# "$failures"); 3 = no overlapping benchmarks to compare. awk fatally exits 2 on
	# its own errors, so 2 must NOT be a business sentinel — any exit other than 0/3
	# is treated as a hard failure, never as a clean run. `|| awk_status=$?` captures
	# the code without disabling errexit globally.
	awk_status=0
	awk -v threshold="$threshold" -v missing="$missing" -f "$ROOT_DIR/scripts/bench-compare.awk" \
		"$baseline" "$current" >"$failures" || awk_status=$?

	case "$awk_status" in
		0) ;;
		3)
			echo "bench-regression: no benchmark names overlap between baseline and current run; cannot compare" >&2
			echo "bench-regression: ensure both source revisions contain the selected benchmarks" >&2
			exit 2
			;;
		*)
			echo "bench-regression: benchmark comparison failed unexpectedly (awk exit $awk_status)" >&2
			exit 2
			;;
	esac

	# A narrowed BENCH_PATTERN or BENCH_PACKAGES deliberately runs a subset, so
	# missing baseline names are expected there. On the default full run they mean a
	# benchmark was deleted or renamed and its coverage silently dropped.
	if [[ -s "$missing" ]]; then
		if [[ "$BENCH_PATTERN" == "$DEFAULT_BENCH_PATTERN" && "$BENCH_PACKAGES" == "$DEFAULT_BENCH_PACKAGES" ]]; then
			echo "bench-regression: baseline benchmarks missing from the current run:" >&2
			sort "$missing" >&2
			echo "bench-regression: inspect the selected source revisions and benchmark definitions before comparing again" >&2
			exit 1
		fi
		echo "bench-regression: $(wc -l <"$missing" | tr -d ' ') baseline benchmark(s) not in this narrowed run; not compared." >&2
	fi

	if [[ -s "$failures" ]]; then
		echo "bench-regression: detected ns/op regressions above +${threshold}%:" >&2
		sort "$failures" >&2
		exit 1
	fi

	echo "bench-regression: OK, no ns/op regression above +${threshold}%."
)

capture_measurements() {
	python3 "$ROOT_DIR/scripts/bench_run.py" "$@"
}

main() {
	cd "$ROOT_DIR"
	mkdir -p "$TMPDIR" "$GOTMPDIR" "$GOCACHE"
	if [[ "${1:-}" == "--update-baseline" || "${BENCH_UPDATE_BASELINE:-0}" == "1" ]]; then
		write_baseline
		return
	fi
	if [[ $# -gt 0 ]]; then
		echo "bench-regression: unknown argument: $1" >&2
		return 2
	fi
	if [[ ! "$BENCH_REGRESSION_THRESHOLD_PCT" =~ ^[0-9]+([.][0-9]+)?%?$ ]]; then
		echo "bench-regression: BENCH_REGRESSION_THRESHOLD_PCT must be a non-negative percentage, got: $BENCH_REGRESSION_THRESHOLD_PCT" >&2
		return 2
	fi
	if [[ -z "$BENCH_BASELINE_DIR" ]]; then
		echo "bench-regression: set BENCH_BASELINE_DIR to a prepared clean baseline checkout at a distinct commit" >&2
		echo "bench-regression: historical BENCH_BASELINE files are only used by --update-baseline" >&2
		return 2
	fi
	local capture_dir benchstat_bin
	capture_dir="$(mktemp -d "$TMPDIR/pipelock-bench-pair.XXXXXX")"
	printf 'bench-regression: paired measurements retained in %s\n' "$capture_dir"
	printf 'bench-regression: threshold=+%s%% count=%s benchtime=%s\n' "${BENCH_REGRESSION_THRESHOLD_PCT%\%}" "$BENCH_COUNT" "$BENCH_TIME"
	capture_measurements --baseline "$BENCH_BASELINE_DIR" \
		--candidate "$ROOT_DIR" --output "$capture_dir" -- "${bench_cmd[@]}" || return $?

	# benchstat is display-only; raw measurements still decide without it.
	benchstat_bin="$(benchstat_path || true)"
	if [[ -z "$benchstat_bin" ]]; then
		echo "bench-regression: benchstat not found; summary display disabled (decision still enforced)." >&2
	fi
	compare_measurements "$capture_dir/baseline.txt" "$capture_dir/current.txt" "$capture_dir" "$benchstat_bin"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
