# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Fail a pull request that slows large-body text DLP.

Runs BenchmarkTextDLPThroughput on the base and head checkouts of one runner,
interleaving the two sides round by round through bench_run.capture_pair, and
compares the per-shape fastest round. A head that is slower than base by more
than the threshold on any shape fails. The scanner cost this guards is per
byte of scanned text, so the summary also reports MB/s.

Noise control: paired rounds on one runner, the fastest round per side, and a
separate warn band below the failure threshold. The scan is deterministic, so
load on the runner can only make a round slower; the fastest round is the best
estimate of its cost. On a loaded workstation, identical code compared by
median differed by up to 25 percent across three rounds and by at most 10
percent compared by fastest round, while a real 40 percent slowdown showed in
both.

Both sides run the candidate's benchmark file. The gate copies it into the
baseline checkout and commits it there, so a base that predates the benchmark
can still be measured and both sides always run the same workload code. A
change that weakens the workload weakens both sides alike; review still owns
the benchmark's content. The file uses only the scanner's exported API so it
builds on older commits.

The fastest round estimates best-case cost. A change that slows only some
rounds, such as one that adds rare stalls, can pass.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_run  # noqa: E402

BENCH_NAME = "BenchmarkTextDLPThroughput"
BENCH_PACKAGE = "./internal/scanner/"
BENCH_FILE = Path("internal/scanner/text_dlp_throughput_bench_test.go")
# Every shape must be measured on both sides; a skipped or failed shape is
# not a pass.
EXPECTED_SHAPES = ("prose/1MiB", "short/1MiB", "b64json/1MiB")
DEFAULT_ROUNDS = 5
DEFAULT_FAIL_PCT = 20.0
DEFAULT_WARN_PCT = 10.0


class GateError(ValueError):
    """The measurements cannot decide the gate."""


def prepare_baseline(baseline: Path, candidate: Path) -> None:
    """Commit the candidate's benchmark file into the baseline checkout.

    bench_run measures only clean checkouts at distinct commits, so the copy is
    committed with a throwaway identity. The baseline is a scratch worktree.
    """
    # Refuse a dirty baseline before changing it, and commit only the
    # benchmark path, so preparation cannot absorb unrelated changes.
    bench_run.checkout_state(baseline.resolve(strict=True))
    source = candidate / BENCH_FILE
    if not source.is_file():
        raise GateError(f"candidate has no {BENCH_FILE}")
    target = baseline / BENCH_FILE
    if target.is_file() and target.read_bytes() == source.read_bytes():
        return
    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    git = ["git", "-C", str(baseline), "-c", "user.name=throughput-gate", "-c", "user.email=gate@invalid.example"]
    for command in (git + ["add", "--", str(BENCH_FILE)],
                    git + ["commit", "--quiet", "--no-gpg-sign", "-m", "measure with the candidate's benchmark", "--", str(BENCH_FILE)]):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise GateError(f"could not prepare the baseline benchmark: {result.stderr.strip()}")


def benchmark_command(rounds: int, benchtime: str) -> list[str]:
    return ["go", "test", BENCH_PACKAGE, "-run=^$", f"-bench=^{BENCH_NAME}$",
            f"-benchtime={benchtime}", f"-count={rounds}", "-benchmem"]


ROW = re.compile(r"^(Benchmark\S+?)(?:-\d+)?\s+(\d+)\s+([0-9]+(?:\.[0-9]+)?) ns/op(?:\s+([0-9]+(?:\.[0-9]+)?) MB/s)?")


def samples(text: str) -> dict[str, list[float]]:
    """ns/op per sub-benchmark, in round order."""
    out: dict[str, list[float]] = {}
    for line in text.splitlines():
        match = ROW.match(line)
        if not match or int(match[2]) == 0:
            continue
        out.setdefault(match[1], []).append(float(match[3]))
    return out


def bytes_per_op(text: str) -> dict[str, float]:
    """Bytes scanned per op, recovered from ns/op and MB/s for the summary."""
    out: dict[str, float] = {}
    for line in text.splitlines():
        match = ROW.match(line)
        if match and match[4] and int(match[2]) > 0:
            out.setdefault(match[1], float(match[3]) * float(match[4]))
    return out


def compare(base_text: str, head_text: str, fail_pct: float, warn_pct: float, rounds: int) -> tuple[list[dict], bool]:
    base, head = samples(base_text), samples(head_text)
    expected = {f"{BENCH_NAME}/{shape}" for shape in EXPECTED_SHAPES}
    for side, rows_seen in (("base", base), ("head", head)):
        if set(rows_seen) != expected:
            raise GateError(f"{side} measured {sorted(rows_seen)}, expected {sorted(expected)}")
    shared = sorted(expected)
    sizes = bytes_per_op(base_text)
    rows = []
    failed = False
    for name in shared:
        if len(base[name]) != rounds or len(head[name]) != rounds:
            raise GateError(f"{name}: expected {rounds} rounds per side, got {len(base[name])} and {len(head[name])}")
        base_ns, head_ns = min(base[name]), min(head[name])
        delta = (head_ns / base_ns - 1.0) * 100.0
        size = sizes.get(name)
        status = "ok"
        if delta > fail_pct:
            status, failed = "FAIL", True
        elif delta > warn_pct:
            status = "warn"
        rows.append({
            "name": name, "base_ns": base_ns, "head_ns": head_ns, "delta_pct": delta, "status": status,
            "base_mbps": size / base_ns if size else None, "head_mbps": size / head_ns if size else None,
            "rounds": len(base[name]),
        })
    return rows, failed


def failure_detail(output: Path, limit: int = 4000) -> str:
    """The tail of every non-empty sample stderr, such as a compiler error."""
    parts = []
    for path in sorted(output.glob("*-*.stderr")):
        text = path.read_text(errors="replace").strip()
        if text:
            parts.append(f"{path.name}:\n{text[-limit:]}")
    return "\n\n".join(parts)[-limit:]


def summary(rows: list[dict], fail_pct: float, warn_pct: float) -> str:
    lines = ["## Text DLP throughput gate", "",
             f"Fastest of paired rounds on one runner. Fail above +{fail_pct:g}%, warn above +{warn_pct:g}%.", "",
             "| Benchmark | Base MB/s | Head MB/s | Base ns/op | Head ns/op | Delta | Status |",
             "| --- | ---: | ---: | ---: | ---: | ---: | --- |"]
    for row in rows:
        if "base_ns" not in row:
            lines.append(f"| {row['name']} | | | | | | {row['status']} |")
            continue
        mbps = lambda value: f"{value:.2f}" if value else "n/a"  # noqa: E731
        lines.append(f"| {row['name']} | {mbps(row['base_mbps'])} | {mbps(row['head_mbps'])} | "
                     f"{row['base_ns']:.0f} | {row['head_ns']:.0f} | {row['delta_pct']:+.1f}% | {row['status']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", required=True, type=Path, help="clean checkout of the base commit")
    parser.add_argument("--candidate", required=True, type=Path, help="clean checkout of the head commit")
    parser.add_argument("--output", required=True, type=Path, help="empty directory for raw samples and the summary")
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS)
    parser.add_argument("--benchtime", default="1x")
    parser.add_argument("--fail-pct", type=float, default=DEFAULT_FAIL_PCT)
    parser.add_argument("--warn-pct", type=float, default=DEFAULT_WARN_PCT)
    args = parser.parse_args()
    if args.rounds < 3:
        parser.error("--rounds must be at least 3 so a median exists")
    args.output.mkdir(mode=0o750, parents=True, exist_ok=True)
    status = 0
    try:
        prepare_baseline(args.baseline, args.candidate)
        bench_run.capture_pair(args.baseline, args.candidate, args.output, benchmark_command(args.rounds, args.benchtime))
        base_text = (args.output / "baseline.txt").read_text()
        head_text = (args.output / "current.txt").read_text()
        rows, failed = compare(base_text, head_text, args.fail_pct, args.warn_pct, args.rounds)
    except (bench_run.RunError, GateError, subprocess.CalledProcessError, OSError) as exc:
        detail = failure_detail(args.output)
        (args.output / "throughput-summary.md").write_text(
            f"## Text DLP throughput gate\n\nNot decided: {exc}\n" + (f"\n```\n{detail}\n```\n" if detail else ""))
        print(f"throughput-gate: {exc}", file=sys.stderr)
        if detail:
            print(detail, file=sys.stderr)
        return 2
    text = summary(rows, args.fail_pct, args.warn_pct)
    (args.output / "throughput-summary.md").write_text(text)
    (args.output / "throughput-rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(text)
    if failed:
        print("throughput-gate: head is slower than base beyond the threshold", file=sys.stderr)
        status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
