# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Capture validated benchmark pairs and smoke-test all benchmarks."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


class RunError(ValueError):
    """The measurements cannot be compared."""


def command_output(command: list[str], cwd: Path) -> str:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def checkout_state(path: Path) -> str:
    root = Path(command_output(["git", "rev-parse", "--show-toplevel"], path)).resolve()
    if root != path:
        raise RunError(f"not a checkout root: {path}")
    if command_output(["git", "status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"], path):
        raise RunError(f"checkout must be clean: {path}")
    return command_output(["git", "rev-parse", "--verify", "HEAD"], path)


def run_inputs(path: Path, source: str, command: list[str]) -> dict:
    # Resolve inside each module: GOTOOLCHAIN=auto can select different Go versions.
    return {
        "source": source,
        "go": command_output(["go", "version"], path),
        "machine": command_output(["uname", "-srmo"], path),
        "go_env": json.loads(command_output([
            "go", "env", "-json", "GOOS", "GOARCH", "GOFLAGS", "GOEXPERIMENT", "CGO_ENABLED",
        ], path)),
        "command": command,
    }


def validate_inputs(baseline: dict, current: dict) -> None:
    for key in ("go", "machine", "command", "go_env"):
        if not baseline.get(key) or not current.get(key):
            raise RunError(f"missing measurement input: {key}")
        if baseline[key] != current[key]:
            raise RunError(f"measurement input mismatch: {key}")
    for key in ("GOOS", "GOARCH", "CGO_ENABLED"):
        if not baseline["go_env"].get(key):
            raise RunError(f"missing Go environment input: {key}")
    for key in ("GOFLAGS", "GOEXPERIMENT"):
        if key not in baseline["go_env"]:
            raise RunError(f"missing Go environment input: {key}")


def output_metadata(path: Path) -> dict:
    # Go's benchmark format repeats these headers for each package. Only complete
    # ns/op rows count; progress lines and benchmark log output aren't samples.
    headers: dict[str, set[str]] = {key: set() for key in ("goos", "goarch", "cpu")}
    processors: dict[tuple[str, str], set[int]] = {}
    package = ""
    for line in path.read_text().splitlines():
        key, separator, value = line.partition(": ")
        if line.rstrip() == "cpu:":
            headers["cpu"].add("")
        if separator and key in headers:
            headers[key].add(value.strip())
        if key == "pkg" and separator:
            package = value.strip()
        fields = line.split()
        if not fields or not fields[0].startswith("Benchmark") or "ns/op" not in fields:
            continue
        # Go's testing.BenchmarkResult prints iterations, then a decimal ns/op.
        # AWK coerces a malformed value to zero, which would look like a speedup.
        if (len(fields) < 4 or fields[3] != "ns/op" or
                not fields[1].isdecimal() or int(fields[1]) == 0 or
                not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", fields[2])):
            raise RunError("invalid benchmark ns/op sample")
        if not package:
            raise RunError("benchmark sample has no package header")
        match = re.fullmatch(r"(.+)-([0-9]+)", fields[0])
        # testing prints no suffix for GOMAXPROCS=1; otherwise it appends -N.
        name, procs = (match[1], int(match[2])) if match else (fields[0], 1)
        processors.setdefault((package, name), set()).add(procs)
    for key, values in headers.items():
        # testing/benchmark.go omits cpu when sysinfo.CPUName() is empty.
        # An explicitly empty header is still invalid, unlike an absent one.
        if key == "cpu" and not values:
            continue
        if len(values) != 1 or not next(iter(values)):
            raise RunError(f"missing or inconsistent benchmark header: {key}")
    if not processors:
        raise RunError("no benchmark samples captured")
    return {**{key: next(iter(value), "") for key, value in headers.items()}, "processors": processors}


def validate_outputs(baseline: Path, current: Path, inputs: dict) -> None:
    base, cur = output_metadata(baseline), output_metadata(current)
    for key in ("goos", "goarch", "cpu"):
        if base[key] != cur[key]:
            raise RunError(f"benchmark header mismatch: {key}")
    for key, env_key in (("goos", "GOOS"), ("goarch", "GOARCH")):
        if base[key] != inputs["go_env"][env_key]:
            raise RunError(f"benchmark header differs from resolved Go environment: {key}")
    # Leave missing names/no overlap to the existing comparator. For shared
    # benchmarks, preserve CPU suffixes until comparability has been checked.
    for key in base["processors"].keys() & cur["processors"].keys():
        if base["processors"][key] != cur["processors"][key]:
            raise RunError(f"effective GOMAXPROCS mismatch: {key[0]} {key[1]}")


def exclusive_file(path: Path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w")


def measure(path: Path, source: str, metadata: dict, output: Path, command: list[str], on_start=None) -> None:
    if checkout_state(path) != source or run_inputs(path, source, command) != metadata:
        raise RunError(f"measurement inputs changed before running: {path}")
    with exclusive_file(output) as stdout, exclusive_file(output.with_suffix(".stderr")) as stderr:
        stdout.write(f"# Source: {source}\n# Go: {metadata['go']}\n# Machine: {metadata['machine']}\n")
        stdout.write(f"# Command: {shlex.join(command)}\n")
        stdout.flush()
        if on_start is not None:
            on_start()
        subprocess.run(command, cwd=path, check=True, stdout=stdout, stderr=stderr)
    if checkout_state(path) != source or run_inputs(path, source, command) != metadata:
        raise RunError(f"measurement inputs changed while running: {path}")


def single_sample_command(command: list[str]) -> tuple[int, list[str]]:
    # The shell assembles one -count=N flag. Go documents -count as repetitions
    # of each benchmark; preserve that count as rounds, each invoking -count=1.
    indexes = [index for index, arg in enumerate(command) if arg.startswith("-count=")]
    if len(indexes) != 1:
        raise RunError("expected one -count=N benchmark argument")
    index = indexes[0]
    value = command[index].partition("=")[2]
    try:
        count = int(value)
    except ValueError as exc:
        raise RunError("benchmark count must be a positive Go integer") from exc
    if not re.fullmatch(r"[+]?[0-9]+", value) or not 0 < count <= sys.maxsize:
        raise RunError("benchmark count must be a positive Go integer")
    sample = list(command)
    sample[index] = "-count=1"
    return count, sample


def capture_pair(baseline: Path, current: Path, output: Path, command: list[str]) -> None:
    baseline, current, output = baseline.resolve(strict=True), current.resolve(strict=True), output.resolve(strict=True)
    if any(output.is_relative_to(path) for path in (baseline, current)):
        raise RunError("measurement output must be outside both checkouts")
    count, sample_command = single_sample_command(command)
    base_source, cur_source = checkout_state(baseline), checkout_state(current)
    if base_source == cur_source:
        raise RunError("baseline and candidate must have distinct source commits")
    base_inputs = run_inputs(baseline, base_source, sample_command)
    cur_inputs = run_inputs(current, cur_source, sample_command)
    # Capture the exact inputs even if admission fails. Exclusive creation never
    # overwrites an earlier pair or follows an existing output symlink.
    with exclusive_file(output / "inputs.json") as stream:
        json.dump({"baseline": base_inputs, "candidate": cur_inputs,
                   "rounds": count, "requested_command": command}, stream, indent=2)
        stream.write("\n")
    validate_inputs(base_inputs, cur_inputs)
    sides = {"baseline": (baseline, base_source, base_inputs), "candidate": (current, cur_source, cur_inputs)}
    with exclusive_file(output / "execution.jsonl") as execution:
        for number in range(1, count + 1):
            order = ("baseline", "candidate") if number % 2 else ("candidate", "baseline")
            for side in order:
                path, source, metadata = sides[side]
                sample = output / f"{side}-{number}.txt"

                def started():
                    # Record only admitted invocations, immediately before running
                    # Go. Flush so a failed command still leaves its actual order.
                    json.dump({"round": number, "side": side, "command": sample_command,
                               "stdout": sample.name, "stderr": sample.with_suffix(".stderr").name}, execution)
                    execution.write("\n")
                    execution.flush()

                measure(path, source, metadata, sample, sample_command, on_start=started)
            validate_outputs(output / f"baseline-{number}.txt", output / f"candidate-{number}.txt", base_inputs)
    # Keep the comparator's aggregate inputs without discarding any invocation's
    # raw stdout/stderr. Exclusive creation retains the no-overwrite contract.
    for side, name in (("baseline", "baseline"), ("candidate", "current")):
        for suffix in (".txt", ".stderr"):
            with exclusive_file(output / (name + suffix)) as aggregate:
                for number in range(1, count + 1):
                    with (output / f"{side}-{number}{suffix}").open() as sample:
                        shutil.copyfileobj(sample, aggregate)
    if checkout_state(baseline) != base_source or checkout_state(current) != cur_source:
        raise RunError("source changed during paired measurement")
    validate_outputs(output / "baseline.txt", output / "current.txt", base_inputs)


def smoke_benchmarks() -> int:
    """Exercise all benchmarks, including opt-in fixture-backed cases."""
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="benchmark-smoke-") as directory:
        Path(directory).chmod(0o750)
        fixtures = Path(directory) / "fixtures"
        subprocess.run([sys.executable, str(root / "scripts/e2e/browser_repro/fixture.py"),
                        "--output", str(fixtures)], check=True, stdout=subprocess.DEVNULL)
        fixtures.chmod(0o750)
        for name in ("echarts.js", "monaco.js", "react-dom.js"):
            shutil.copyfile(fixtures / "generated-js.js", fixtures / name)
            (fixtures / name).chmod(0o600)
        env = dict(os.environ)
        for key in ("PIPELOCK_BROWSER_REPRO_BENCH_DIR", "RESPONSE_BENCH_DIR", "PIPELOCK_RESPONSE_BENCH_DIR"):
            env[key] = str(fixtures)
        env["PIPELOCK_RESPONSE_PASS_SAMPLE"] = str(fixtures / "generated-js.js")
        start = time.monotonic()
        # Enterprise includes every default benchmark plus enterprise-only ones.
        result = subprocess.run(["go", "test", "-tags", "enterprise", "./...", "-run=^$", "-bench=.",
                                 "-benchtime=1x", "-benchmem", "-count=1"], cwd=root, env=env, check=False)
        print(f"benchmark-smoke: elapsed={time.monotonic() - start:.2f}s exit={result.returncode}", flush=True)
        return result.returncode


# Fixed iterations and in-process repetitions follow Go's -benchtime=Nx and
# -count contracts. Repetition one is initialization; the remaining three must
# agree, so a benchmark that varies is excluded at run time, not reported.
ALLOCATION_REPETITIONS = 4
# Reproduced on linux/amd64 with -count=4 at the stated fixed iteration counts.
# These are observed post-warm-up allocs/op values, never a numerical tolerance.
ALLOCATION_EXCLUSIONS: dict[tuple[str, str], str] = {
    ("github.com/luckyPipewrench/pipelock/internal/mcp", "BenchmarkMCPScanResponseLargeWarn"):
        "allocs/op varies after warm-up: 53170, 53171, 53165 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/mcp", "BenchmarkMCPScanResponse_Clean"):
        "allocs/op varies after warm-up: 2433, 2434, 2432 (200 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/mcp", "BenchmarkMCPScanResponse_Injection"):
        "allocs/op varies after warm-up: 3025, 3025, 3026 (200 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/mcp", "BenchmarkParallel_MCPScanClean"):
        "allocs/op varies after warm-up: 2489, 2478, 2475 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/mcp", "BenchmarkParallel_MCPScanInjection"):
        "allocs/op varies after warm-up: 3053, 3058, 3052 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkDecodeBudget/base64"):
        "allocs/op varies after warm-up: 113, 112, 114 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkDecodeBudget/hex"):
        "allocs/op varies after warm-up: 3146296, 3146300, 3146296 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkDecodeBudget/json"):
        "allocs/op varies after warm-up: 431, 432, 435 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkHotPathKnownSecretsTextDLPReceipt"):
        "allocs/op varies after warm-up: 5862, 5862, 5863 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkHotPathScanResponseReceipt"):
        "allocs/op varies after warm-up: 130, 132, 130 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkParallel_Blocklist"):
        "allocs/op varies after warm-up: 20, 21, 21 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkParallel_DLPBlock"):
        "allocs/op varies after warm-up: 187, 188, 188 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkParallel_Entropy"):
        "allocs/op varies after warm-up: 295, 296, 296 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkParallel_ResponseScan"):
        "allocs/op varies after warm-up: 46, 56, 58 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkRequestBodyDLP/2KiB"):
        "allocs/op varies after warm-up: 1942, 1943, 1942 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkRequestBodyDLP/64KiB"):
        "allocs/op varies after warm-up: 2316, 2316, 2317 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkRequestBodyDLPWithEnvSecret/2KiB"):
        "allocs/op varies after warm-up: 6012, 6012, 6013 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkRequestBodyDLPWithEnvSecret/64KiB"):
        "allocs/op varies after warm-up: 2344, 2345, 2349 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/JSONLike_256KiB_InjectionEarly"):
        "allocs/op varies after warm-up: 270, 253, 258 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/JSONLike_256KiB_InjectionLate"):
        "allocs/op varies after warm-up: 264, 287, 277 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/JSONLike_64KiB_InjectionEarly"):
        "allocs/op varies after warm-up: 236, 266, 253 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/JSONLike_64KiB_InjectionLate"):
        "allocs/op varies after warm-up: 239, 253, 265 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/NaturalProse_256KiB_InjectionEarly"):
        "allocs/op varies after warm-up: 284, 268, 268 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/NaturalProse_256KiB_InjectionLate"):
        "allocs/op varies after warm-up: 237, 273, 253 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/NaturalProse_64KiB_InjectionEarly"):
        "allocs/op varies after warm-up: 267, 239, 253 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/NaturalProse_64KiB_InjectionLate"):
        "allocs/op varies after warm-up: 266, 249, 253 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/UniformFiller_256KiB_InjectionEarly"):
        "allocs/op varies after warm-up: 240, 251, 240 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/UniformFiller_256KiB_InjectionLate"):
        "allocs/op varies after warm-up: 267, 286, 240 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/UniformFiller_64KiB_InjectionEarly"):
        "allocs/op varies after warm-up: 236, 249, 250 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_Large/UniformFiller_64KiB_InjectionLate"):
        "allocs/op varies after warm-up: 253, 249, 253 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScanResponse_StateControlMatch"):
        "allocs/op varies after warm-up: 49, 45, 45 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkScan_ManyQueryParamsAllowed"):
        "allocs/op varies after warm-up: 974487, 974486, 974488 (20 iterations)",
    ("github.com/luckyPipewrench/pipelock/internal/scanner", "BenchmarkWIFOverlapScan"):
        "allocs/op varies after warm-up: 115011, 115014, 115014 (20 iterations)",
}
# Go splits -skip at top-level alternations and slashes. Anchor each path
# component so excluding one sub-case keeps its siblings running.
ALLOCATION_SKIPPED = tuple(sorted({name for _, name in ALLOCATION_EXCLUSIONS}))


def allocation_skip_pattern(names: tuple[str, ...]) -> str:
    return "|".join("/".join(f"^{re.escape(part)}$" for part in name.split("/")) for name in names)


# Go applies -skip in every listed package, so a test keeps each skipped
# top-level name defined in one package only.
ALLOCATION_COMMAND = ["go", "test", "./internal/scanner/...", "./internal/proxy/...", "./internal/mcp/...",
                      "-run=^$", "-bench=.", f"-skip={allocation_skip_pattern(ALLOCATION_SKIPPED)}",
                      "-benchtime=20x", f"-count={ALLOCATION_REPETITIONS}", "-benchmem"]


def allocation_samples(text: str, repetitions: int = ALLOCATION_REPETITIONS) -> tuple[dict, dict]:
    """Read package-qualified Go benchmark rows; never silently overwrite one."""
    samples: dict[tuple[str, str], list[tuple[int, int]]] = {}
    notes = {}
    processors: dict[tuple[str, str], set[int]] = {}
    package = ""
    for line in text.splitlines():
        if line.startswith("pkg: "):
            package = line[5:].strip()
        fields = line.split()
        if not fields or not fields[0].startswith("Benchmark"):
            continue
        match = re.fullmatch(r"(.+)-([0-9]+)", fields[0])
        name, procs = (match[1], int(match[2])) if match else (fields[0], 1)
        key = (package, name)
        processors.setdefault(key, set()).add(procs)
        # testing.BenchmarkResult format, with optional throughput/custom metrics.
        valid = (package and len(fields) >= 8 and fields[1].isdigit() and int(fields[1]) > 0
                 and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", fields[2]) and fields[3] == "ns/op")
        try:
            alloc_index, bytes_index = fields.index("allocs/op"), fields.index("B/op")
            valid = (valid and alloc_index > 0 and bytes_index > 0
                     and fields[alloc_index - 1].isdigit() and fields[bytes_index - 1].isdigit())
            if not valid:
                raise ValueError
            samples.setdefault(key, []).append((int(fields[alloc_index - 1]), int(fields[bytes_index - 1])))
        except ValueError:
            notes[key] = "malformed benchmark row"
    values = {}
    for key, rows in samples.items():
        if len(processors[key]) != 1:
            notes[key] = "mixed effective GOMAXPROCS values for duplicate benchmark name"
        elif len(rows) != repetitions:
            notes[key] = f"expected {repetitions} repetitions, got {len(rows)} (missing or duplicate name)"
        elif len({row[0] for row in rows[1:]}) != 1:
            notes[key] = "allocs/op varies after warm-up: " + ", ".join(str(row[0]) for row in rows[1:])
        elif key not in notes:
            values[key] = (*rows[-1], next(iter(processors[key])))
    for key, reason in ALLOCATION_EXCLUSIONS.items():
        if key in samples or key in notes:
            notes[key] = reason
        elif key[1] in ALLOCATION_SKIPPED:
            notes[key] = reason + " (skipped, not run)"
    return {key: value for key, value in values.items() if key not in notes}, notes


def allocation_report(baseline: str, current: str) -> str:
    base, base_notes = allocation_samples(baseline)
    head, head_notes = allocation_samples(current)
    for key in base.keys() & head.keys():
        if base[key][2] != head[key][2]:
            base_notes[key] = head_notes[key] = "effective GOMAXPROCS differs between base and head"
    excluded = base_notes.keys() | head_notes.keys()
    shared = (base.keys() & head.keys()) - excluded
    changed = sorted(key for key in shared if base[key][0] != head[key][0])
    lines = ["## Benchmark allocation report", "",
             f"Report only; first repetition discarded. Fixed 20 iterations, {ALLOCATION_REPETITIONS} repetitions per process.",
             "Only allocs/op is compared. B/op and timing are not compared.",
             "A benchmark whose remaining repetitions disagree is excluded below, as are known varying cases.",
             "Known varying benchmark cases are skipped rather than run; their other cases remain compared.",
             "Opt-in fixture benchmarks remain skipped unless their fixture environment is configured.", "",
             f"Changed rows: {len(changed)}", "",
             "| Package / benchmark | Base allocs/op | Head allocs/op | Delta | Base B/op (not compared) | Head B/op (not compared) |",
             "| --- | ---: | ---: | ---: | ---: | ---: |"]

    def label(key):
        return (key[0] + " / " + key[1]).replace("&", "&amp;").replace("<", "&lt;").replace("|", "&#124;")

    for key in changed:
        lines.append(f"| {label(key)} | {base[key][0]} | {head[key][0]} | {head[key][0] - base[key][0]:+d} | {base[key][1]} | {head[key][1]} |")
    lines += ["", "### New / removed benchmarks", "", "| Package / benchmark | Status |", "| --- | --- |"]
    base_names, head_names = base.keys() | base_notes.keys(), head.keys() | head_notes.keys()
    for key in sorted(base_names ^ head_names):
        lines.append(f"| {label(key)} | {'new' if key in head_names else 'removed'} |")
    lines += ["", f"Unchanged benchmarks: {len(shared) - len(changed)}", "", "### Excluded benchmarks", ""]
    for key in sorted(excluded):
        reasons = sorted({notes[key] for notes in (base_notes, head_notes) if key in notes})
        lines.append(f"- {label(key)}: {'; '.join(reasons)}")
    if not excluded:
        lines.append("None.")
    if not base and not head:
        lines += ["", "No comparable allocation samples were captured."]
    return "\n".join(lines) + "\n"


def capture_allocations(baseline: Path, current: Path, output: Path) -> None:
    """Reuse paired-run input admission and capture, keeping warm-up in process."""
    baseline, current, output = baseline.resolve(strict=True), current.resolve(strict=True), output.resolve(strict=True)
    if any(output.is_relative_to(path) for path in (baseline, current)):
        raise RunError("measurement output must be outside both checkouts")
    sources = [checkout_state(path) for path in (baseline, current)]
    inputs = [run_inputs(path, source, ALLOCATION_COMMAND) for path, source in zip((baseline, current), sources)]
    validate_inputs(*inputs)
    for path, source, metadata, name in zip((baseline, current), sources, inputs, ("baseline", "current")):
        try:
            measure(path, source, metadata, output / f"{name}.txt", ALLOCATION_COMMAND)
        except subprocess.CalledProcessError:
            # Captured benchmark failures must remain visible in the job log.
            for suffix in (".txt", ".stderr"):
                print((output / (name + suffix)).read_text(), file=sys.stderr)
            raise
    if any(checkout_state(path) != source for path, source in zip((baseline, current), sources)):
        raise RunError("source changed during allocation measurement")
    write_allocation_summary(output)


def write_allocation_summary(output: Path) -> None:
    texts = [(output / f"{name}.txt").read_text() for name in ("baseline", "current")]
    with exclusive_file(output / "allocation-summary.md") as summary:
        summary.write(allocation_report(*texts))
    # A run that compared nothing, such as a skip pattern matching every
    # benchmark, fails rather than passing with an empty report.
    if not any(allocation_samples(text)[0] for text in texts):
        raise RunError("no comparable allocation samples were captured")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="run every benchmark once with generated fixtures")
    if "--smoke" in sys.argv[1:]:
        parser.parse_args()
        return smoke_benchmarks()
    parser.add_argument("--alloc-report", action="store_true", help="report allocations with in-process warm-up")
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not args.alloc_report and command[:2] != ["go", "test"]:
        parser.error("expected the assembled go test benchmark command")
    try:
        if args.alloc_report:
            capture_allocations(args.baseline, args.candidate, args.output)
        else:
            capture_pair(args.baseline, args.candidate, args.output, command)
    except (RunError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"bench-regression: measurement refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
