# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Capture and validate a local benchmark pair; scoring stays in bench-compare.awk."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


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
        if len(values) != 1 or not next(iter(values)):
            raise RunError(f"missing or inconsistent benchmark header: {key}")
    if not processors:
        raise RunError("no benchmark samples captured")
    return {**{key: next(iter(value)) for key, value in headers.items()}, "processors": processors}


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


def measure(path: Path, source: str, metadata: dict, output: Path, command: list[str]) -> None:
    if checkout_state(path) != source or run_inputs(path, source, command) != metadata:
        raise RunError(f"measurement inputs changed before running: {path}")
    with exclusive_file(output) as stdout, exclusive_file(output.with_suffix(".stderr")) as stderr:
        stdout.write(f"# Source: {source}\n# Go: {metadata['go']}\n# Machine: {metadata['machine']}\n")
        stdout.write(f"# Command: {shlex.join(command)}\n")
        stdout.flush()
        subprocess.run(command, cwd=path, check=True, stdout=stdout, stderr=stderr)
    if checkout_state(path) != source or run_inputs(path, source, command) != metadata:
        raise RunError(f"measurement inputs changed while running: {path}")


def capture_pair(baseline: Path, current: Path, output: Path, command: list[str]) -> None:
    baseline, current, output = baseline.resolve(strict=True), current.resolve(strict=True), output.resolve(strict=True)
    if any(output.is_relative_to(path) for path in (baseline, current)):
        raise RunError("measurement output must be outside both checkouts")
    base_source, cur_source = checkout_state(baseline), checkout_state(current)
    if base_source == cur_source:
        raise RunError("baseline and candidate must have distinct source commits")
    base_inputs = run_inputs(baseline, base_source, command)
    cur_inputs = run_inputs(current, cur_source, command)
    # Capture the exact inputs even if admission fails. Exclusive creation never
    # overwrites an earlier pair or follows an existing output symlink.
    with exclusive_file(output / "inputs.json") as stream:
        json.dump({"baseline": base_inputs, "candidate": cur_inputs}, stream, indent=2)
        stream.write("\n")
    validate_inputs(base_inputs, cur_inputs)
    measure(baseline, base_source, base_inputs, output / "baseline.txt", command)
    measure(current, cur_source, cur_inputs, output / "current.txt", command)
    if checkout_state(baseline) != base_source or checkout_state(current) != cur_source:
        raise RunError("source changed during paired measurement")
    validate_outputs(output / "baseline.txt", output / "current.txt", base_inputs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if command[:2] != ["go", "test"]:
        parser.error("expected the assembled go test benchmark command")
    try:
        capture_pair(args.baseline, args.candidate, args.output, command)
    except (RunError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"bench-regression: measurement refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
