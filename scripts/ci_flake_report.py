# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Rerun the tests a race shard failed and label each flaky or deterministic.

A red race shard on main says a test failed once. It does not say whether the
failure reproduces, which decides the next step: a deterministic failure is a
regression to fix or revert, and a failure that does not reproduce every time
is a flaky test to fix at its cause. This reruns only the failed top-level
tests, a few times each, and reports which kind each one is.

It never changes the job's result. The caller keeps the original test status,
so a flaky failure still fails the shard: hiding it would let the same flake
red main again. A DATA RACE or a package-level failure (build error, panic,
timeout with no named test) is reported as is and not rerun, because a
repeat that passes would not make it less real.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

if __package__:
    from .ci_test_packages import ROOT, exact_names_regex
else:
    from ci_test_packages import ROOT, exact_names_regex

# Enough reruns to tell a test that fails every time from one that fails
# sometimes, without turning a red shard into a long one.
DEFAULT_RERUNS = 5
# A shard with more failures than this is broken, not flaky; rerunning all of
# them would only delay the red result.
MAX_TESTS = 10
RERUN_TIMEOUT_SECONDS = 600
RACE_MARKER = "WARNING: DATA RACE"


def failed_tests(events) -> tuple[dict[str, list[str]], list[str], dict[str, list[str]]]:
    """Return (rerunnable failures by package, packages failing with no test, races by package)."""
    failed: dict[str, set[str]] = {}
    races: dict[str, set[str]] = {}
    package_failed: set[str] = set()
    raced_output: dict[tuple[str, str], bool] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        package, test, action = event.get("Package"), event.get("Test"), event.get("Action")
        if not isinstance(package, str) or not package:
            continue
        top = test.split("/", 1)[0] if isinstance(test, str) and test else None
        if action == "output" and top and RACE_MARKER in str(event.get("Output", "")):
            raced_output[(package, top)] = True
        if action != "fail":
            continue
        if top is None:
            package_failed.add(package)
        elif raced_output.get((package, top)):
            races.setdefault(package, set()).add(top)
        else:
            failed.setdefault(package, set()).add(top)
    # A package whose only failure is the package line had no named test to rerun.
    bare = sorted(pkg for pkg in package_failed if pkg not in failed and pkg not in races)
    return ({pkg: sorted(names) for pkg, names in failed.items()}, bare,
            {pkg: sorted(names) for pkg, names in races.items()})


def read_events(stream) -> list:
    events = []
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def rerun(package: str, names: list[str], tags: str, reruns: int, timeout: float) -> dict[str, int]:
    """Rerun names under -race; return failures per test, or -1 when the rerun could not finish."""
    command = ["go", "test", "-race", f"-count={reruns}", "-parallel=2", f"-timeout={int(timeout)}s", "-json"]
    if tags:
        command.extend(["-tags", tags])
    command.extend(["-run=" + exact_names_regex(names), package])
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout + 60)
    except subprocess.TimeoutExpired:
        return {name: -1 for name in names}
    failures = {name: 0 for name in names}
    finished = {name: 0 for name in names}
    for event in read_events(result.stdout.splitlines()):
        test = event.get("Test")
        if event.get("Package") != package or test not in failures:
            continue
        if event.get("Action") in ("pass", "fail", "skip"):
            finished[test] += 1
            if event.get("Action") == "fail":
                failures[test] += 1
    # A rerun that crashed or timed out before every requested run finished is
    # unknown, including when a run had already failed. A partial count would
    # call that flake and hide that the rerun did not finish.
    return {name: failures[name] if finished[name] >= reruns else -1 for name in names}


def classify(failures: int, reruns: int) -> str:
    if failures < 0:
        return "UNKNOWN"
    if failures == reruns:
        return "DETERMINISTIC"
    return "FLAKY"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tags", default="", help="build tags the shard used")
    parser.add_argument("--reruns", type=int, default=DEFAULT_RERUNS)
    parser.add_argument("--label", default="race shard")
    args = parser.parse_args()
    if args.reruns < 2:
        parser.error("--reruns must be at least 2")

    failed, bare, races = failed_tests(read_events(sys.stdin))
    lines = [f"## Failure classification: {args.label}", "",
             f"Each failed test was rerun {args.reruns} times under -race. "
             "The shard's own result is unchanged.", "",
             "| Package | Test | Reruns failed | Kind |", "|---|---|---|---|"]
    for package, names in sorted(races.items()):
        for name in names:
            print(f"::error title=Data race::{package} {name} reported a data race; not rerun, a race is a bug whether or not it repeats.")
            lines.append(f"| {package} | {name} | not rerun | DATA RACE |")
    for package in bare:
        print(f"::error title=Package failure::{package} failed outside any named test (build error, panic or timeout); not rerun.")
        lines.append(f"| {package} | (package) | not rerun | PACKAGE |")
    total = sum(len(names) for names in failed.values())
    if total > MAX_TESTS:
        print(f"::warning title=Too many failures to classify::{total} tests failed; over {MAX_TESTS} is not flakiness, so none were rerun.")
        lines.append(f"| | {total} failed tests | not rerun | TOO MANY |")
    else:
        for package, names in sorted(failed.items()):
            counts = rerun(package, names, args.tags, args.reruns, RERUN_TIMEOUT_SECONDS)
            for name in names:
                count = counts[name]
                kind = classify(count, args.reruns)
                shown = "rerun did not finish" if count < 0 else f"{count} of {args.reruns}"
                lines.append(f"| {package} | {name} | {shown} | {kind} |")
                if kind == "DETERMINISTIC":
                    print(f"::error title=Deterministic failure::{package} {name} failed all {args.reruns} reruns: a regression to fix or revert.")
                elif kind == "FLAKY":
                    print(f"::error title=Flaky test::{package} {name} failed {count} of {args.reruns} reruns after failing in the shard: fix its cause; the shard stays red.")
                else:
                    print(f"::warning title=Unclassified failure::{package} {name}: the rerun did not finish.")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    text = "\n".join(lines) + "\n"
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
