#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Rebuild scripts/ci_test_durations.json from `go test -json` output.

The sub-shard split in scripts/ci_test_packages.py balances by these measured
seconds. Feed it the JSON of race runs that cover a split tree (CI keeps each
shard's stream as a workflow artifact). Each weight includes elapsed time plus
the recursive costs of directly paused children divided by race parallelism.
Incomplete runs are lower bounds.

    python3 scripts/ci_test_durations.py --write shard-a.json shard-b.json ...

Only trees listed in TEST_SPLITS are recorded. Measurements are merged per test
name: a re-measured test takes its new time, an unmeasured test keeps its old
one, and a test no longer in the tree is dropped, so a partial refresh from a
few shards never erases the rest.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ci_test_packages import (  # noqa: E402
    DURATIONS_FILE,
    HEAVY_TREES,
    ROOT,
    SHARDS,
    TEST_SPLITS,
    load_durations,
    load_package_durations,
    package_in_tree,
    tree_test_names,
)


def tree_for_package(package: str) -> str | None:
    for tree in TEST_SPLITS:
        if package_in_tree(package, HEAVY_TREES[tree]):
            return tree
    return None


def collect_packages(paths: list[Path]) -> dict[str, float]:
    """Record whole-package elapsed time for packages outside the split trees.

    These weights balance the rest shards, which run whole packages.
    """
    measured: dict[str, float] = {}
    for path in paths:
        packages: dict[str, float | None] = {}
        pending: set[tuple[str, str]] = set()
        failed: set[str] = set()
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                package, action = event.get("Package"), event.get("Action")
                if not isinstance(package, str) or tree_for_package(package) is not None:
                    continue
                name = event.get("Test")
                if isinstance(name, str):
                    key = (package, name)
                    if action == "run":
                        pending.add(key)
                    elif action in ("pass", "fail", "skip"):
                        pending.discard(key)
                        if action == "fail":
                            failed.add(package)
                elif name is None:
                    if action in ("start", "run", "fail"):
                        packages[package] = None
                    elif action == "pass":
                        elapsed = event.get("Elapsed")
                        packages[package] = float(elapsed) if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool) else None
        for package, elapsed in packages.items():
            if elapsed is not None and package not in failed and not any(pkg == package for pkg, _ in pending):
                measured[package] = max(measured.get(package, 0.0), round(elapsed, 1))
    return measured


# The race commands in .github/workflows/ci.yaml use -parallel=2.
RACE_PARALLELISM = 2


def collect(
    paths: list[Path], previous: dict[str, dict[str, float]] | None = None,
) -> dict[str, dict[str, float]]:
    # Deduplicate retries by package and full test name, keeping the slowest
    # completed event. A started but incomplete leaf contributes no elapsed
    # time; the resulting estimate is a lower bound, not a complete run.
    events: dict[tuple[str, str], float | None] = {}
    incomplete: set[tuple[str, str]] = set()
    paused: set[tuple[str, str]] = set()
    parents: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for path in paths:
        active: set[tuple[str, str]] = set()
        pending: set[tuple[str, str]] = set()
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue
                package, name = event.get("Package"), event.get("Test")
                if not isinstance(package, str) or not isinstance(name, str) or tree_for_package(package) is None:
                    continue
                action = event.get("Action")
                if action not in ("run", "pause", "cont", "pass", "fail", "skip"):
                    continue
                key = (package, name)
                events.setdefault(key, None)
                if action == "run":
                    pending.add(key)
                    # Only an active prefix can have started this subtest.
                    prefix = name
                    while "/" in prefix:
                        prefix = prefix.rsplit("/", 1)[0]
                        parent = (package, prefix)
                        if parent in active:
                            parents.setdefault(key, set()).add(parent)
                            break
                    active.add(key)
                elif action == "pause":
                    active.discard(key)
                    paused.add(key)
                elif action == "cont":
                    active.add(key)
                elif action in ("pass", "fail", "skip"):
                    active.discard(key)
                    pending.discard(key)
                    if action in ("fail", "skip"):
                        incomplete.add((package, name.split("/", 1)[0]))
                elapsed = event.get("Elapsed")
                if action in ("pass", "fail", "skip") and isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool):
                    events[key] = max(events[key] or 0.0, float(elapsed))

        incomplete.update((pkg, name.split("/", 1)[0]) for pkg, name in pending)

    # cmd/test2json documents pause and cont; testing.T.Run documents that
    # parallel children resume only after their parent test function returns,
    # and a test's elapsed time excludes the wall time of its paused children.
    # Non-paused children are already included in their parent's elapsed time.
    # The go test -parallel flag is one limit for the whole test binary, so the
    # running time of a paused subtree is divided by it once, where the subtree
    # joins a test that is not itself paused, never again at each nested level.
    def parent_of(package: str, name: str) -> tuple[str, str]:
        # A t.Run name may itself contain "/", so the parent is the longest
        # prefix that ran as a test, not the name minus its last segment.
        prefix = name
        while "/" in prefix:
            prefix = prefix.rsplit("/", 1)[0]
            if (package, prefix) in events:
                return package, prefix
        return package, name.split("/", 1)[0]

    paused_work: dict[tuple[str, str], float] = {}
    for key in sorted(events, key=lambda item: item[1].count("/"), reverse=True):
        package, name = key
        if key in paused and "/" in name:
            work = (events[key] or 0.0) + paused_work.get(key, 0.0)
            for parent in parents.get(key, {parent_of(package, name)}):
                paused_work[parent] = paused_work.get(parent, 0.0) + work

    measured: dict[str, dict[str, float]] = {}
    keys = {(pkg, name.split("/", 1)[0]) for pkg, name in events}
    for package, name in keys:
        weight = (events.get((package, name)) or 0.0) + paused_work.get((package, name), 0.0) / RACE_PARALLELISM
        if (package, name) not in events and not weight:
            continue
        tree = tree_for_package(package)
        if (package, name) in incomplete:
            weight = max(weight, (previous or {}).get(tree, {}).get(name, 0.0))
        tests = measured.setdefault(tree, {})
        tests[name] = max(tests.get(name, 0.0), round(weight, 1))
    return measured


def merge(
    previous: dict[str, dict[str, float]],
    measured: dict[str, dict[str, float]],
    inventory: dict[str, set[str]] | None = None,
) -> dict:
    """Overlay new measurements per test name onto the previous weights.

    A re-measured name takes its new time, so a test that got faster stops
    being charged its old cost. A name absent from the inputs keeps its old
    time, so refreshing from a few shards never erases the rest of a tree.
    When an inventory is given, names no longer present in the tree are dropped.
    """
    trees: dict[str, dict[str, float]] = {}
    for tree in TEST_SPLITS:
        tests = dict(previous.get(tree, {}))
        tests.update(measured.get(tree, {}))
        if inventory is not None and tree in inventory:
            tests = {name: seconds for name, seconds in tests.items() if name in inventory[tree]}
        if tests:
            trees[tree] = dict(sorted(tests.items()))
    return {"trees": trees}


def artifact_complete(path: Path) -> bool:
    """Require terminal package results and no unfinished tests in a CI stream."""
    packages: dict[str, str | None] = {}
    pending: set[tuple[str, str]] = set()
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or not isinstance(event.get("Package"), str):
                continue
            package = event["Package"]
            packages.setdefault(package, None)
            name, action = event.get("Test"), event.get("Action")
            if isinstance(name, str):
                key = (package, name)
                if action == "run":
                    pending.add(key)
                elif action in ("pass", "fail", "skip"):
                    pending.discard(key)
            elif action in ("pass", "fail", "skip"):
                packages[package] = action
    return bool(packages) and not pending and all(action in ("pass", "skip") for action in packages.values())


def ci_artifact_inputs(directory: Path) -> list[Path]:
    """Require every Go 1.26 producer before treating a refresh as CI evidence."""
    inputs: list[Path] = []
    for lane in ("oss", "enterprise"):
        for shard in SHARDS:
            profile = directory / f"go-test-json-{lane}-go126-{shard}" / f"go-test-{lane}.json"
            if not profile.is_file() or profile.stat().st_size == 0:
                raise ValueError(f"missing or empty CI timing artifact: {profile}")
            if not artifact_complete(profile):
                raise ValueError(f"incomplete or failed CI timing artifact: {profile}")
            if not collect([profile]) and not collect_packages([profile]):
                raise ValueError(f"CI timing artifact has no measured results: {profile}")
            inputs.append(profile)
    return inputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inputs", nargs="*", type=Path, help="go test -json output files")
    parser.add_argument("--write", action="store_true", help=f"update {DURATIONS_FILE.name}")
    parser.add_argument("--ci-artifacts", type=Path, help="require the complete Go 1.26 CI artifact directory")
    args = parser.parse_args()
    if args.ci_artifacts and args.inputs:
        parser.error("use either --ci-artifacts or input files")
    try:
        inputs = ci_artifact_inputs(args.ci_artifacts) if args.ci_artifacts else args.inputs
    except ValueError as error:
        print(f"ci_test_durations.py: {error}", file=sys.stderr)
        return 1
    if not inputs:
        parser.error("provide input files or --ci-artifacts")

    previous = load_durations()
    measured = collect(inputs, previous)
    packages = collect_packages(inputs)
    if not measured and not packages:
        print("ci_test_durations.py: no test results in the inputs", file=sys.stderr)
        return 1
    inventory = {tree: set(tree_test_names(ROOT / HEAVY_TREES[tree])) for tree in TEST_SPLITS}
    result = merge(previous, measured, inventory)
    merged_packages = dict(load_package_durations())
    merged_packages.update(packages)
    if merged_packages:
        result["packages"] = dict(sorted(merged_packages.items()))
    for tree, tests in result["trees"].items():
        print(f"{tree}: {len(tests)} tests, {sum(tests.values()):.0f}s measured", file=sys.stderr)
    print(f"rest packages: {len(merged_packages)}", file=sys.stderr)
    text = json.dumps(result, indent=1, sort_keys=False) + "\n"
    if args.write:
        DURATIONS_FILE.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
