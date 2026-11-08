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
    MIN_UNMEASURED_SECONDS,
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
    # Top-level names whose own subtest skipped. Distinct from a failure or a
    # test that never finished: only this gap has no elapsed time to record.
    skipped_subtests: set[tuple[str, str]] = set()
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
                    if "/" not in name and key in pending:
                        incomplete.add(key)
                    pending.add(key)
                    if "/" not in name:
                        # A new attempt of a top-level test (a retry appended to
                        # the same stream) ends everything its last attempt left
                        # running, so a stale subtest cannot claim a new child.
                        active = {item for item in active if item[0] != package or item[1].split("/", 1)[0] != name}
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
                        top = (package, name.split("/", 1)[0])
                        incomplete.add(top)
                        if action == "skip" and "/" in name:
                            skipped_subtests.add(top)
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
            # Retries can record more than one parent for the same subtest, and
            # every candidate is a prefix of its name. Charge its work once,
            # through the deepest (longest) candidate, so the attempts are not
            # added together and a later attempt cannot drop an earlier path.
            parent = max(parents[key], key=lambda item: len(item[1])) if key in parents else parent_of(package, name)
            paused_work[parent] = paused_work.get(parent, 0.0) + work

    measured: dict[str, dict[str, float]] = {}
    keys = {(pkg, name.split("/", 1)[0]) for pkg, name in events}
    for package, name in keys:
        weight = (events.get((package, name)) or 0.0) + paused_work.get((package, name), 0.0) / RACE_PARALLELISM
        if (package, name) not in events and not weight:
            continue
        tree = tree_for_package(package)
        if (package, name) in incomplete:
            recorded = (previous or {}).get(tree) or {}
            if name in recorded:
                # A recorded test keeps the slower of this run and its previous
                # weight. A stored zero stays zero; it is a weight, not "missing".
                weight = max(weight, recorded[name])
            elif (package, name) in skipped_subtests:
                # No previous weight. A skipped subtest did not measure the work
                # the race shards run, so charge the floor an unmeasured new
                # test already pays instead of recording zero.
                weight = max(weight, MIN_UNMEASURED_SECONDS)
        tests = measured.setdefault(tree, {})
        tests[name] = max(tests.get(name, 0.0), round(weight, 1))
    return measured


def merge(
    previous: dict[str, dict[str, float]],
    measured: dict[str, dict[str, float]],
    inventory: dict[str, set[str]] | None = None,
) -> dict:
    """Overlay new measurements per test name onto the previous weights.

    A completely re-measured name takes its new time, so a test that got faster
    stops being charged its old cost. collect() charges a name whose run failed,
    never finished, or skipped any subtest at least its previous weight, so such
    a run can raise a weight but never lower it. A name with no previous weight
    whose subtest skipped is charged MIN_UNMEASURED_SECONDS, the same floor an
    unmeasured test already pays, instead of zero. A name absent from the inputs
    keeps its old time, so refreshing from a few shards never erases the rest of a tree.
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


def selection_path(path: Path) -> Path:
    """The changed-test selection written beside a partial race stream."""
    return path.with_suffix(".selection.json")


def partial_overrides(paths: list[Path]) -> dict:
    """Turn changed-test race runs into weight overrides.

    Split trees store per-test weights, so a measured test replaces its own
    weight. Rest shards store whole-package totals, so the changed-test runner
    measures a touched rest package whole and its run replaces the total. A
    rest package that ran only some of its tests can't stand in for its total,
    so it is refused rather than added to or ignored.
    """
    whole: set[str] = set()
    measured: list[Path] = []
    previous = load_durations()
    preserved: dict[str, dict[str, float]] = {}
    for path in paths:
        empty = not path.read_bytes().strip()
        if not empty and not artifact_complete(path):
            raise ValueError(f"incomplete or failed changed-test race stream: {path}")
        try:
            selection = json.loads(selection_path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"partial stream {path} needs its selection file "
                             f"{selection_path(path).name}: {error}") from error
        # A sibling's measurement of a shared name cannot replace the
        # recorded weight of a package this selection left unmeasured.
        for package in selection.get("skipped", []):
            tree = tree_for_package(package)
            if tree is None:
                continue
            recorded = previous.get(tree, {})
            for name in selection.get("selected", {}).get(package, []):
                if name in recorded:
                    preserved.setdefault(tree, {})[name] = recorded[name]
        if empty:
            # The deadline can leave every selected package unmeasured; its
            # stream is then empty by design. An empty stream with any package
            # its selection does not name as skipped is an incomplete run.
            selected = selection.get("selected", {})
            if not isinstance(selected, dict) or not set(selected) <= set(selection.get("skipped", [])):
                raise ValueError(f"incomplete or failed changed-test race stream: {path}")
            continue
        whole.update(selection.get("whole", []))
        measured.append(path)
    paths = measured
    if not paths:
        return {"trees": preserved, "packages": {}}
    packages: dict[str, float] = {}
    for path in paths:
        for package, seconds in collect_packages([path]).items():
            if package not in whole:
                raise ValueError(f"{path}: rest package {package} ran only some tests; "
                                 "measure the whole package to replace its total")
            # Several streams of one package keep the slowest run.
            packages[package] = max(packages.get(package, 0.0), seconds)
    result = {"trees": collect(paths, previous), "packages": packages}
    for tree, tests in preserved.items():
        weights = result["trees"].setdefault(tree, {})
        for name, seconds in tests.items():
            weights[name] = max(weights.get(name, 0.0), seconds)
    # Reuse the planner's finite, non-negative weight validation for imported
    # partial JSON too; invalid numbers must never make a budget compare green.
    from ci_test_packages import _seconds_map
    for tree, tree_tests in result["trees"].items():
        _seconds_map(paths[0], tree, tree_tests)
    _seconds_map(paths[0], "packages", result["packages"])
    return result


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
    parser.add_argument("--partial", action="store_true",
                        help="inputs contain only changed tests, not complete packages")
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
    try:
        overrides = partial_overrides(inputs) if args.partial else None
    except ValueError as error:
        print(f"ci_test_durations.py: {error}", file=sys.stderr)
        return 1
    measured = overrides["trees"] if overrides else collect(inputs, previous)
    packages = overrides["packages"] if overrides else collect_packages(inputs)
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
