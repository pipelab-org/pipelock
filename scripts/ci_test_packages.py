#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Print the package list, or the test selector, for a CI test shard.

Package shards
--------------
Three heavy package trees run on their own shards and every other package is
spread round-robin over the rest shards. The union of all package shards is
exactly `go list ./...`.

Test sub-shards
---------------
The proxy and scanner trees are each too slow for one runner, so their tests
are divided by top-level test name across sub-shards (`proxy-0`, `proxy-1`,
...). Every sub-shard of a tree runs the same packages with a different
selector:

* sub-shard i < n-1 runs `-run` of the names packed into bucket i, longest
  measured test first onto the least-loaded bucket using
  scripts/ci_test_durations.json (a stable name hash when a tree has no
  measurements);
* the last sub-shard runs `-skip` of the union of every earlier bucket.

That makes the split complete and disjoint by construction rather than by the
accuracy of the name inventory. A test the inventory never saw (a new file, an
unusual declaration) matches no `-run` bucket and is not skipped by the last
sub-shard, so it still runs exactly once. The inventory only affects balance,
which is why it is a cheap source scan rather than a compile of every test
binary. `--check-partition` compares the selectors against `go test -list`
under the real build tags for release verification.

A name the inventory lists that does not exist under the current build tags is
harmless: no test matches it. Benchmarks are not listed because these shards
never pass -bench.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

HEAVY_TREES = {
    "proxy": "internal/proxy",
    "scanner": "internal/scanner",
    "mcp": "internal/mcp",
    "runtime": "internal/cli/runtime",
}
# Number of test-name sub-shards per heavy tree. A tree absent here runs as a
# single shard named after the tree.
TEST_SPLITS = {
    "proxy": 8,
    "scanner": 4,
    "mcp": 8,
    "runtime": 2,
}
REST_SHARDS = ("rest-0", "rest-1", "rest-2", "rest-3")
# Sub-shards per heavy tree in the no-race lane pull requests wait on. Without
# -race most trees run several times faster, so they need fewer splits than the
# race lane above; the race-measured weights still balance the buckets, since
# relative test cost survives dropping the race detector well enough to pack.
#
# Measured without -race on four pinned cores: internal/mcp took 694s and
# internal/proxy 552s alone, so each splits three ways; every rest package
# together came to about eight minutes of four-way work. Two rest shards left the
# enterprise pair the slowest jobs in the lane at about six minutes, so three.
# Proxy splits four ways: by 2026-11-05 the name-split enterprise proxy-1 shard
# took 494s on main against the 8-minute package timeout plus setup (about
# 540s), and two pull requests adding a few proxy tests timed it out.
UNIT_SPLITS = {
    "proxy": 4,
    "scanner": 1,
    "mcp": 3,
    "runtime": 1,
}
UNIT_REST_SHARDS = ("rest-0", "rest-1", "rest-2")

# Temporary predicted-load ceiling pending proxy and rest-shard test-time cuts.
# Weights from main CI run 42120390716 (2026-11-05) predict at most 794.9s;
# ceil(794.9 * 1.10) = 875s leaves a 10% operating margin. That run's slowest
# package took 776.138s. Keep the 600s runtime warnings in ci.yaml as the
# recovery target, then lower this ceiling after re-measuring the test cuts.
# This doesn't extend the 900s package or 1260s whole-attempt timeouts.
SHARD_BUDGET_SECONDS = 875
# Rest shards run their packages two at a time (-p=2), so summed package time
# overstates wall time by about that factor.
REST_PACKAGE_PARALLELISM = 2
# Least cost charged to a test with no measurement.
MIN_UNMEASURED_SECONDS = 1.0

# Measured race-test seconds per top-level test, used to balance sub-shards by
# time instead of by name count. Regenerate it from CI shard timings with
# scripts/ci_test_durations.py when shards drift past the CI time budget.
DURATIONS_FILE = ROOT / "scripts" / "ci_test_durations.json"


def _heavy_shard_names() -> tuple[str, ...]:
    names: list[str] = []
    for tree in HEAVY_TREES:
        count = TEST_SPLITS.get(tree, 1)
        if count == 1:
            names.append(tree)
        else:
            names.extend(f"{tree}-{index}" for index in range(count))
    return tuple(names)


HEAVY_SHARDS = _heavy_shard_names()
SHARDS = (*HEAVY_SHARDS, *REST_SHARDS)

# Go's test-result cache keys a result on the test binary's own inputs and the
# files and environment the test process reads. A test that runs the go tool in
# a subprocess (go build ./cmd/pipelock, then exercises that binary) depends on
# source the child compiles, which that key never sees, so a cached pass could
# outlive a change to it. A file that both calls exec.Command and names "go" is
# treated as doing that, and every package whose test binary includes such a
# file runs with -count=1 in the no-race lane.
GO_TOOL_EXEC_RE = re.compile(r"\bexec\.Command(?:Context)?\(")
GO_TOOL_NAME_RE = re.compile(r'"go"')


def go_tool_dirs(root: Path = ROOT) -> tuple[set[str], set[str]]:
    """Repository-relative directories with a .go file that runs the go tool.

    Returns (library, test): a non-test file is compiled into every test binary
    that imports its package; a _test.go file only into its own package's.
    """
    library: set[str] = set()
    test: set[str] = set()
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if not d.startswith(".") and d not in {"testdata", "node_modules"})
        for filename in files:
            if not filename.endswith(".go"):
                continue
            text = (Path(directory) / filename).read_text(encoding="utf-8", errors="replace")
            if GO_TOOL_EXEC_RE.search(text) and GO_TOOL_NAME_RE.search(text):
                rel = Path(directory).relative_to(root).as_posix()
                (test if filename.endswith("_test.go") else library).add(rel)
    return library, test


def fresh_packages(packages: list[str], tags: str) -> list[str]:
    """The subset of packages whose test binary includes a go-tool-running file."""
    if not packages:
        return []
    module = module_path()
    library_dirs, test_dirs = go_tool_dirs()
    as_package = lambda d: f"{module}/{d}" if d != "." else module  # noqa: E731
    tool_packages = {as_package(d) for d in library_dirs}
    self_fresh = {as_package(d) for d in test_dirs}
    cmd = ["go", "list", "-test"]
    if tags:
        cmd.extend(["-tags", tags])
    cmd.extend(["-f", "{{.ImportPath}}|{{join .Deps \" \"}}", *packages])
    result = subprocess.run(cmd, check=True, text=True, capture_output=True, cwd=ROOT)
    test_deps: dict[str, set[str]] = {}
    for line in result.stdout.splitlines():
        name, _, deps = line.partition("|")
        # "pkg.test" is the test main; its Deps cover the package, its internal
        # and external test files, and everything they import.
        if name.endswith(".test"):
            test_deps[name[: -len(".test")]] = set(deps.split())
    fresh = []
    for pkg in packages:
        deps = test_deps.get(pkg, set()) | {pkg}
        if pkg in self_fresh or {d.split(" ")[0] for d in deps} & tool_packages:
            fresh.append(pkg)
    return fresh


def module_path() -> str:
    for line in (ROOT / "go.mod").read_text(encoding="utf-8").splitlines():
        if line.startswith("module "):
            return line.split()[1]
    raise ValueError("go.mod has no module line")


# Linux's include/uapi/linux/binfmts.h sets MAX_ARG_STRLEN to PAGE_SIZE * 32
# (128 KiB with 4 KiB pages), including the terminating NUL,
# and `go test` forwards the selector to the test binary as one argument. Keep
# clear of that with room for the flag prefix; fail here instead of at exec if
# even the compact selector outgrows the limit.
MAX_SELECTOR_BYTES = 120_000

# Top-level functions `go test` runs under -run/-skip. Matching is deliberately
# loose (a helper such as `func TestHelper(x int)` is also listed): an extra
# name only shifts balance, while a missed name still runs in the last
# sub-shard. Receivers (`func (r T) TestX`) are methods, never tests.
TEST_FUNC_RE = re.compile(r"^func[ \t]+((?:Test|Fuzz|Example)\w*)[ \t]*[\[(]", re.MULTILINE)
TEST_KIND_PREFIXES = ("Test", "Fuzz", "Example")


def list_packages(
    tags: str, root: Path | None = None, tests_only: bool = False, timeout: float | None = None,
) -> list[str]:
    cmd = ["go", "list"]
    if tags:
        cmd.extend(["-tags", tags])
    if tests_only:
        cmd.extend(["-f", "{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}"])
    cmd.append("./...")
    try:
        result = subprocess.run(cmd, check=True, text=True, capture_output=True, cwd=root or ROOT, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ValueError("changed-test measurement timeout: package discovery") from None
    return [line for line in result.stdout.splitlines() if line]


def package_suffix(package: str) -> str:
    marker = "/internal/"
    if marker not in package:
        return ""
    # Classify from the first internal/ directory. Using the last occurrence
    # would incorrectly move internal/foo/internal/proxy into the proxy shard.
    return "internal/" + package.split(marker, 1)[1]


def package_in_tree(package: str, root: str) -> bool:
    suffix = package_suffix(package)
    return suffix == root or suffix.startswith(root + "/")


def shard_tree(shard: str) -> tuple[str, int, int] | None:
    """Return (tree, sub-shard index, sub-shard count) for a heavy shard."""
    if shard in HEAVY_TREES and TEST_SPLITS.get(shard, 1) == 1:
        return shard, 0, 1
    tree, sep, index = shard.rpartition("-")
    if sep and tree in TEST_SPLITS and index.isdigit():
        count = TEST_SPLITS[tree]
        position = int(index)
        if 0 <= position < count and shard == f"{tree}-{position}":
            return tree, position, count
    return None


# One shard per distinct package list: the first sub-shard of each split tree
# stands for all of its sub-shards, which select the same packages.
PACKAGE_SHARDS = tuple(
    shard for shard in SHARDS if shard in REST_SHARDS or shard_tree(shard)[1] == 0
)


def select_packages(
    packages: list[str], shard: str, package_weights: dict[str, float] | None = None
) -> list[str]:
    """Return the packages a shard runs.

    Rest packages are dealt round-robin by name, or, with measured package
    seconds, packed longest first onto the least-loaded rest shard. Either way
    every rest package lands in exactly one rest shard.
    """
    heavy_roots = tuple(HEAVY_TREES.values())
    if shard in REST_SHARDS:
        rest_packages = sorted(
            pkg for pkg in packages if not any(package_in_tree(pkg, root) for root in heavy_roots)
        )
        shard_index = REST_SHARDS.index(shard)
        if package_weights:
            buckets = partition_names(rest_packages, len(REST_SHARDS), package_weights)
            return buckets[shard_index]
        return [pkg for index, pkg in enumerate(rest_packages) if index % len(REST_SHARDS) == shard_index]

    located = shard_tree(shard)
    if located is None:
        raise ValueError(f"unknown shard {shard!r}")
    wanted = HEAVY_TREES[located[0]]
    selected = [pkg for pkg in packages if package_in_tree(pkg, wanted)]
    if not selected:
        raise ValueError(f"no packages matched shard {shard!r}")
    return selected


def tree_test_names(root: Path) -> list[str]:
    """Inventory top-level test, fuzz and example names under a package tree."""
    names: set[str] = set()
    for directory, subdirs, files in os.walk(root):
        # testdata holds fixtures the go tool never compiles as package tests.
        subdirs[:] = sorted(d for d in subdirs if d != "testdata")
        for filename in files:
            if filename.endswith("_test.go"):
                text = (Path(directory) / filename).read_text(encoding="utf-8", errors="replace")
                names.update(TEST_FUNC_RE.findall(text))
    return sorted(names)


def name_bucket(name: str, count: int) -> int:
    """Stable bucket for a test name: independent of order, run, and hash seed."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % count


def exact_names_regex(names: list[str]) -> str:
    """Return a Go regexp that matches exactly the given top-level names.

    Both anchors sit outside one group, so `TestScan` cannot match
    `TestScanTextForDLP` and nothing can match a longer or shorter name. Names
    share literal prefixes in a radix tree to keep the argument short.
    The pattern contains no `/`, so go test applies it to top-level names and
    leaves every subtest of a selected test to run.
    """
    if not names:
        raise ValueError("refusing to build a selector for an empty name set")

    def compact(values: list[str]) -> str:
        # Sorted endpoints determine the common prefix of the whole group.
        # Consume it at once so long names do not add one stack frame per char.
        prefix = os.path.commonprefix((values[0], values[-1]))
        branches: dict[str, list[str]] = {}
        for value in values:
            rest = value[len(prefix):]
            branches.setdefault(rest[:1], []).append(rest)
        alternatives = [compact(rests) if char else "" for char, rests in branches.items()]
        suffix = alternatives[0] if len(alternatives) == 1 else "(?:" + "|".join(alternatives) + ")"
        # An empty alternative preserves a name that is also another's prefix.
        return re.escape(prefix) + suffix

    return "^(?:" + compact(sorted(set(names))) + ")$"


def load_durations(path: Path = DURATIONS_FILE) -> dict[str, dict[str, float]]:
    """Read measured top-level test seconds per tree; a missing file means none."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    trees = data.get("trees") if isinstance(data, dict) else None
    if not isinstance(trees, dict):
        raise ValueError(f"{path.name}: expected a 'trees' object")
    return {tree: _seconds_map(path, tree, tests) for tree, tests in trees.items()}


def load_package_durations(path: Path = DURATIONS_FILE) -> dict[str, float]:
    """Read measured seconds per rest-shard package; absent means round-robin."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "packages" not in data:
        return {}
    return _seconds_map(path, "packages", data["packages"])


def _seconds_map(path: Path, label: str, values: object) -> dict[str, float]:
    if not isinstance(values, dict):
        raise ValueError(f"{path.name}: {label!r} must map names to seconds")
    clean: dict[str, float] = {}
    for name, seconds in values.items():
        if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or not math.isfinite(seconds) or seconds < 0:
            raise ValueError(f"{path.name}: {label}.{name} must be non-negative seconds")
        clean[name] = float(seconds)
    return clean


def partition_names(
    names: list[str], count: int, weights: dict[str, float] | None = None
) -> list[list[str]]:
    """Split names into count buckets.

    Without weights a name's bucket is a stable hash, which balances counts but
    not time. With measured weights, names are packed longest first onto the
    least-loaded bucket so a few slow tests cannot pile onto one shard. A name
    with no measurement is charged the median measured time. Ties break on the
    bucket index and names are visited in a fixed order, so the result depends
    only on the inputs.
    """
    unique = sorted(set(names))
    buckets: list[list[str]] = [[] for _ in range(count)]
    if not weights:
        for name in unique:
            buckets[name_bucket(name, count)].append(name)
        return buckets
    known = sorted(weights[name] for name in unique if name in weights)
    default = max(known[len(known) // 2] if known else 1.0, MIN_UNMEASURED_SECONDS)
    loads = [0.0] * count
    for name in sorted(unique, key=lambda n: (-weights.get(n, default), n)):
        # Equal loads (including all-zero measurements) fall back to the
        # bucket with the fewest names, so no bucket is left empty.
        target = min(range(count), key=lambda i: (loads[i], len(buckets[i]), i))
        buckets[target].append(name)
        loads[target] += weights.get(name, default)
    for bucket in buckets:
        bucket.sort()
    return buckets


def shard_selector(
    shard: str, names: list[str] | None = None, weights: dict[str, float] | None = None
) -> str:
    """Return the go test selector flag for a shard, or "" when it runs all tests.

    With names omitted, the real inventory and the checked-in durations are
    used. Passing names without weights keeps the unweighted hash split.
    """
    located = shard_tree(shard)
    if located is None or located[2] == 1:
        if located is None and shard not in REST_SHARDS:
            raise ValueError(f"unknown shard {shard!r}")
        return ""
    tree, index, count = located
    return tree_selector(tree, index, count, names, weights, "TEST_SPLITS")


def tree_selector(
    tree: str,
    index: int,
    count: int,
    names: list[str] | None = None,
    weights: dict[str, float] | None = None,
    splits_name: str = "TEST_SPLITS",
) -> str:
    """Return sub-shard index's selector when tree's tests split count ways."""
    if names is None:
        names = tree_test_names(ROOT / HEAVY_TREES[tree])
        if weights is None:
            weights = load_durations().get(tree)
    buckets = partition_names(names, count, weights)
    for position, bucket in enumerate(buckets):
        if not bucket:
            raise ValueError(f"sub-shard {tree}-{position} would select no tests")
    if index < count - 1:
        selector = "-run=" + exact_names_regex(buckets[index])
    else:
        earlier = [name for bucket in buckets[:-1] for name in bucket]
        selector = "-skip=" + exact_names_regex(earlier)
    if len(selector.encode("utf-8")) > MAX_SELECTOR_BYTES:
        if index < count - 1:
            remedy = f"raise {splits_name}[{tree!r}]"
        else:
            # The final sub-shard skips every earlier bucket, so more splits
            # make its selector longer, not shorter.
            remedy = (
                f"the final sub-shard skips every earlier bucket; lower {splits_name}[{tree!r}] "
                "or split the tree's packages into separate heavy trees"
            )
        raise ValueError(
            f"selector for {tree}-{index} is {len(selector)} bytes, over {MAX_SELECTOR_BYTES}; {remedy}"
        )
    return selector


def unit_shard_names() -> tuple[str, ...]:
    """Shard names of the no-race lane, heavy trees first, then rest shards."""
    names: list[str] = []
    for tree in HEAVY_TREES:
        count = UNIT_SPLITS.get(tree, 1)
        names.extend([tree] if count == 1 else [f"{tree}-{index}" for index in range(count)])
    return (*names, *UNIT_REST_SHARDS)


def unit_shard_tree(shard: str) -> tuple[str, int, int] | None:
    """Return (tree, index, count) for a no-race heavy shard, or None for rest."""
    if shard in UNIT_REST_SHARDS:
        return None
    if shard in HEAVY_TREES and UNIT_SPLITS.get(shard, 1) == 1:
        return shard, 0, 1
    tree, sep, index = shard.rpartition("-")
    count = UNIT_SPLITS.get(tree, 1)
    if sep and tree in HEAVY_TREES and count > 1 and index.isdigit() and shard == f"{tree}-{int(index)}":
        if int(index) < count:
            return tree, int(index), count
    raise ValueError(f"unknown no-race shard {shard!r}")


def unit_shard_packages(packages: list[str], shard: str) -> list[str]:
    """Packages a no-race shard runs; rest packages pack into UNIT_REST_SHARDS."""
    located = unit_shard_tree(shard)
    if located is None:
        heavy_roots = tuple(HEAVY_TREES.values())
        rest_packages = sorted(
            pkg for pkg in packages if not any(package_in_tree(pkg, root) for root in heavy_roots)
        )
        buckets = partition_names(rest_packages, len(UNIT_REST_SHARDS), load_package_durations())
        return buckets[UNIT_REST_SHARDS.index(shard)]
    wanted = HEAVY_TREES[located[0]]
    selected = [pkg for pkg in packages if package_in_tree(pkg, wanted)]
    if not selected:
        raise ValueError(f"no packages matched no-race shard {shard!r}")
    return selected


def unit_shard_selector(shard: str, names: list[str] | None = None) -> str:
    """The no-race shard's -run/-skip flag, or "" when it runs every test."""
    located = unit_shard_tree(shard)
    if located is None or located[2] == 1:
        return ""
    tree, index, count = located
    return tree_selector(tree, index, count, names, None, "UNIT_SPLITS")


def selector_selects(selector: str, name: str) -> bool:
    """Evaluate a selector against a top-level name the way go test does."""
    if not selector:
        return True
    flag, _, pattern = selector.partition("=")
    matched = re.search(pattern, name) is not None
    if flag == "-run":
        return matched
    if flag == "-skip":
        return not matched
    raise ValueError(f"unknown selector flag {flag!r}")


def go_test_list(packages: list[str], tags: str) -> list[str]:
    """Top-level names `go test -list` reports, one entry per (package, name)."""
    cmd = ["go", "test"]
    if tags:
        cmd.extend(["-tags", tags])
    cmd.extend(["-list", ".*", *packages])
    result = subprocess.run(cmd, check=True, text=True, capture_output=True, cwd=ROOT)
    names = []
    for line in result.stdout.splitlines():
        # Package status lines ("ok", "?") are not names. Benchmarks never run
        # in these shards (no -bench), so they are not part of the partition.
        if line.startswith(TEST_KIND_PREFIXES):
            names.append(line)
    return names


def partition_errors(listed: list[str], selectors: dict[str, str]) -> list[str]:
    """Return every listed name not selected by exactly one sub-shard."""
    errors = []
    for name in listed:
        picked = [shard for shard, selector in selectors.items() if selector_selects(selector, name)]
        if len(picked) != 1:
            errors.append(f"{name}: selected by {picked or 'no sub-shard'}")
    return errors


def check_partition(tags: str, only_tree: str | None = None) -> int:
    packages = list_packages(tags)
    status = 0
    for tree, count in TEST_SPLITS.items():
        if only_tree is not None and tree != only_tree:
            continue
        shards = [f"{tree}-{index}" for index in range(count)]
        tree_packages = select_packages(packages, shards[0])
        listed = go_test_list(tree_packages, tags)
        selectors = {shard: shard_selector(shard) for shard in shards}
        counts = {
            shard: sum(1 for name in listed if selector_selects(selectors[shard], name))
            for shard in shards
        }
        errors = partition_errors(listed, selectors)
        summary = " + ".join(f"{shard}={counts[shard]}" for shard in shards)
        print(f"{tree} (tags={tags or 'none'}): listed={len(listed)} {summary}")
        if errors or sum(counts.values()) != len(listed):
            status = 1
            for error in errors:
                print(f"  PARTITION ERROR {error}", file=sys.stderr)
    return status


def prediction_plan(tags: str) -> dict:
    """Freeze the inventory and packing weights used on both sides of a pair."""
    return {"trees": load_durations(), "packages": load_package_durations(),
            "names": {tree: tree_test_names(ROOT / root) for tree, root in HEAVY_TREES.items()},
            "inventory": list_packages(tags)}


def predicted_loads(
    tags: str, overrides: dict | None = None, plan: dict | None = None,
) -> dict[str, float]:
    """Predict each shard's test seconds from the checked-in measurements.

    A sub-shard's load is the summed time of its top-level tests; a name with
    no measurement is charged its tree's median. A rest shard's load is its
    summed package time divided by the packages it runs at once, bounded
    below by the longest indivisible package.
    """
    plan = prediction_plan(tags) if plan is None else plan
    baseline = plan["trees"]
    durations = {tree: dict(tests) for tree, tests in baseline.items()}
    for tree, tests in (overrides or {}).get("trees", {}).items():
        durations.setdefault(tree, {}).update(tests)
    loads: dict[str, float] = {}
    for tree, count in TEST_SPLITS.items():
        names = plan["names"][tree]
        weights = durations.get(tree, {})
        known = sorted(baseline.get(tree, {})[name] for name in set(names) if name in baseline.get(tree, {}))
        # Most tests round to 0.0s, so the median can be zero; an unmeasured
        # test must still cost something or a new slow test predicts free.
        default = max(known[len(known) // 2] if known else 1.0, MIN_UNMEASURED_SECONDS)
        # Cost the buckets CI really selects from the checked-in weights. An
        # in-memory repack would claim a balance no runner actually uses yet.
        buckets = partition_names(names, count, baseline.get(tree) or None)
        # Names missed by the cheap source inventory run in the final -skip
        # bucket. AST-selected multiline declarations must still be charged.
        buckets[-1].extend(sorted(set((overrides or {}).get("trees", {}).get(tree, {})) - set(names)))
        for index, bucket in enumerate(buckets):
            loads[f"{tree}-{index}"] = sum(weights.get(name, default) for name in bucket)
    package_baseline = plan["packages"]
    package_weights = dict(package_baseline)
    package_weights.update((overrides or {}).get("packages", {}))
    packages = plan["inventory"]
    known = sorted(package_baseline.values())
    default = max(known[len(known) // 2] if known else 1.0, MIN_UNMEASURED_SECONDS)
    for shard in REST_SHARDS:
        selected = select_packages(packages, shard, package_baseline)
        seconds = [package_weights.get(pkg, default) for pkg in selected]
        loads[shard] = package_makespan(seconds, REST_PACKAGE_PARALLELISM)
    return loads


def package_makespan(seconds: list[float], slots: int) -> float:
    """Worst-case finish time of whole packages run on a fixed number of slots.

    go test -p starts packages in build-graph order, not longest first, so any
    estimate that assumes a good order can come in under the real shard time.
    For any order in which a free slot never sits idle while a package waits,
    the finish time is at most total/slots + (1 - 1/slots) * longest. That
    bound is what the budget is checked against. Three 350s packages on two
    slots therefore predict 700s, and a single package can never be divided.
    """
    if not seconds:
        return 0.0
    slots = max(slots, 1)
    return sum(seconds) / slots + (1 - 1 / slots) * max(seconds)


def _without_introduced(overrides: dict | None, base_overrides: dict | None, introduced: dict) -> dict:
    """Head weights with zero-base names and packages put back at their base cost.

    New tests and packages are stored as 0 on the base and their measured time
    on the head. Restoring that base cost shows the predicted time they add,
    without comparing a re-measured existing test to itself.
    """
    mixed: dict = {"trees": {}, "packages": {}}
    if overrides:
        mixed["trees"] = {tree: dict(tests) for tree, tests in overrides.get("trees", {}).items()}
        mixed["packages"] = dict(overrides.get("packages", {}))
    base_trees = (base_overrides or {}).get("trees", {})
    base_packages = (base_overrides or {}).get("packages", {})
    for tree, names in introduced.get("trees", {}).items():
        weights = mixed["trees"].setdefault(tree, {})
        known = base_trees.get(tree, {})
        for name in names:
            weights[name] = float(known.get(name, 0.0))
    for package in introduced.get("packages", ()):
        mixed["packages"][package] = float(base_packages.get(package, 0.0))
    return mixed


def check_budget(
    tags: str, budget: float, overrides: dict | None = None, base_overrides: dict | None = None,
    plan: dict | None = None, *, introduced: dict | None = None,
) -> int:
    # NaN compares false with everything, so it would pass every shard.
    if not math.isfinite(budget) or budget <= 0:
        print(f"ci_test_packages.py: budget must be a positive finite number of seconds, got {budget}", file=sys.stderr)
        return 2
    plan = prediction_plan(tags) if plan is None else plan
    loads = predicted_loads(tags, overrides, plan)
    base = predicted_loads(tags, base_overrides, plan) if base_overrides is not None else None
    # A name or package with no base weight contributes its full head measurement.
    # That charge is not run-to-run noise. Re-measured existing tests are: with
    # no sourced noise band, failing any increase there would fail unchanged
    # tests, so that increase is reported when the shard was already over.
    new_work: set[str] = set()
    if base is not None and introduced and (introduced.get("trees") or introduced.get("packages")):
        without = predicted_loads(tags, _without_introduced(overrides, base_overrides, introduced), plan)
        for shard, load in loads.items():
            if load > without[shard]:
                new_work.add(shard)
    over = {shard: load for shard, load in loads.items()
            if load > budget and (base is None or base[shard] <= budget or shard in new_work)}
    if base is not None:
        for shard, load in loads.items():
            if shard not in over and base[shard] > budget and load > base[shard]:
                print(f"::warning title=Shard already over budget::{shard} base={base[shard]:.0f}s "
                      f"head={load:.0f}s against the {budget:.0f}s budget; the debt predates this change")
    for shard in SHARDS:
        mark = "  OVER" if shard in over else ""
        comparison = ""
        if base is not None:
            comparison = f" base={base[shard]:.3f}s delta={loads[shard] - base[shard]:+.3f}s"
            debt = max(0.0, base[shard] - budget)
            if debt:
                comparison += f" inherited-debt={debt:.3f}s"
        print(f"{shard:12s} {loads[shard]:9.3f}s{comparison}{mark}")
    if base is not None:
        print(f"Paired predicted shard time: base={sum(base.values()):.3f}s "
              f"head={sum(loads.values()):.3f}s delta={sum(loads.values()) - sum(base.values()):+.3f}s")
    if over:
        if base is not None and any(base[shard] > budget for shard in over):
            why = " because this change added measured tests to a shard already over budget"
        elif base is not None:
            why = " and pushed over by this change"
        else:
            why = ""
        print(
            f"ci_test_packages.py: {len(over)} shard(s) predicted over the {budget:.0f}s budget "
            f"(tags={tags or 'none'}){why}; reduce test cost or review the shard allocation",
            file=sys.stderr,
        )
        return 1
    return 0


def changed_tests(base: str, head: str, tags: str = "") -> list[dict[str, str]]:
    """Compare parsed declarations at Git refs, independent of the working tree."""
    result = subprocess.run(
        ["go", "run", str(ROOT / "scripts/ci_changed_tests.go"), "--base", base, "--head", head, "--tags", tags],
        check=True, capture_output=True, text=True, cwd=ROOT,
    )
    return json.loads(result.stdout)


def runnable_changed_tests(
    tests: list[dict[str, str]], tags: str, import_paths: dict[str, str] | None = None,
) -> dict[str, list[str]]:
    """Use Go's real build constraints, including race, OS and architecture.

    import_paths, when given, receives each selected source directory's import path.
    """
    selected: dict[str, list[str]] = {}
    for package in sorted({test["package"] for test in tests}):
        command = ["go", "list", "-e", "-json", "-tags", ",".join(filter(None, ["race", tags])), package]
        result = subprocess.run(command, check=True, capture_output=True, text=True, cwd=ROOT)
        info = json.loads(result.stdout)
        if not isinstance(info, dict):
            raise ValueError(f"unknown go list classification for {package}")
        # Build-constrained packages have no applicable files. Other errors
        # (such as an invalid package) must not silently become a no-op.
        if info.get("Error"):
            error = info["Error"].get("Err", "")
            # Nested modules are outside the main module's ./... race lane.
            if "main module" in error and "does not contain package" in error:
                continue
            if "build constraints exclude all Go files" in error:
                continue
            raise ValueError(info["Error"])
        if not isinstance(info.get("ImportPath"), str) or not info["ImportPath"]:
            raise ValueError(f"go list returned no import path for {package}")
        files = set(info.get("TestGoFiles", []) + info.get("XTestGoFiles", []))
        # A file this build's constraints exclude (an enterprise-only test in
        # an OSS run) is go list's IgnoredGoFiles; the other edition measures
        # it. A file in neither list is unclassified and fails closed.
        ignored = set(info.get("IgnoredGoFiles", []))
        names: set[str] = set()
        for test in tests:
            if test["package"] != package:
                continue
            name = Path(test["file"]).name
            if name in files:
                names.add(test["name"])
            elif name not in ignored:
                raise ValueError(f"go list did not classify {test['file']} for {package}")
        if not names:
            continue
        selected[info["ImportPath"]] = sorted(names)
        if import_paths is not None:
            import_paths[package] = info["ImportPath"]
    return selected


# Measurement deadline inside the job's 48-minute ceiling, leaving room for
# checkout, module download and compilation before measuring starts.
MEASURE_DEADLINE_SECONDS = 40 * 60
# go test's own -timeout, as on the race lane.
MEASURE_PACKAGE_TIMEOUT_SECONDS = 15 * 60
# Don't start a package with less time than this left.
MEASURE_MIN_START_SECONDS = 60


@contextmanager
def measurement_base(base: str):
    """Check out the resolved base on this runner without moving the head."""
    revision = subprocess.run(
        ["git", "rev-parse", "--verify", base + "^{commit}"],
        check=True, capture_output=True, text=True, cwd=ROOT,
    ).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="ci-changed-base-") as directory:
        root = Path(directory) / "base"
        subprocess.run(["git", "worktree", "add", "--detach", str(root), revision], check=True, cwd=ROOT)
        try:
            yield root
        finally:
            # Tests can write files into the base checkout. A plain remove
            # refuses that dirt and would replace a successful measurement,
            # or a measurement error, with a cleanup failure.
            removed = subprocess.run(
                ["git", "worktree", "remove", "--force", str(root)], cwd=ROOT,
            )
            if removed.returncode != 0 and sys.exc_info()[0] is None:
                raise subprocess.CalledProcessError(removed.returncode, removed.args)


def run_measurement(command: list[str], stream, root: Path, remaining: float) -> int:
    """Bound compilation as well as tests, and reap descendants on timeout."""
    with subprocess.Popen(command, stdout=stream, cwd=root, start_new_session=True) as process:
        try:
            return process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise ValueError("changed-test measurement timeout") from None
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise


def measured_selection(
    selected: dict[str, list[str]], whole: list[str], tags: str, path: Path,
    root: Path, remaining_seconds,
) -> dict:
    if __package__:
        from .ci_test_durations import partial_overrides, selection_path
    else:
        from ci_test_durations import partial_overrides, selection_path
    if not selected:
        return {"trees": {}, "packages": {}}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for package, names in selected.items():
            remaining = remaining_seconds()
            if remaining < MEASURE_MIN_START_SECONDS:
                raise ValueError(f"measurement deadline reached before {package}: {names}")
            # Use one common test timeout on both sides. The outer deadline
            # bounds the pair, including compilation; exhaustion never passes.
            command = ["go", "test", "-race", "-p=1", "-parallel=2",
                       f"-timeout={MEASURE_PACKAGE_TIMEOUT_SECONDS}s", "-count=1", "-json"]
            if tags:
                command.extend(["-tags", tags])
            if package not in whole:
                command.append("-run=" + exact_names_regex(names))
            command.append(package)
            print(f"Measuring {root}: " + shlex.join(command), flush=True)
            if run_measurement(command, stream, root, remaining):
                raise ValueError(f"changed-test race run failed: {package}; inspect {path}")
    selection_path(path).write_text(
        json.dumps({"selected": selected, "whole": whole, "skipped": []}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    # A successful process with no selected test result is not measurement.
    # Skipped tests, including new ones, provide no usable timing evidence.
    completed: set[tuple[str, str]] = set()
    pending: set[tuple[str, str]] = set()
    packages: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        # Build events carry ImportPath, not Package (go help buildjson). Output
        # from a successful build, such as a compiler warning, is not a result;
        # a failed build also fails the go test process, which raises above.
        if isinstance(event, dict) and event.get("Action") == "build-output" and "Package" not in event:
            continue
        if not isinstance(event, dict) or event.get("Package") not in selected:
            raise ValueError(f"unexpected measurement event: {event}")
        package, name, action = event["Package"], event.get("Test"), event.get("Action")
        if action == "skip" and isinstance(name, str):
            # Whole rest packages can contain unrelated platform skips, and a
            # selected test can skip some of its subtests. Neither invalidates
            # the measured total. A selected top-level test must actually run.
            if name in selected[package]:
                raise ValueError(f"selected test skipped: {package}: {name}")
            pending.discard((package, name))
            continue
        if action in ("pass", "fail", "skip"):
            elapsed = event.get("Elapsed")
            if action != "pass" or isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0:
                raise ValueError(f"unusable terminal measurement: {event}")
            if name is None:
                packages.add(package)
            else:
                completed.add((package, name))
                pending.discard((package, name))
        elif action == "run" and isinstance(name, str):
            pending.add((package, name))
    missing = {(pkg, name) for pkg, names in selected.items() for name in names} - completed
    if missing or pending or packages != set(selected):
        raise ValueError(f"selected tests produced no terminal result: {sorted(missing | pending)}; "
                         f"missing packages: {sorted(set(selected) - packages)}")
    return partial_overrides([path])


def merge_overrides(into: dict, more: dict) -> None:
    """Fold one package's measured weights into the run's overrides."""
    for tree, tests in more.get("trees", {}).items():
        weights = into["trees"].setdefault(tree, {})
        for name, seconds in tests.items():
            weights[name] = max(weights.get(name, 0.0), seconds)
    into["packages"].update(more.get("packages", {}))


def measure_changed_tests(
    tests: list[dict[str, str]], tags: str, json_out: Path, base: str,
    deadline_seconds: float = MEASURE_DEADLINE_SECONDS, clock=time.monotonic,
) -> int:
    if __package__:
        from .ci_test_durations import selection_path, tree_for_package
    else:
        from ci_test_durations import selection_path, tree_for_package
    # Resolve even an empty selection: an unknown base must never become a
    # successful "no changed tests" result.
    started = clock()
    with measurement_base(base) as base_root:
        for test in tests:
            if not isinstance(test, dict) or not all(isinstance(test.get(key), str) and test[key]
                                                    for key in ("package", "file", "name")) or type(test.get("new")) is not bool:
                raise ValueError(f"unknown changed-test classification: {test}")
        import_paths: dict[str, str] = {}
        selected = runnable_changed_tests(tests, tags, import_paths) if tests else {}
        if not selected:
            print(f"No added or changed runnable tests (tags={tags or 'none'}); race measurement is a no-op")
            return 0
        plan = prediction_plan(tags)
        new: dict[str, set[str]] = {}
        for test in tests:
            package = import_paths.get(test["package"])
            if package and test["new"] and test["name"] in selected.get(package, []):
                new.setdefault(package, set()).add(test["name"])
        whole = sorted(pkg for pkg in selected if tree_for_package(pkg) is None)
        remaining_seconds = lambda: deadline_seconds - (clock() - started)  # noqa: E731
        # Base discovery can fetch modules the head doesn't share; keep it
        # inside the pair's deadline instead of the job's.
        if remaining_seconds() <= 0:
            raise ValueError("measurement deadline reached before base package discovery")
        base_packages = set(list_packages(",".join(filter(None, ["race", tags])), root=base_root,
                                          tests_only=True, timeout=remaining_seconds()))
        base_selected: dict[str, list[str]] = {}
        for package, names in selected.items():
            existing = sorted(set(names) - new.get(package, set()))
            if package not in base_packages:
                if existing:
                    raise ValueError(f"existing changed tests have no base package: {package}: {existing}")
            elif package in whole or existing:
                base_selected[package] = existing
        base_path = json_out.with_suffix(".base.json")
        # A new test has no recorded weight, so its head run is the one
        # measurement the gate can't do without. Measure every package with new
        # tests at head first, then their bases while time remains, then pair
        # each edited-only package base-then-head. A base that misses the
        # deadline keeps its recorded weight, the comparator the gate used
        # before paired runs; a skipped edited-only pair keeps its recorded
        # weight on both sides, so that pair stays comparable. Pairing every
        # new-test package first spent the deadline on whole rest packages'
        # bases before the last new test was reached.
        new_order = sorted(pkg for pkg in selected if pkg in new)
        edited_order = sorted(pkg for pkg in selected if pkg not in new)
        overrides: dict = {"trees": {}, "packages": {}}
        base_overrides: dict = {"trees": {}, "packages": {}}
        head_streams: list[Path] = []
        base_streams: list[Path] = []
        measured: list[str] = []
        skipped: list[str] = []
        base_measured: set[str] = set()
        base_skipped: list[str] = []
        base_seconds = head_seconds = 0.0
        streams = iter(range(len(selected) * 2))

        def measure(package: str, base_side: bool) -> dict:
            nonlocal base_seconds, head_seconds
            index = next(streams)
            stream = json_out.with_suffix(f".{'base' if base_side else 'head'}.{index}.json")
            names = base_selected[package] if base_side else selected[package]
            pair_started = clock()
            result = measured_selection(
                {package: names}, [package] if package in whole else [], tags, stream,
                base_root if base_side else ROOT, remaining_seconds,
            )
            if base_side:
                base_seconds += clock() - pair_started
                base_streams.append(stream)
                base_measured.add(package)
            else:
                head_seconds += clock() - pair_started
                head_streams.append(stream)
                measured.append(package)
            return result

        for package in new_order:
            if remaining_seconds() < MEASURE_MIN_START_SECONDS:
                raise ValueError(
                    f"measurement deadline reached before {package}; new tests have no recorded "
                    f"weight, so they can't be left unmeasured: {sorted(new[package])}. Split the "
                    "pull request or record their weights from a full race run.")
            merge_overrides(overrides, measure(package, base_side=False))
        for package in new_order:
            if package not in base_selected:
                continue
            if remaining_seconds() < MEASURE_MIN_START_SECONDS:
                base_skipped.append(package)
                continue
            merge_overrides(base_overrides, measure(package, base_side=True))
        for package in edited_order:
            pair_base_overrides = None
            if remaining_seconds() >= MEASURE_MIN_START_SECONDS and package in base_selected:
                pair_base_overrides = measure(package, base_side=True)
            if remaining_seconds() < MEASURE_MIN_START_SECONDS:
                if pair_base_overrides is not None:
                    # Without its head, a lone base would compare against the
                    # recorded head weight; drop it so the pair stays comparable.
                    base_streams.pop()
                    base_measured.discard(package)
                skipped.append(package)
                continue
            merge_overrides(overrides, measure(package, base_side=False))
            if pair_base_overrides is not None:
                merge_overrides(base_overrides, pair_base_overrides)
        for target, streams in ((json_out, head_streams), (base_path, base_streams)):
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("w", encoding="utf-8") as stream:
                for part in streams:
                    stream.write(part.read_text(encoding="utf-8"))
        for package in skipped:
            print(f"::warning title=Changed test not re-measured::{package} kept its recorded weight on "
                  f"both sides; the {deadline_seconds:.0f}s measurement deadline was reached")
        for package in base_skipped:
            print(f"::warning title=Changed test base not re-measured::{package} was measured at head; "
                  f"its base kept its recorded weight because the {deadline_seconds:.0f}s measurement "
                  "deadline was reached")
        selection_path(json_out).write_text(json.dumps({
            "new": {pkg: sorted(names) for pkg, names in new.items()},
            "selected": selected, "whole": [pkg for pkg in whole if pkg in measured],
            "skipped": skipped,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        selection_path(base_path).write_text(json.dumps({
            "selected": {pkg: base_selected[pkg] for pkg in sorted(base_measured)},
            "whole": [pkg for pkg in whole if pkg in base_measured],
            "skipped": sorted(pkg for pkg in [*skipped, *base_skipped] if pkg in base_selected),
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        introduced: dict[str, dict | list] = {"trees": {}, "packages": []}
        for package, names in new.items():
            tree = tree_for_package(package)
            if tree is not None:
                # Full head measurement against an explicit zero base weight.
                base_overrides["trees"].setdefault(tree, {}).update(dict.fromkeys(names, 0.0))
                introduced["trees"].setdefault(tree, []).extend(names)
            elif package not in base_packages:
                # No base package total exists to subtract. An existing rest
                # package is measured whole on both sides, so a new test inside
                # it stays on the re-measured path.
                base_overrides["packages"][package] = 0.0
                introduced["packages"].append(package)
        for tree in introduced["trees"]:
            introduced["trees"][tree] = sorted(set(introduced["trees"][tree]))
        introduced["packages"] = sorted(set(introduced["packages"]))
        # Tree weights are keyed by test name. If a measured package, or a new
        # test's zero base, shares a name with a skipped package, it must not
        # lower that skipped test's recorded weight on either side. Applied
        # after the zero-base charge so a shared name keeps its recorded base.
        for package in skipped:
            tree = tree_for_package(package)
            recorded = plan.get("trees", {}).get(tree, {}) if tree is not None else {}
            if tree is None:
                continue
            for name in selected[package]:
                for side in (overrides, base_overrides):
                    weights = side["trees"].get(tree, {})
                    if name in weights:
                        weights[name] = max(weights[name], float(recorded.get(name, 0.0)))
                    elif name in recorded:
                        # The cheap declaration inventory can miss a name; an
                        # explicit override keeps its recorded load counted.
                        side["trees"].setdefault(tree, {})[name] = float(recorded[name])
        print(f"Paired measurement wall time: {clock() - started:.3f}s "
              f"(shared deadline {deadline_seconds:.0f}s; base={base_seconds:.3f}s/{len(base_selected)} packages, "
              f"head={head_seconds:.3f}s/{len(selected)} packages)")
        return check_budget(
            tags, SHARD_BUDGET_SECONDS, overrides, base_overrides, plan, introduced=introduced,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Select CI package shard")
    parser.add_argument("--shard", choices=SHARDS, help="shard to print")
    parser.add_argument(
        "--unit-shard",
        choices=unit_shard_names(),
        help="no-race lane shard to print (packages, or its selector with --selector)",
    )
    parser.add_argument(
        "--fresh",
        choices=("only", "exclude"),
        help="with --unit-shard: print only the packages that must run with -count=1, or all the others",
    )
    parser.add_argument(
        "--list-unit-shards",
        action="store_true",
        help="print the no-race lane's shard names as a JSON list",
    )
    parser.add_argument("--tags", default="", help="go build tags for go list")
    parser.add_argument(
        "--selector",
        action="store_true",
        help="print the go test -run/-skip flag for the shard instead of its packages",
    )
    parser.add_argument(
        "--check-partition",
        action="store_true",
        help="verify sub-shard selectors against go test -list (scoped to --shard's tree if given)",
    )
    parser.add_argument(
        "--check-budget",
        action="store_true",
        help="fail when the checked-in measurements predict any shard over the budget",
    )
    parser.add_argument(
        "--budget-seconds",
        type=float,
        default=SHARD_BUDGET_SECONDS,
        help=f"predicted-load budget per shard (default {SHARD_BUDGET_SECONDS})",
    )
    parser.add_argument("--measurement-json", nargs="+", type=Path,
                        help="override weights with partial changed-test race JSON streams")
    parser.add_argument("--changed-tests-base", help="base revision for AST test selection")
    parser.add_argument("--changed-tests-head", default="HEAD", help="head revision for AST test selection")
    parser.add_argument("--measure-changed-tests", action="store_true", help="race-test the changed selection and check budget")
    parser.add_argument("--json-out", type=Path, default=Path("changed-tests.json"), help="changed-test race JSON output")
    args = parser.parse_args()

    try:
        if args.changed_tests_base:
            tests = changed_tests(args.changed_tests_base, args.changed_tests_head, args.tags)
            if args.measure_changed_tests:
                return measure_changed_tests(tests, args.tags, args.json_out, args.changed_tests_base)
            print(json.dumps(tests, indent=2))
            return 0
        if args.measure_changed_tests:
            parser.error("--measure-changed-tests needs --changed-tests-base")
        if args.list_unit_shards:
            print(json.dumps(list(unit_shard_names())))
            return 0
        if args.unit_shard:
            if args.selector:
                print(unit_shard_selector(args.unit_shard))
                return 0
            packages = unit_shard_packages(list_packages(args.tags), args.unit_shard)
            if args.fresh:
                fresh = set(fresh_packages(packages, args.tags))
                packages = [p for p in packages if (p in fresh) == (args.fresh == "only")]
            print(" ".join(packages))
            return 0
        if args.check_budget:
            overrides = None
            if args.measurement_json:
                if __package__:
                    from .ci_test_durations import partial_overrides
                else:
                    from ci_test_durations import partial_overrides
                overrides = partial_overrides(args.measurement_json)
            return check_budget(args.tags, args.budget_seconds, overrides)
        if args.check_partition:
            tree = None
            if args.shard:
                located = shard_tree(args.shard)
                if located is None or located[2] == 1:
                    print(f"{args.shard} runs every test of its packages; no partition to check")
                    return 0
                tree = located[0]
            return check_partition(args.tags, tree)
        if not args.shard:
            parser.error("--shard is required")
        if args.selector:
            print(shard_selector(args.shard))
            return 0
        packages = select_packages(list_packages(args.tags), args.shard, load_package_durations())
    except (subprocess.CalledProcessError, ValueError, OSError) as err:
        print(f"ci_test_packages.py: {err}", file=sys.stderr)
        return 1

    print(" ".join(packages))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
