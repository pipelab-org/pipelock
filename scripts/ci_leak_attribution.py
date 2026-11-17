#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Name the tests that were running when a leaked CI process started.

The process supervisor reports each descendant that outlived the command with
its start time, never its arguments. A go test -json stream records when each
test started and ended, so the tests running at a leaked process's start time
include the one that spawned it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


MAX_TESTS_PER_PROCESS = 20
# /proc start times are in clock ticks and the stream in nanoseconds. Widen
# each test window slightly so a spawn at a window edge still matches.
EDGE_SECONDS = 0.05
_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_time(value: object) -> float | None:
    """Return a go test -json Time as Unix seconds, or None when unusable."""
    if not isinstance(value, str) or not value:
        return None
    # Python's parser accepts at most microseconds; go test emits nanoseconds.
    text = _FRACTION.sub(r"\1", value.replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def collect_windows(lines) -> list[tuple[str, str, float, float | None]]:
    """Collect (package, test, start, end) for every test in a JSON stream."""
    starts: dict[tuple[str, str], float] = {}
    windows: list[tuple[str, str, float, float | None]] = []
    for line in lines:
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(event, dict):
            continue
        test, package = event.get("Test"), event.get("Package")
        if not isinstance(test, str) or not test or not isinstance(package, str):
            continue
        at = parse_time(event.get("Time"))
        if at is None:
            continue
        key = (package, test)
        action = event.get("Action")
        if action == "run":
            starts[key] = at
        elif action in ("pass", "fail", "skip") and key in starts:
            windows.append((package, test, starts.pop(key), at))
    # A test still open when the stream ended was running until the end.
    windows.extend((package, test, start, None) for (package, test), start in starts.items())
    return windows


def running_at(windows, moment: float) -> list[str]:
    """Return the tests running at moment, most specific (deepest) first."""
    names = [
        f"{package} {test}"
        for package, test, start, end in windows
        if start - EDGE_SECONDS <= moment and (end is None or moment <= end + EDGE_SECONDS)
    ]
    return sorted(set(names), key=lambda name: (-name.count("/"), name))


def attribute(report: dict, lines) -> list[str]:
    """Describe each leaked process with the tests running when it started."""
    processes = report.get("cleanup_processes")
    if not isinstance(processes, list):
        return []
    windows = None
    messages = []
    for entry in processes:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "unavailable")
        pid = entry.get("pid", "?")
        started = entry.get("started_unix")
        if not isinstance(started, (int, float)):
            messages.append(f"leaked process {name} (pid {pid}): start time unavailable")
            continue
        if windows is None:
            windows = collect_windows(lines)
        stamp = datetime.fromtimestamp(started, tz=timezone.utc).isoformat(timespec="milliseconds")
        tests = running_at(windows, float(started))
        if not tests:
            messages.append(f"leaked process {name} (pid {pid}) started at {stamp}; no test was running then")
            continue
        shown = tests[:MAX_TESTS_PER_PROCESS]
        more = len(tests) - len(shown)
        suffix = f" (+{more} more)" if more > 0 else ""
        messages.append(
            f"leaked process {name} (pid {pid}) started at {stamp} while these tests ran{suffix}:\n  "
            + "\n  ".join(shown)
        )
    return messages


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("supervision", type=Path, help="process supervisor status file")
    parser.add_argument("events", type=Path, help="go test -json output")
    args = parser.parse_args()
    try:
        report = json.loads(args.supervision.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    if not isinstance(report, dict):
        return 0
    try:
        with args.events.open(encoding="utf-8", errors="replace") as stream:
            messages = attribute(report, stream)
    except OSError:
        return 0
    for message in messages:
        print(f"ci-leak-attribution: {message}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
