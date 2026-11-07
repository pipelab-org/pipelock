#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Decide whether a change can alter which Go toolchain CI builds with.

Pull requests skip the Go 1.27 race matrices because, outside a toolchain
change, they only ever caught timing flakes, never a version-specific failure
(see ci.yaml's test-oss-go127 job). This decides when a change IS a toolchain
change, so those matrices run exactly then.

Go selects its toolchain from the ``go`` and ``toolchain`` lines of go.mod and
the ``GOTOOLCHAIN`` environment variable (https://go.dev/doc/toolchain), and
CI installs it with actions/setup-go. A change is a toolchain change when it:

* touches go.mod or go.sum (the module's Go line, toolchain line, and the
  dependency set both versions compile);
* touches scripts/check-go-matrix.sh, which keeps the CI and release Go
  versions in step, or this script, which decides when they are proven;
* changes a setup-go step in a workflow or local composite action: its
  ``uses`` ref, its ``with`` inputs, and the matrix entries an input reads
  (release.yaml pins ``go-version: ${{ matrix.go.version }}``, so a version
  bump edits only ``matrix.go``, while its shard list is not read by setup-go);
* changes a ``GOTOOLCHAIN`` setting in any workflow, job, or step environment,
  or a ``run`` script that mentions GOTOOLCHAIN.

An existing job must keep exactly the setup-go steps and GOTOOLCHAIN settings
it had. A new job counts only when it brings one no job had at the base.

Setup-go steps are compared parsed, not as text, the way check-go-matrix.sh
reads pins: renaming or reordering steps, editing shard lists, timeouts, or
any other job content is not a toolchain change. Comparison is from the merge
base, matching ``git diff BASE...HEAD``.

Prints ``true`` or ``false``. A git failure exits non-zero, so the calling
step fails and the required test (1.27) check refuses to accept skipped race
matrices. A workflow that does not parse at either revision counts as a
toolchain change: the proof runs rather than being skipped on a guess.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from typing import Callable

import yaml

TOOLCHAIN_PATHS = ("go.mod", "go.sum", "scripts/check-go-matrix.sh", "scripts/ci_go_toolchain.py")
STEP_FILES_RE = re.compile(r"^\.github/(?:workflows/[^/]+|actions/.+/action)\.ya?ml$")
SETUP_GO = "actions/setup-go"
TOOLCHAIN_ENV = "GOTOOLCHAIN"
MATRIX_REF_RE = re.compile(r"\bmatrix\.([A-Za-z0-9_-]+)")

Git = Callable[[list[str]], str]


class Unparsed(Exception):
    """A workflow file at one revision that could not be read as YAML."""


def git(args: list[str]) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def is_setup_go(step: dict) -> bool:
    uses = step.get("uses")
    return isinstance(uses, str) and (uses == SETUP_GO or uses.startswith(SETUP_GO + "@"))


def env_toolchain(env: object) -> object:
    return env.get(TOOLCHAIN_ENV) if isinstance(env, dict) else None


def referenced_matrix(inputs: dict, matrix: object) -> object:
    """Return only the parts of a job matrix that setup-go inputs read.

    release.yaml's matrix holds both the Go versions and the shard list; a
    shard change must not count as a toolchain change. An unrecognized matrix
    shape (a fromJSON expression, say) is kept whole.
    """
    keys = sorted(set(MATRIX_REF_RE.findall(canonical(inputs))))
    if not isinstance(matrix, dict):
        return matrix
    projected: dict[str, object] = {key: matrix.get(key) for key in keys}
    for extra in ("include", "exclude"):
        entries = matrix.get(extra)
        if isinstance(entries, list):
            projected[extra] = [
                {key: entry[key] for key in keys if key in entry} if isinstance(entry, dict) else entry
                for entry in entries
            ]
        elif entries is not None:
            projected[extra] = entries
    return projected


def step_records(steps: object, matrix: object) -> list[str]:
    records = []
    if not isinstance(steps, list):
        return records
    for step in steps:
        if not isinstance(step, dict):
            continue
        if is_setup_go(step):
            inputs = step.get("with") if isinstance(step.get("with"), dict) else {}
            entry = {"uses": step["uses"], "with": inputs}
            if MATRIX_REF_RE.search(canonical(inputs)):
                entry["matrix"] = referenced_matrix(inputs, matrix)
            records.append(canonical(["setup-go", entry]))
        if env_toolchain(step.get("env")) is not None:
            records.append(canonical([TOOLCHAIN_ENV, step["env"][TOOLCHAIN_ENV]]))
        run = step.get("run")
        if isinstance(run, str) and TOOLCHAIN_ENV in run:
            records.append(canonical(["run", run]))
    return records


def file_records(path: str, text: str) -> dict[str, Counter[str]]:
    """Map each scope (a job, or a file's top level) to its toolchain records."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise Unparsed(f"{path}: {exc}") from exc
    scopes: dict[str, Counter[str]] = {}
    if not isinstance(doc, dict):
        return scopes
    top: Counter[str] = Counter()
    if env_toolchain(doc.get("env")) is not None:
        top[canonical([TOOLCHAIN_ENV, doc["env"][TOOLCHAIN_ENV]])] += 1
    runs = doc.get("runs")
    if isinstance(runs, dict):
        top.update(step_records(runs.get("steps"), None))
    if top:
        scopes[path] = top
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            records: Counter[str] = Counter()
            if env_toolchain(job.get("env")) is not None:
                records[canonical([TOOLCHAIN_ENV, job["env"][TOOLCHAIN_ENV]])] += 1
            strategy = job.get("strategy")
            matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
            records.update(step_records(job.get("steps"), matrix))
            if records:
                scopes[f"{path}#{job_id}"] = records
    return scopes


def revision_records(rev: str, run_git: Git) -> dict[str, Counter[str]]:
    listed = run_git(["ls-tree", "-r", "--name-only", rev, "--", ".github/"])
    scopes: dict[str, Counter[str]] = {}
    for path in sorted(p for p in listed.splitlines() if STEP_FILES_RE.match(p)):
        scopes.update(file_records(path, run_git(["show", f"{rev}:{path}"])))
    return scopes


def compare(before: dict[str, Counter[str]], after: dict[str, Counter[str]]) -> list[str]:
    """Name every way the head runs Go differently from the base.

    A scope at both revisions must keep exactly its records. A new scope
    changes the toolchain only when it brings a record no base scope has: a
    new job that installs a Go version CI already installs runs nothing new.
    A removed scope cannot introduce a toolchain; check-go-matrix.sh owns
    whether the remaining jobs still cover every supported Go minor.
    """
    known = set().union(*before.values()) if before else set()
    reasons = []
    for scope in sorted(after):
        if scope in before:
            for record in sorted((before[scope] - after[scope]).elements()):
                reasons.append(f"{scope} removed: {record}")
            for record in sorted((after[scope] - before[scope]).elements()):
                reasons.append(f"{scope} added: {record}")
        else:
            reasons += [f"{scope} (new) added: {record}" for record in sorted(set(after[scope]) - known)]
    return reasons


def toolchain_changed(base: str, head: str, run_git: Git = git) -> tuple[bool, list[str]]:
    merge_base = run_git(["merge-base", base, head]).strip()
    touched = run_git(["diff", "--name-only", merge_base, head, "--", *TOOLCHAIN_PATHS]).split()
    if touched:
        return True, [f"toolchain file changed: {path}" for path in touched]
    step_files = [
        path for path in run_git(["diff", "--name-only", merge_base, head, "--", ".github/"]).split()
        if STEP_FILES_RE.match(path)
    ]
    if not step_files:
        return False, []
    try:
        before = revision_records(merge_base, run_git)
        after = revision_records(head, run_git)
    except Unparsed as exc:
        return True, [f"workflow does not parse, so it cannot be ruled out: {exc}"]
    reasons = compare(before, after)
    return bool(reasons), reasons


def main(argv: list[str] | None = None, run_git: Git = git) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", help="pull request or merge group base commit")
    parser.add_argument("head", help="pull request or merge group head commit")
    args = parser.parse_args(argv)
    try:
        changed, reasons = toolchain_changed(args.base, args.head, run_git)
    except subprocess.CalledProcessError as exc:
        print(f"ci_go_toolchain: git {' '.join(exc.cmd[1:])} failed: {(exc.stderr or '').strip()}", file=sys.stderr)
        return 1
    for reason in reasons:
        print(reason, file=sys.stderr)
    print("true" if changed else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
