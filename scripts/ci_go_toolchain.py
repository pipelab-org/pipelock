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
  ``uses`` ref, ``if`` condition, ``with`` inputs, and the matrix entries an
  input reads (release.yaml pins ``go-version: ${{ matrix.go.version }}``, so a
  version bump edits only ``matrix.go``, while its shard list is not read by
  setup-go);
* changes a ``GOTOOLCHAIN`` setting in any workflow, job, or step environment,
  or a ``run`` script that mentions GOTOOLCHAIN.

An existing job must keep exactly the setup-go steps and GOTOOLCHAIN settings
it had. A new job counts only when it brings one no job had at the base.
Simultaneous scope removals and additions must preserve the removed records
exactly, or a rename could hide a switch to a version already used elsewhere.

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
# Contexts an expression can read (GitHub Actions expression contexts). A
# dotted matrix key is resolved exactly; runtime contexts (step outputs, needs,
# github, runner) cannot be resolved from a diff, so only the expression text
# is recorded; every other reference (env, vars, inputs, bracket indexing, a
# bare matrix) records the scope's whole env, inputs and matrix instead.
# https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)
CONTEXT_REF_RE = re.compile(r"\b(matrix|env|vars|inputs|needs|github|steps|jobs?|runner|secrets|strategy)\b\s*([.\[]?)")
DOTTED_MATRIX_RE = re.compile(r"\bmatrix\.([A-Za-z_][A-Za-z0-9_-]*)")
RUNTIME_CONTEXTS = frozenset({"needs", "github", "steps", "job", "jobs", "runner", "secrets", "strategy"})

Git = Callable[[list[str]], str]
Scopes = dict[str, list[str]]


class Unparsed(Exception):
    """A workflow file at one revision that could not be read as YAML."""


def git(args: list[str]) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def is_setup_go(step: dict) -> bool:
    uses = step.get("uses")
    return isinstance(uses, str) and (uses == SETUP_GO or uses.startswith(SETUP_GO + "@"))


def is_local(uses: object) -> bool:
    return isinstance(uses, str) and uses.startswith("./")


def env_toolchain(env: object) -> object:
    return env.get(TOOLCHAIN_ENV) if isinstance(env, dict) else None


def expression_texts(value: object, condition: object = None) -> list[str]:
    """Return the expression bodies in a value, plus a step or job condition.

    A condition is an expression with or without ${{ }}.
    """
    texts = EXPRESSION_RE.findall(canonical(value))
    if isinstance(condition, str):
        texts += EXPRESSION_RE.findall(condition) or [condition]
    elif condition is not None:
        texts.append(canonical(condition))
    return texts


def project_matrix(keys: set[str], matrix: object) -> object:
    """Keep the matrix keys an expression reads, and every include/exclude.

    release.yaml's matrix holds both the Go versions and the shard list; a
    shard change must not count as a toolchain change. Include and exclude
    entries match on every dimension, so they stay whole. An unrecognized
    matrix shape (a fromJSON expression, say) is kept whole.
    """
    if not isinstance(matrix, dict):
        return matrix
    projected: dict[str, object] = {key: matrix.get(key) for key in sorted(keys)}
    for extra in ("include", "exclude"):
        if extra in matrix:
            projected[extra] = matrix[extra]
    return projected


def dependencies(texts: list[str], context: dict) -> dict:
    """Return the parts of a scope that a set of expressions can read."""
    keys: set[str] = set()
    whole = False
    for text in texts:
        for match in CONTEXT_REF_RE.finditer(text):
            name, accessor = match.group(1), match.group(2)
            if name in RUNTIME_CONTEXTS:
                continue
            if name == "matrix" and accessor == ".":
                continue
            whole = True
        keys |= set(DOTTED_MATRIX_RE.findall(text))
    if whole:
        return {"context": context}
    if keys:
        return {"matrix": project_matrix(keys, context.get("matrix"))}
    return {}


def step_records(steps: object, context: dict, version_files: set[str]) -> list[str]:
    records = []
    if not isinstance(steps, list):
        return records
    for step in steps:
        if not isinstance(step, dict):
            continue
        condition = step.get("if")
        step_context = {**context, "step_env": step.get("env")}
        if is_setup_go(step):
            inputs = step.get("with") if isinstance(step.get("with"), dict) else {}
            entry = {"uses": step["uses"], "with": inputs, "if": condition}
            entry.update(dependencies(expression_texts(inputs, condition), step_context))
            records.append(canonical(["setup-go", entry]))
            version_file = inputs.get("go-version-file")
            if isinstance(version_file, str):
                version_files.add(version_file)
        elif is_local(step.get("uses")):
            # A local action or workflow can forward these inputs to setup-go.
            inputs = step.get("with")
            entry = {"uses": step["uses"], "with": inputs, "if": condition}
            entry.update(dependencies(expression_texts(inputs, condition), step_context))
            records.append(canonical(["local-action", entry]))
        if env_toolchain(step.get("env")) is not None:
            value = step["env"][TOOLCHAIN_ENV]
            entry = {"value": value, "if": condition}
            entry.update(dependencies(expression_texts(value, condition), step_context))
            records.append(canonical([TOOLCHAIN_ENV, entry]))
        run = step.get("run")
        if isinstance(run, str) and TOOLCHAIN_ENV in run:
            entry = {"run": run, "if": condition}
            entry.update(dependencies(expression_texts(run, condition), step_context))
            records.append(canonical(["run", entry]))
    return records


def toolchain_env_record(env: object, context: dict) -> list[str]:
    if env_toolchain(env) is None:
        return []
    value = env[TOOLCHAIN_ENV]
    entry = {"value": value}
    entry.update(dependencies(expression_texts(value), context))
    return [canonical([TOOLCHAIN_ENV, entry])]


def file_records(path: str, text: str, version_files: set[str]) -> Scopes:
    """Map each scope (a job, or a file's top level) to its ordered records."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise Unparsed(f"{path}: {exc}") from exc
    scopes: Scopes = {}
    if not isinstance(doc, dict):
        return scopes
    # PyYAML reads the bare key `on` as boolean true.
    triggers = doc.get("on", doc.get(True))
    call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
    inputs = call.get("inputs") if isinstance(call, dict) else doc.get("inputs")
    context = {"workflow_env": doc.get("env"), "inputs": inputs}
    top = toolchain_env_record(doc.get("env"), context)
    runs = doc.get("runs")
    if isinstance(runs, dict):
        top += step_records(runs.get("steps"), context, version_files)
    # Retain empty scopes: removing their last record still changes the
    # toolchain of a workflow, job or composite action that continues to run.
    scopes[path] = top
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            strategy = job.get("strategy")
            matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
            job_context = {**context, "job_env": job.get("env"), "matrix": matrix}
            records = toolchain_env_record(job.get("env"), job_context)
            if is_local(job.get("uses")):
                entry = {"uses": job["uses"], "with": job.get("with"), "if": job.get("if")}
                entry.update(dependencies(expression_texts(job.get("with"), job.get("if")), job_context))
                records.append(canonical(["reusable-workflow", entry]))
            records += step_records(job.get("steps"), job_context, version_files)
            scopes[f"{path}#{job_id}"] = records
    return scopes


def revision_records(rev: str, run_git: Git) -> tuple[Scopes, set[str]]:
    listed = run_git(["ls-tree", "-rz", "--name-only", rev, "--", ".github/"])
    scopes: Scopes = {}
    version_files: set[str] = set()
    for path in sorted(p for p in listed.split("\0") if STEP_FILES_RE.match(p)):
        scopes.update(file_records(path, run_git(["show", f"{rev}:{path}"]), version_files))
    return scopes, version_files


def compare(before: Scopes, after: Scopes) -> list[str]:
    """Name every way the head runs Go differently from the base.

    A scope at both revisions must keep exactly its records, in order: a later
    setup-go step replaces an earlier one. A new scope changes the toolchain
    only when it brings a record no base scope has exactly, condition
    included: a new job that installs a Go version CI already installs, the
    same way, runs nothing new. A removed scope alone cannot introduce a
    toolchain; check-go-matrix.sh owns whether the remaining jobs still cover
    every supported Go minor. When scopes are both removed and added, match
    their complete record sets before allowing known pins: job and workflow
    renames must not hide changes.
    """
    known = {record for records in before.values() for record in records}
    reasons = []
    for scope in sorted(after):
        if scope in before:
            old, new = Counter(before[scope]), Counter(after[scope])
            for record in sorted((old - new).elements()):
                reasons.append(f"{scope} removed: {record}")
            for record in sorted((new - old).elements()):
                reasons.append(f"{scope} added: {record}")
            if old == new and before[scope] != after[scope]:
                reasons.append(f"{scope} reordered its toolchain steps")
        else:
            reasons += [f"{scope} (new) added: {record}" for record in sorted(after[scope]) if record not in known]
    removed = Counter(canonical(sorted(before[scope])) for scope in before.keys() - after.keys() if before[scope])
    added = Counter(canonical(sorted(after[scope])) for scope in after.keys() - before.keys() if after[scope])
    if removed - added and added - removed:
        reasons.append("removed and added toolchain scopes do not preserve the same records")
    return reasons


def changed_paths(merge_base: str, head: str, paths: list[str], run_git: Git) -> list[str]:
    output = run_git(["diff", "-z", "--name-only", merge_base, head, "--", *paths])
    return [path for path in output.split("\0") if path]


def toolchain_changed(base: str, head: str, run_git: Git = git) -> tuple[bool, list[str]]:
    merge_base = run_git(["merge-base", base, head]).strip()
    touched = changed_paths(merge_base, head, list(TOOLCHAIN_PATHS), run_git)
    if touched:
        return True, [f"toolchain file changed: {path}" for path in touched]
    try:
        before, before_files = revision_records(merge_base, run_git)
        after, after_files = revision_records(head, run_git)
    except Unparsed as exc:
        return True, [f"workflow does not parse, so it cannot be ruled out: {exc}"]
    reasons = []
    version_files = before_files | after_files
    unresolved = sorted(path for path in version_files if EXPRESSION_RE.search(path))
    reasons += [f"go-version-file is an expression, so its file cannot be tracked: {path}" for path in unresolved]
    literal = sorted(path.removeprefix("./") for path in version_files - set(unresolved))
    if literal:
        reasons += [f"go-version-file changed: {path}" for path in changed_paths(merge_base, head, literal, run_git)]
    reasons += compare(before, after)
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
