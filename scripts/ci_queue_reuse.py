#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Decide whether a merge-queue run can reuse a green pull request result.

The merge queue builds one candidate at a time. When main has not moved since
the pull request's last green CI run, the queue candidate has exactly the tree
that run already proved, and running the whole suite again buys nothing.

This prints ``queue_tree_tested=true`` only when every link is verified:

* the queue ref is GitHub's own ``gh-readonly-queue/<base>/pr-<n>-<base sha>``
  form, and the base sha it names is the merge group's base;
* a successful ``pull_request`` run of this exact workflow exists for the pull
  request's current head;
* that run uploaded a ``ci-tested-tree`` artifact naming the tree it tested;
* that tree equals the queue candidate's tree.

Anything else, including every API, git, or parse error, prints
``queue_tree_tested=false`` so the queue runs the full suite. The reason goes
to stderr. The script never exits non-zero for a lookup problem: failing here
would red the classifier and every required check behind it, which turns a
missed optimization into a blocked merge.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import sys
import zipfile
from typing import Callable

ARTIFACT_NAME = "ci-tested-tree"
ARTIFACT_FILE = "tested-tree"
# GitHub names queue branches gh-readonly-queue/<base>/pr-<number>-<base sha>:
# the sha is the base commit the candidate was built on, not the PR head.
QUEUE_REF_RE = re.compile(r"^(?:refs/heads/)?gh-readonly-queue/[^/]+(?:/[^/]+)*/pr-([1-9][0-9]*)-([0-9a-f]{40})$")
TREE_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
# Newest first; a few attempts cover reruns without walking a long history.
MAX_RUNS = 5
MAX_ARTIFACT_BYTES = 64 * 1024

Api = Callable[[str], bytes]
Git = Callable[[list[str]], str]


class Refusal(Exception):
    """A verified reason the queue must run the full suite."""


def gh_api(path: str) -> bytes:
    completed = subprocess.run(
        ["gh", "api", "-X", "GET", path],
        check=True, capture_output=True, timeout=60,
    )
    return completed.stdout


def git(args: list[str]) -> str:
    completed = subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True, timeout=60,
    )
    return completed.stdout.strip()


def api_json(api: Api, path: str) -> dict:
    value = json.loads(api(path))
    if not isinstance(value, dict):
        raise Refusal(f"{path} did not return an object")
    return value


def tested_tree_from_zip(data: bytes) -> str:
    if len(data) > MAX_ARTIFACT_BYTES:
        raise Refusal("tested-tree artifact is unexpectedly large")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        if names != [ARTIFACT_FILE]:
            raise Refusal(f"tested-tree artifact holds {names!r}, not exactly {ARTIFACT_FILE!r}")
        info = archive.getinfo(ARTIFACT_FILE)
        if info.file_size > 256:
            raise Refusal("tested-tree file is unexpectedly large")
        tree = archive.read(ARTIFACT_FILE).decode("ascii").strip()
    if not TREE_RE.fullmatch(tree):
        raise Refusal("tested-tree artifact does not hold a tree id")
    return tree


def decide(
    repo: str, queue_ref: str, queue_sha: str, base_sha: str, workflow_path: str, api: Api, run_git: Git,
) -> str:
    """Return the matching run id, or raise Refusal with the reason.

    Tree equality is the proof: a green run whose recorded tree equals the
    candidate's tested identical content. Everything else only locates runs.
    """
    match = QUEUE_REF_RE.fullmatch(queue_ref)
    if not match:
        raise Refusal(f"{queue_ref!r} is not a merge-queue ref")
    number, named_base = match.group(1), match.group(2)
    if not re.fullmatch(r"[0-9a-f]{40}", queue_sha):
        raise Refusal("queue head sha is malformed")
    if named_base != base_sha:
        raise Refusal("queue ref names a different base than the merge group")

    queue_tree = run_git(["rev-parse", "--verify", f"{queue_sha}^{{tree}}"])
    if not TREE_RE.fullmatch(queue_tree):
        raise Refusal("could not read the queue candidate's tree")

    pull = api_json(api, f"repos/{repo}/pulls/{number}")
    head = (pull.get("head") or {}).get("sha")
    if not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise Refusal(f"pull request #{number} has no readable head sha")

    runs = api_json(
        api,
        f"repos/{repo}/actions/runs?event=pull_request&status=success&head_sha={head}&per_page=20",
    ).get("workflow_runs")
    if not isinstance(runs, list):
        raise Refusal("workflow run listing is malformed")
    candidates = [
        run for run in runs
        if isinstance(run, dict)
        and run.get("path") == workflow_path
        and run.get("event") == "pull_request"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        and run.get("head_sha") == head
        and (run.get("repository") or {}).get("full_name") == repo
    ]
    candidates.sort(key=lambda run: str(run.get("run_started_at") or ""), reverse=True)
    if not candidates:
        raise Refusal(f"no successful {workflow_path} pull request run for {head}")

    for run in candidates[:MAX_RUNS]:
        run_id = run.get("id")
        if not isinstance(run_id, int):
            continue
        artifacts = api_json(
            api, f"repos/{repo}/actions/runs/{run_id}/artifacts?name={ARTIFACT_NAME}&per_page=10",
        ).get("artifacts")
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts:
            if (
                not isinstance(artifact, dict)
                or artifact.get("name") != ARTIFACT_NAME
                or artifact.get("expired") is not False
                or not isinstance(artifact.get("id"), int)
            ):
                continue
            tree = tested_tree_from_zip(api(f"repos/{repo}/actions/artifacts/{artifact['id']}/zip"))
            if tree == queue_tree:
                return str(run_id)
    raise Refusal("no green pull request run tested the queue candidate's exact tree")


def main(argv: list[str] | None = None, api: Api = gh_api, run_git: Git = git) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--queue-ref", required=True)
    parser.add_argument("--queue-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--workflow-path", default=".github/workflows/ci.yaml")
    args = parser.parse_args(argv)
    try:
        run_id = decide(
            args.repo, args.queue_ref, args.queue_sha, args.base_sha, args.workflow_path, api, run_git,
        )
    except Refusal as refusal:
        print(f"running the full suite: {refusal}", file=sys.stderr)
        print("queue_tree_tested=false")
        return 0
    except Exception as error:  # noqa: BLE001 - any lookup failure means run everything
        print(f"running the full suite: reuse lookup failed ({type(error).__name__})", file=sys.stderr)
        print("queue_tree_tested=false")
        return 0
    print(f"reusing pull request run {run_id}: it tested this exact tree", file=sys.stderr)
    print("queue_tree_tested=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
