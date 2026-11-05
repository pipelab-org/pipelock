#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for the merge-queue reuse decision.

Reuse skips the queue's own test run, so every case that is not a verified
exact-tree match must print false and still exit zero.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ci_queue_reuse as reuse  # noqa: E402
from test_ci_security_workflow import job_block, step_script  # noqa: E402

REPO = "pipelab-org/pipelock"
HEAD = "a" * 40
QUEUE_SHA = "b" * 40
BASE = "9" * 40
TREE = "c" * 40
OTHER_TREE = "d" * 40
QUEUE_REF = f"refs/heads/gh-readonly-queue/main/pr-2104-{BASE}"
WORKFLOW = ".github/workflows/ci.yaml"


def tree_zip(content: str = TREE, name: str = reuse.ARTIFACT_FILE, extra: dict | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, content)
        for extra_name, extra_content in (extra or {}).items():
            archive.writestr(extra_name, extra_content)
    return buffer.getvalue()


def good_run(**overrides) -> dict:
    run = {
        "id": 101,
        "path": WORKFLOW,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": HEAD,
        "repository": {"full_name": REPO},
        "run_started_at": "2026-11-05T20:00:00Z",
    }
    run.update(overrides)
    return run


class FakeApi:
    def __init__(self, *, pull_head=HEAD, runs=None, artifacts=None, zips=None, fail=None):
        self.pull_head = pull_head
        self.runs = [good_run()] if runs is None else runs
        self.artifacts = (
            {101: [{"id": 9, "name": reuse.ARTIFACT_NAME, "expired": False}]} if artifacts is None else artifacts
        )
        self.zips = {9: tree_zip()} if zips is None else zips
        self.fail = fail
        self.calls = []

    def __call__(self, path: str) -> bytes:
        self.calls.append(path)
        if self.fail and self.fail in path:
            raise RuntimeError("api down")
        if path == f"repos/{REPO}/pulls/2104":
            return json.dumps({"head": {"sha": self.pull_head}}).encode()
        if path.startswith(f"repos/{REPO}/actions/runs?"):
            return json.dumps({"workflow_runs": self.runs}).encode()
        if "/artifacts?" in path:
            run_id = int(path.split("/actions/runs/")[1].split("/")[0])
            return json.dumps({"artifacts": self.artifacts.get(run_id, [])}).encode()
        if path.endswith("/zip"):
            return self.zips[int(path.split("/artifacts/")[1].split("/")[0])]
        raise AssertionError(f"unexpected api path {path}")


def fake_git(tree: str = TREE):
    def run(args):
        assert args == ["rev-parse", "--verify", f"{QUEUE_SHA}^{{tree}}"], args
        return tree
    return run


def run_main(api, git=None, queue_ref=QUEUE_REF, queue_sha=QUEUE_SHA, base_sha=BASE, workflow=WORKFLOW):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = reuse.main(
            ["--repo", REPO, "--queue-ref", queue_ref, "--queue-sha", queue_sha, "--base-sha", base_sha,
             "--workflow-path", workflow],
            api=api, run_git=git or fake_git(),
        )
    return code, out.getvalue(), err.getvalue()


class QueueReuseTest(unittest.TestCase):
    def assert_decision(self, expected: str, **kwargs) -> str:
        code, out, err = run_main(**kwargs)
        self.assertEqual(code, 0, "a lookup problem must never red the classifier")
        self.assertEqual(out, f"queue_tree_tested={expected}\n", err)
        return err

    def test_exact_tree_match_reuses(self):
        err = self.assert_decision("true", api=FakeApi())
        self.assertIn("reusing pull request run 101", err)

    def test_ref_without_refs_heads_prefix_still_parses(self):
        self.assert_decision("true", api=FakeApi(), queue_ref=f"gh-readonly-queue/main/pr-2104-{BASE}")

    def test_different_tree_runs_full_suite(self):
        self.assert_decision("false", api=FakeApi(zips={9: tree_zip(OTHER_TREE)}))

    def test_main_moved_tree_differs(self):
        self.assert_decision("false", api=FakeApi(), git=fake_git(OTHER_TREE))

    def test_non_queue_refs_refuse(self):
        for ref in (
            "refs/heads/main",
            f"refs/heads/feature/pr-2104-{BASE}",
            f"refs/heads/gh-readonly-queue/main/pr-0-{BASE}",
            f"refs/heads/gh-readonly-queue/main/pr-2104-{BASE[:39]}",
            f"refs/heads/gh-readonly-queue/main/pr-2104-{BASE}x",
            "",
        ):
            with self.subTest(ref=ref):
                self.assert_decision("false", api=FakeApi(), queue_ref=ref)

    def test_malformed_queue_sha_refuses(self):
        self.assert_decision("false", api=FakeApi(), queue_sha="not-a-sha")

    def test_queue_ref_base_must_match_merge_group_base(self):
        self.assert_decision("false", api=FakeApi(), base_sha="8" * 40)

    def test_unreadable_pull_request_head_refuses(self):
        for head in (None, "", "e" * 39, "E" * 40, 12):
            with self.subTest(head=head):
                self.assert_decision("false", api=FakeApi(pull_head=head))

    def test_runs_for_a_different_head_never_match(self):
        # The API now reports a newer head; runs for the old head are ignored.
        self.assert_decision("false", api=FakeApi(pull_head="e" * 40))

    def test_run_filters_reject_every_untrusted_shape(self):
        bad_runs = {
            "other workflow": good_run(path=".github/workflows/hardening.yaml"),
            "push event": good_run(event="push"),
            "merge group event": good_run(event="merge_group"),
            "still running": good_run(status="in_progress"),
            "failed": good_run(conclusion="failure"),
            "cancelled": good_run(conclusion="cancelled"),
            "skipped": good_run(conclusion="skipped"),
            "other head": good_run(head_sha="f" * 40),
            "other repository": good_run(repository={"full_name": "someone/fork"}),
            "missing repository": good_run(repository=None),
            "non-integer id": good_run(id="101"),
        }
        for description, run in bad_runs.items():
            with self.subTest(description):
                self.assert_decision("false", api=FakeApi(runs=[run]))

    def test_no_runs_refuses(self):
        self.assert_decision("false", api=FakeApi(runs=[]))

    def test_artifact_shapes_that_refuse(self):
        cases = {
            "missing artifact": {101: []},
            "expired": {101: [{"id": 9, "name": reuse.ARTIFACT_NAME, "expired": True}]},
            "expired unknown": {101: [{"id": 9, "name": reuse.ARTIFACT_NAME}]},
            "other name": {101: [{"id": 9, "name": "coverage", "expired": False}]},
            "string id": {101: [{"id": "9", "name": reuse.ARTIFACT_NAME, "expired": False}]},
        }
        for description, artifacts in cases.items():
            with self.subTest(description):
                self.assert_decision("false", api=FakeApi(artifacts=artifacts))

    def test_artifact_contents_that_refuse(self):
        cases = {
            "not a tree id": tree_zip("not-a-tree"),
            "short tree id": tree_zip(TREE[:39]),
            "uppercase tree id": tree_zip(TREE.upper()),
            "wrong file name": tree_zip(name="tree.txt"),
            "extra file": tree_zip(extra={"other": "x"}),
            "oversized file": tree_zip(TREE + " " * 300),
            "not a zip": b"not a zip archive",
            "oversized archive": b"x" * (reuse.MAX_ARTIFACT_BYTES + 1),
        }
        for description, data in cases.items():
            with self.subTest(description):
                self.assert_decision("false", api=FakeApi(zips={9: data}))

    def test_newest_matching_run_wins_and_older_runs_are_checked(self):
        runs = [
            good_run(id=101, run_started_at="2026-11-05T19:00:00Z"),
            good_run(id=202, run_started_at="2026-11-05T21:00:00Z"),
        ]
        artifacts = {
            101: [{"id": 9, "name": reuse.ARTIFACT_NAME, "expired": False}],
            202: [{"id": 10, "name": reuse.ARTIFACT_NAME, "expired": False}],
        }
        # The newest run tested an older tree; the older run tested this one.
        err = self.assert_decision(
            "true", api=FakeApi(runs=runs, artifacts=artifacts, zips={10: tree_zip(OTHER_TREE), 9: tree_zip()}),
        )
        self.assertIn("run 101", err)

    def test_api_and_git_failures_run_full_suite(self):
        for fragment in ("/pulls/", "/actions/runs?", "/artifacts?", "/zip"):
            with self.subTest(fragment):
                self.assert_decision("false", api=FakeApi(fail=fragment))

        def broken_git(_args):
            raise RuntimeError("no such object")
        self.assert_decision("false", api=FakeApi(), git=broken_git)
        self.assert_decision("false", api=FakeApi(), git=lambda _args: "")

    def test_malformed_api_payloads_run_full_suite(self):
        class Garbage(FakeApi):
            def __init__(self, target, payload):
                super().__init__()
                self.target, self.payload = target, payload

            def __call__(self, path):
                if self.target in path:
                    return self.payload
                return super().__call__(path)

        for target, payload in (
            ("/pulls/", b"[]"),
            ("/pulls/", b"not json"),
            ("/pulls/", b'{"head": null}'),
            ("/actions/runs?", b'{"workflow_runs": {}}'),
            ("/artifacts?", b'{"artifacts": "x"}'),
        ):
            with self.subTest(target=target, payload=payload):
                self.assert_decision("false", api=Garbage(target, payload))


class WorkflowReuseStepTest(unittest.TestCase):
    def test_lookup_deadline_falls_back_before_classifier_timeout(self):
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yaml"
        script = step_script(
            job_block(workflow.read_text(), "changed-files"),
            "Reuse a green pull request result for this exact tree",
        )
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            checker = temp / "source.py"
            output = temp / "output"
            calls = temp / "timeout-calls"
            for name, body in {
                "git": '#!/bin/sh\ncat "$CHECKER_SOURCE"\n',
                # Exercise real process termination without spending the full
                # production budget. Record its arguments to pin that budget.
                "timeout": '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TIMEOUT_CALLS"\n'
                           'shift 2\nexec /usr/bin/timeout --signal=KILL 1s "$@"\n',
            }.items():
                executable = temp / name
                executable.write_text(body)
                executable.chmod(0o700)
            env = os.environ | {
                "PATH": f"{temp}:{os.environ['PATH']}",
                "CHECKER_SOURCE": str(checker), "TIMEOUT_CALLS": str(calls),
                "GITHUB_OUTPUT": str(output), "BASE_SHA": BASE,
                "QUEUE_REF": QUEUE_REF, "QUEUE_SHA": QUEUE_SHA, "REPO": REPO,
                "TMPDIR": str(temp),
            }
            cases = (
                ("import threading\nthreading.Event().wait()\n", "false"),
                ('print("queue_tree_tested=true")\n', "true"),
                ('print("queue_tree_tested=true")\nraise SystemExit(1)\n', "false"),
                ('print("queue_tree_tested=true\\nextra output")\n', "false"),
                ("", "false"),
            )
            for source, expected in cases:
                with self.subTest(expected=expected):
                    checker.write_text(source)
                    output.write_text("")
                    result = subprocess.run(
                        ["/usr/bin/timeout", "--signal=KILL", "5s", "bash", "-euo", "pipefail", "-c", script],
                        env=env, capture_output=True, text=True, check=False, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(), f"queue_tree_tested={expected}\n")
            self.assertTrue(calls.exists(), "lookup must invoke its own deadline")
            self.assertEqual(calls.read_text().count("--signal=KILL 60s python3 "), len(cases))


if __name__ == "__main__":
    unittest.main()
