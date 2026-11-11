#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Execute ci.yaml's documentation-only classifier against real git histories.

A documentation-only verdict lets a pull request skip the Go build, test, lint
and platform jobs, so every way Go can reach a Markdown file, and every git
failure, must produce the full suite. The script under test is read from the
workflow itself, so this exercises exactly what CI runs.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yaml"


def classifier_script(step_id: str = "docs") -> str:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    steps = jobs["changed-files"]["steps"]
    matches = [step["run"] for step in steps if step.get("id") == step_id]
    if len(matches) != 1:
        raise AssertionError("changed-files must have exactly one docs classifier step")
    return matches[0]


class DocsClassifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pipelock-docs-classifier-")
        self.repo = Path(self.temp.name)
        self.git("init", "-q", "-b", "main")
        self.write("docs/guide.md", "guide\n")
        self.write("README.md", "readme\n")
        self.write("internal/shield/shield.go", "package shield\n")
        self.write("internal/hermes/embed.go", "package hermes\n")
        self.write("internal/hermes/plugin_template/plugin.py", "x = 1\n")
        self.write("internal/aarp/scope_test.go", 'package aarp\nconst doc = "docs/specs/envelope.md"\n')
        self.write("docs/specs/envelope.md", "spec\n")
        self.commit("base")
        self.base = self.rev()
        self.script = classifier_script()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", *args],
            cwd=self.repo, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def write(self, path: str, text: str) -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)

    def rev(self) -> str:
        return self.git("rev-parse", "HEAD")

    def classify(self, base: str | None = None) -> tuple[int, str]:
        with tempfile.NamedTemporaryFile("r", encoding="utf-8", delete=False) as output:
            output_path = output.name
        try:
            result = subprocess.run(
                ["bash", "-c", self.script],
                cwd=self.repo,
                env={
                    **os.environ,
                    "BASE_SHA": base or self.base,
                    "HEAD_SHA": self.rev(),
                    "GITHUB_OUTPUT": output_path,
                    "GITHUB_WORKSPACE": str(ROOT),
                },
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode, Path(output_path).read_text(encoding="utf-8").strip()
        finally:
            os.unlink(output_path)

    def assert_full_ci(self) -> None:
        status, output = self.classify()
        self.assertEqual(status, 0)
        self.assertEqual(output, "docs_only=false")

    def test_prose_only_change_is_documentation_only(self) -> None:
        self.write("docs/guide.md", "guide, revised\n")
        self.write("docs/new-page.md", "new\n")
        self.commit("prose")
        self.assertEqual(self.classify(), (0, "docs_only=true"))

    def test_source_renamed_to_markdown_runs_everything(self) -> None:
        # Default rename detection reports only the new Markdown path.
        self.git("mv", "internal/shield/shield.go", "docs/moved.md")
        self.commit("rename")
        self.assertEqual(self.git("diff", "--name-only", f"{self.base}...HEAD"), "docs/moved.md")
        self.assert_full_ci()

    def test_markdown_inside_a_go_package_runs_everything(self) -> None:
        # //go:embed plugin_template/* reaches this file without naming it.
        self.write("internal/hermes/plugin_template/NOTES.md", "notes\n")
        self.commit("embedded prose")
        self.assert_full_ci()

    def test_markdown_beside_a_non_ascii_go_file_runs_everything(self) -> None:
        # git quotes non-ASCII names unless asked for NUL-delimited output, so
        # a package whose only source is "é.go" must still count as Go.
        self.write("internal/accent/é.go", "package accent\n")
        self.commit("accented package")
        base = self.rev()
        self.write("internal/accent/NOTES.md", "notes\n")
        self.commit("prose in the package")
        self.assertEqual(self.classify(base), (0, "docs_only=false"))

    def test_markdown_named_by_go_code_runs_everything(self) -> None:
        self.write("docs/specs/envelope.md", "spec, revised\n")
        self.commit("tested prose")
        self.assert_full_ci()

    def test_non_markdown_change_runs_everything(self) -> None:
        self.write("docs/diagram.svg", "<svg/>\n")
        self.commit("asset")
        self.assert_full_ci()

    def test_fixture_markdown_runs_everything(self) -> None:
        self.write("testdata/case.md", "fixture\n")
        self.commit("fixture")
        self.assert_full_ci()

    def test_go_package_at_the_root_runs_everything(self) -> None:
        self.write("doc.go", "package pipelock\n")
        self.commit("root package")
        base = self.rev()
        self.write("docs/guide.md", "guide, revised\n")
        self.commit("prose")
        self.assertEqual(self.classify(base), (0, "docs_only=false"))

    def test_queue_range_keeps_toolchain_changes_from_earlier_members(self) -> None:
        self.write(".github/workflows/ci.yaml",
                   "jobs:\n  t:\n    steps:\n      - uses: actions/setup-go@v7\n        with: {go-version: '1.27'}\n")
        self.commit("queued toolchain member")
        earlier_head = self.rev()
        self.write("docs/guide.md", "queued prose change\n")
        self.commit("queued prose member")
        # Looking only at the last member would miss the policy change.
        self.assertEqual(self.classify(earlier_head), (0, "docs_only=true"))
        self.assert_full_ci()
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["changed-files"]["steps"]
        policy = next(step["run"] for step in steps if step.get("id") == "check")
        with tempfile.NamedTemporaryFile("r", encoding="utf-8") as output:
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", policy], cwd=self.repo,
                env=os.environ | {"BASE_SHA": self.base, "HEAD_SHA": self.rev(), "GITHUB_OUTPUT": output.name,
                                  "GITHUB_WORKSPACE": str(ROOT)},
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(output.name).read_text().strip(), "go_toolchain=true\nbenchmark_smoke=true\nbenchmark_alloc=true\nbenchmark_throughput=true")

    def test_throughput_runs_for_every_internal_package_the_scanner_imports(self) -> None:
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["changed-files"]["steps"]
        policy = next(step["run"] for step in steps if step.get("id") == "check")
        cases = (("internal/config/defaults.go", True), ("internal/extract/extract.go", True),
                 ("internal/jsonnumber/card.go", True), ("internal/scanner/check.go", True),
                 ("scripts/bench_throughput_gate.py", True), ("docs/guide.md", False))
        for path, expected in cases:
            with self.subTest(path=path):
                base = self.rev()
                self.write(path, f"change {path}\n")
                self.commit(path)
                with tempfile.NamedTemporaryFile("r", encoding="utf-8") as output:
                    result = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", policy], cwd=self.repo,
                        env=os.environ | {"BASE_SHA": base, "HEAD_SHA": self.rev(), "GITHUB_OUTPUT": output.name,
                                          "GITHUB_WORKSPACE": str(ROOT)},
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"benchmark_throughput={str(expected).lower()}", Path(output.name).read_text())

    def test_empty_diff_runs_everything(self) -> None:
        self.commit("empty")
        self.assert_full_ci()

    def test_unavailable_base_fails_the_step(self) -> None:
        self.write("docs/guide.md", "guide, revised\n")
        self.commit("prose")
        status, output = self.classify(base="0" * 40)
        self.assertNotEqual(status, 0)
        self.assertNotIn("docs_only=true", output)

    def test_benchmark_inputs_select_smoke(self) -> None:
        self.script = classifier_script("check")
        for path in ("internal/scanner/new.go", "internal/config/new.go", "go.mod", "go.sum",
                     "Makefile", ".github/workflows/ci.yaml", "scripts/bench_run.py",
                     "scripts/e2e/browser_repro/fixture.py", "internal/scanner/testdata/body.json", "configs/new.yaml"):
            with self.subTest(path=path):
                base = self.rev()
                self.write(path, "new benchmark input\n")
                self.commit("input")
                status, output = self.classify(base=base)
                self.assertEqual(status, 0)
                self.assertIn("benchmark_smoke=true", output)
        base = self.rev()
        (self.repo / "internal/scanner/new.go").unlink()
        self.commit("remove")
        self.assertIn("benchmark_smoke=true", self.classify(base=base)[1])

    def test_unrelated_files_skip_benchmark_smoke_but_git_errors_do_not(self) -> None:
        self.script = classifier_script("check")
        self.write("README.md", "prose edit\n")
        self.commit("prose")
        self.assertIn("benchmark_smoke=false", self.classify()[1])
        status, output = self.classify(base="0" * 40)
        self.assertNotEqual(status, 0)
        self.assertNotIn("benchmark_smoke=false", output)

    def test_required_build_rejects_failed_or_unproven_smoke(self) -> None:
        job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["build"]
        step = job["steps"][0]
        env = {**os.environ, **{key: "success" for key in step["env"]},
               "EVENT_NAME": "pull_request", "DOCS_ONLY": "false"}
        for result, required, classifier, event, expected in (
                ("success", "true", "success", "pull_request", 0),
                ("failure", "false", "success", "pull_request", 1),
                ("cancelled", "false", "success", "pull_request", 1),
                ("skipped", "false", "success", "pull_request", 0),
                ("skipped", "true", "success", "pull_request", 1),
                ("skipped", "", "success", "pull_request", 1),
                ("skipped", "false", "failure", "pull_request", 1),
                ("skipped", "false", "success", "push", 1)):
            with self.subTest(result=result, required=required, classifier=classifier, event=event):
                run = subprocess.run(["bash", "-c", step["run"]], cwd=self.repo,
                                     env={**env, "BENCHMARK_SMOKE_RESULT": result,
                                          "BENCHMARK_SMOKE_REQUIRED": required,
                                          "CHANGED_FILES_RESULT": classifier, "EVENT_NAME": event},
                                     capture_output=True, text=True, check=False)
                self.assertEqual(run.returncode, expected, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
