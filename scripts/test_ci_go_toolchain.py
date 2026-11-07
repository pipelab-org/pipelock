#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Run scripts/ci_go_toolchain.py against real git histories.

A false verdict lets a pull request skip the Go 1.27 race matrices, so every
way a change can reach the toolchain must print true, and every git failure
must fail rather than print false.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci_go_toolchain.py"

CI = """\
name: ci
on: [pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      matrix:
        shard: [a, b]
    steps:
      - uses: actions/checkout@v7
      - name: Set up Go
        uses: actions/setup-go@1111111111111111111111111111111111111111 # v7
        with:
          go-version: '1.26'
      - run: go test ./...
"""

RELEASE = """\
name: release
on: [push]
jobs:
  release-tests:
    strategy:
      matrix:
        go:
          - version: '1.26.10'
          - version: '1.27.3'
    steps:
      - uses: actions/setup-go@1111111111111111111111111111111111111111
        with:
          go-version: ${{ matrix.go.version }}
"""


class GoToolchainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pipelock-go-toolchain-")
        self.repo = Path(self.temp.name)
        self.git("init", "-q", "-b", "main")
        self.write("go.mod", "module example.invalid/m\n\ngo 1.26.0\n")
        self.write("go.sum", "")
        self.write("Makefile", "test:\n\tgo test ./...\n")
        self.write("codecov.yml", "coverage: {}\n")
        for path in ("scripts/check-go-matrix.sh", "scripts/ci_test_packages.py", "scripts/ci_test_durations.py",
                     "scripts/ci_test_durations.json", "scripts/ci_changed_tests.go",
                     "scripts/ci-test-with-retry.sh", "scripts/run-race-test.sh", "scripts/ci_go_toolchain.py"):
            self.write(path, "# base\n")
        self.write(".github/workflows/ci.yaml", CI)
        self.write(".github/workflows/release.yaml", RELEASE)
        self.commit("base")
        self.base = self.rev()

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

    def edit(self, path: str, old: str, new: str) -> None:
        text = (self.repo / path).read_text(encoding="utf-8")
        self.assertIn(old, text, "fixture edit must change the file")
        self.write(path, text.replace(old, new))

    def reset_ci(self) -> None:
        self.write(".github/workflows/ci.yaml", CI)
        self.commit("reset")
        self.base = self.rev()

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)

    def rev(self) -> str:
        return self.git("rev-parse", "HEAD")

    def run_script(self, base: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), base or self.base, self.rev()],
            cwd=self.repo, capture_output=True, text=True, check=False,
        )

    def verdict(self) -> str:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def assert_changed(self, message: str) -> None:
        self.commit(message)
        self.assertEqual(self.verdict(), "true", message)

    def assert_unchanged(self, message: str) -> None:
        self.commit(message)
        self.assertEqual(self.verdict(), "false", message)

    def test_empty_change_is_not_a_toolchain_change(self) -> None:
        self.assert_unchanged("empty")

    def test_toolchain_files_are_toolchain_changes(self) -> None:
        for path in ("go.mod", "go.sum", "scripts/check-go-matrix.sh", "scripts/ci_go_toolchain.py"):
            with self.subTest(path=path):
                self.base = self.rev()
                self.write(path, f"# changed {path}\n")
                self.assert_changed(path)

    def test_deleting_a_toolchain_file_is_a_toolchain_change(self) -> None:
        (self.repo / "go.sum").unlink()
        self.assert_changed("drop go.sum")

    def test_ci_harness_files_are_not_toolchain_changes(self) -> None:
        for path in ("scripts/ci_test_packages.py", "scripts/ci_test_durations.py",
                     "scripts/ci_test_durations.json", "scripts/ci_changed_tests.go",
                     "scripts/ci-test-with-retry.sh", "scripts/run-race-test.sh", "Makefile", "codecov.yml",
                     "internal/scanner/scanner.go"):
            with self.subTest(path=path):
                self.base = self.rev()
                self.write(path, f"# changed {path}\n")
                self.assert_unchanged(path)

    def test_workflow_edits_outside_setup_go_are_not_toolchain_changes(self) -> None:
        for old, new in (("timeout-minutes: 15", "timeout-minutes: 20"),
                         ("shard: [a, b]", "shard: [a, b, c]"),
                         ("name: Set up Go", "name: Install Go"),
                         ("run: go test ./...", "run: go test -race ./...")):
            with self.subTest(edit=new):
                self.reset_ci()
                self.edit(".github/workflows/ci.yaml", old, new)
                self.assert_unchanged(new)

    def test_new_workflow_without_setup_go_is_not_a_toolchain_change(self) -> None:
        self.write(".github/workflows/lint.yaml", "on: [pull_request]\njobs:\n  l:\n    steps:\n      - run: true\n")
        self.assert_unchanged("new workflow")

    def test_reordering_steps_is_not_a_toolchain_change(self) -> None:
        self.edit(".github/workflows/ci.yaml", "      - uses: actions/checkout@v7\n", "")
        self.edit(".github/workflows/ci.yaml", "      - run: go test ./...\n",
                  "      - run: go test ./...\n      - uses: actions/checkout@v7\n")
        self.assert_unchanged("reorder")

    def test_setup_go_changes_are_toolchain_changes(self) -> None:
        for old, new in (("go-version: '1.26'", "go-version: '1.27'"),
                         ("go-version: '1.26'", "go-version-file: go.mod"),
                         ("go-version: '1.26'", "go-version: '1.26'\n          check-latest: true"),
                         ("setup-go@1111111111111111111111111111111111111111",
                          "setup-go@2222222222222222222222222222222222222222")):
            with self.subTest(edit=new):
                self.reset_ci()
                self.edit(".github/workflows/ci.yaml", old, new)
                self.assert_changed(new)

    def test_templated_matrix_pin_is_a_toolchain_change(self) -> None:
        # The bump edits only the matrix; no line mentions go-version.
        self.edit(".github/workflows/release.yaml", "version: '1.27.3'", "version: '1.27.4'")
        self.assert_changed("release matrix bump")

    def test_release_shard_list_is_not_a_toolchain_change(self) -> None:
        # setup-go reads matrix.go, not matrix.shard.
        self.edit(".github/workflows/release.yaml", "        go:\n",
                  "        shard: [a, b, c]\n        go:\n")
        self.assert_unchanged("release shard list")

    def test_matrix_include_entries_are_projected_to_the_read_keys(self) -> None:
        self.edit(".github/workflows/release.yaml", "          - version: '1.27.3'\n",
                  "          - version: '1.27.3'\n        include:\n          - shard: x\n")
        self.commit("include entry")
        self.base = self.rev()
        self.edit(".github/workflows/release.yaml", "          - shard: x\n", "          - shard: y\n")
        self.assert_unchanged("include entry edits only a key setup-go does not read")
        self.base = self.rev()
        self.edit(".github/workflows/release.yaml", "          - shard: y\n", "          - shard: x\n")
        self.edit(".github/workflows/release.yaml", "          - shard: x\n",
                  "          - shard: x\n            go: {version: '1.28.0'}\n")
        self.assert_changed("include that adds a Go version")

    def test_new_job_with_a_new_setup_go_is_a_toolchain_change(self) -> None:
        self.write(".github/workflows/fuzz.yaml",
                   "jobs:\n  f:\n    steps:\n      - uses: actions/setup-go@v7\n        with: {go-version: '1.27'}\n")
        self.assert_changed("new setup-go job")

    def test_new_job_reusing_an_existing_setup_go_is_not_a_toolchain_change(self) -> None:
        self.edit(".github/workflows/ci.yaml", "      - run: go test ./...\n",
                  "      - run: go test ./...\n  bench:\n    steps:\n"
                  "      - uses: actions/setup-go@1111111111111111111111111111111111111111\n"
                  "        with:\n          go-version: '1.26'\n      - run: go test -bench=. ./...\n")
        self.assert_unchanged("new job, same pin")

    def test_existing_job_switching_to_another_known_pin_is_a_toolchain_change(self) -> None:
        # 1.27 already appears elsewhere; the test job still runs Go it did not run.
        self.write(".github/workflows/fuzz.yaml",
                   "jobs:\n  f:\n    steps:\n      - uses: actions/setup-go@1111111111111111111111111111111111111111\n"
                   "        with:\n          go-version: '1.27'\n")
        self.commit("fuzz at 1.27")
        self.base = self.rev()
        self.edit(".github/workflows/ci.yaml", "go-version: '1.26'", "go-version: '1.27'")
        self.assert_changed("test job moves to 1.27")

    def test_removing_a_setup_go_job_is_not_a_toolchain_change(self) -> None:
        (self.repo / ".github/workflows/release.yaml").unlink()
        self.assert_unchanged("drop release workflow")

    def test_composite_action_setup_go_is_a_toolchain_change(self) -> None:
        self.write(".github/actions/go/action.yml",
                   "runs:\n  using: composite\n  steps:\n      - uses: actions/setup-go@v7\n"
                   "        with: {go-version: '1.27'}\n")
        self.assert_changed("composite setup-go")

    def test_gotoolchain_settings_are_toolchain_changes(self) -> None:
        for old, new in (("name: ci\n", "name: ci\nenv:\n  GOTOOLCHAIN: local\n"),
                         ("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    env:\n      GOTOOLCHAIN: go1.27.3\n"),
                         ("      - run: go test ./...\n",
                          "      - run: go test ./...\n        env:\n          GOTOOLCHAIN: auto\n"),
                         ("      - run: go test ./...\n",
                          "      - run: echo GOTOOLCHAIN=go1.27.3 >> \"$GITHUB_ENV\"\n      - run: go test ./...\n")):
            with self.subTest(edit=new):
                self.reset_ci()
                self.edit(".github/workflows/ci.yaml", old, new)
                self.assert_changed(new)

    def test_unparseable_workflow_runs_the_proof(self) -> None:
        self.write(".github/workflows/ci.yaml", "jobs: [unclosed\n")
        self.commit("broken")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "true")
        self.assertIn("does not parse", result.stderr)

    def test_compares_from_the_merge_base(self) -> None:
        # A toolchain change that landed on main after the branch point is
        # main's, not this branch's; git diff BASE...HEAD ignores it too.
        branch_point = self.rev()
        self.git("checkout", "-q", "-b", "feature")
        self.write("internal/x.go", "package x\n")
        self.commit("feature")
        feature = self.rev()
        self.git("checkout", "-q", "main")
        self.write("go.mod", "module example.invalid/m\n\ngo 1.27.0\n")
        self.commit("main bumps go")
        main = self.rev()
        self.git("checkout", "-q", "feature")
        self.assertNotEqual(branch_point, main)
        self.assertEqual(self.run_script(base=main).stdout.strip(), "false")
        self.assertEqual(self.rev(), feature)

    def test_git_failure_exits_non_zero_without_a_verdict(self) -> None:
        self.write("internal/x.go", "package x\n")
        self.commit("change")
        result = self.run_script(base="0" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
