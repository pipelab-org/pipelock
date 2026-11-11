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
          - version: '1.26.11'
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
                         ("name: Set up Go", "name: Set up Go\n        if: false"),
                         ("go-version: '1.26'", "go-version-file: go.mod"),
                         ("go-version: '1.26'", "go-version: '1.26'\n          check-latest: true"),
                         ("setup-go@1111111111111111111111111111111111111111",
                          "setup-go@2222222222222222222222222222222222222222")):
            with self.subTest(edit=new):
                self.reset_ci()
                self.edit(".github/workflows/ci.yaml", old, new)
                self.assert_changed(new)

    def test_removing_the_last_record_from_a_retained_scope_is_a_change(self) -> None:
        setup = ("      - name: Set up Go\n"
                 "        uses: actions/setup-go@1111111111111111111111111111111111111111 # v7\n"
                 "        with:\n          go-version: '1.26'\n")
        for where in ("setup-go", "workflow", "job", "step", "run", "composite"):
            with self.subTest(where=where):
                self.reset_ci()
                path = ".github/workflows/ci.yaml"
                before = CI
                after = CI.replace(setup, "")
                if where == "workflow":
                    before = "env: {GOTOOLCHAIN: local}\n" + after
                elif where == "job":
                    before = after.replace("  test:\n", "  test:\n    env: {GOTOOLCHAIN: local}\n")
                elif where == "step":
                    before = after.replace("      - run: go test ./...\n",
                                           "      - run: go test ./...\n        env: {GOTOOLCHAIN: local}\n")
                elif where == "run":
                    before = after.replace("      - run: go test ./...\n",
                                           "      - run: GOTOOLCHAIN=local go test ./...\n")
                elif where == "composite":
                    path = ".github/actions/go/action.yml"
                    before = "runs:\n  using: composite\n  steps:\n" + setup
                    after = "runs:\n  using: composite\n  steps:\n    - run: go version\n      shell: bash\n"
                self.write(path, before)
                self.commit("record present")
                self.base = self.rev()
                self.write(path, after)
                self.assert_changed(f"remove last {where} record")

    def test_workflow_paths_are_read_without_git_quoting_or_word_splitting(self) -> None:
        for name in ("go pins.yaml", "go-é.yml"):
            with self.subTest(name=name):
                self.base = self.rev()
                path = f".github/workflows/{name}"
                self.write(path, CI.replace("'1.26'", "'1.28'"))
                self.assert_changed(f"add {name}")
                self.base = self.rev()
                self.write(path, CI.replace("'1.26'", "'1.29'"))
                self.assert_changed(f"edit {name}")

    def test_renaming_a_job_cannot_hide_switching_to_a_known_pin(self) -> None:
        self.write(".github/workflows/known.yaml", CI.replace("'1.26'", "'1.27'"))
        self.commit("known pin")
        self.base = self.rev()
        renamed = CI.replace("  test:\n", "  renamed-test:\n")
        self.write(".github/workflows/ci.yaml", renamed)
        self.assert_unchanged("rename with identical records")
        self.write(".github/workflows/ci.yaml", renamed.replace("'1.26'", "'1.27'"))
        self.assert_changed("rename and switch to known pin")

    def test_templated_matrix_pin_is_a_toolchain_change(self) -> None:
        # The bump edits only the matrix; no line mentions go-version.
        self.edit(".github/workflows/release.yaml", "version: '1.27.3'", "version: '1.27.4'")
        self.assert_changed("release matrix bump")

    def test_release_shard_list_is_not_a_toolchain_change(self) -> None:
        # setup-go reads matrix.go, not matrix.shard.
        self.edit(".github/workflows/release.yaml", "        go:\n",
                  "        shard: [a, b, c]\n        go:\n")
        self.assert_unchanged("release shard list")

    def test_matrix_include_and_exclude_entries_stay_whole(self) -> None:
        # Include and exclude entries match on every dimension, so editing
        # only shard there can still change which Go versions run.
        self.edit(".github/workflows/release.yaml", "          - version: '1.27.3'\n",
                  "          - version: '1.27.3'\n        include:\n          - shard: x\n")
        self.commit("include entry")
        self.base = self.rev()
        self.edit(".github/workflows/release.yaml", "          - shard: x\n", "          - shard: y\n")
        self.assert_changed("include entry edits a key setup-go does not read")
        self.base = self.rev()
        self.edit(".github/workflows/release.yaml", "        include:\n",
                  "        exclude:\n          - {go: {version: '1.27.3'}, shard: z}\n        include:\n")
        self.assert_changed("exclude entry on an unread dimension")
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

    def test_new_job_that_can_skip_a_known_setup_go_is_a_toolchain_change(self) -> None:
        # When the condition is false, the job's Go commands use the runner's Go.
        self.edit(".github/workflows/ci.yaml", "      - run: go test ./...\n",
                  "      - run: go test ./...\n  bench:\n    steps:\n"
                  "      - uses: actions/setup-go@1111111111111111111111111111111111111111\n"
                  "        if: steps.sources.outputs.changed == 'true'\n"
                  "        with:\n          go-version: '1.26'\n      - run: go test -bench=. ./...\n")
        self.assert_changed("new job, conditional install")

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

    def write_job(self, name: str, body: str) -> None:
        self.write(f".github/workflows/{name}.yaml", body)
        self.commit(f"base {name}")
        self.base = self.rev()

    def test_bracket_matrix_reference_tracks_the_whole_matrix(self) -> None:
        self.write_job("b", "jobs:\n  b:\n    strategy:\n      matrix:\n        go: ['1.26']\n    steps:\n"
                       "      - uses: actions/setup-go@v7\n        with:\n          go-version: ${{ matrix['go'] }}\n")
        self.edit(".github/workflows/b.yaml", "go: ['1.26']", "go: ['1.27']")
        self.assert_changed("bracket matrix reference")

    def test_wildcard_matrix_reference_tracks_the_whole_matrix(self) -> None:
        self.write_job("w", "jobs:\n  w:\n    strategy:\n      matrix:\n        cfg: [{go: '1.26'}]\n    steps:\n"
                       "      - uses: actions/setup-go@v7\n        if: contains(matrix.*.go, '1.26')\n"
                       "        with:\n          go-version: '1.26'\n")
        self.edit(".github/workflows/w.yaml", "cfg: [{go: '1.26'}]", "cfg: [{go: '1.27'}]")
        self.assert_changed("wildcard matrix read in a setup-go condition")

    def test_env_reference_in_go_version_tracks_env(self) -> None:
        self.write_job("e", "env:\n  GO_VERSION: '1.26'\njobs:\n  e:\n    steps:\n"
                       "      - uses: actions/setup-go@v7\n        with:\n          go-version: ${{ env.GO_VERSION }}\n")
        self.edit(".github/workflows/e.yaml", "GO_VERSION: '1.26'", "GO_VERSION: '1.27'")
        self.assert_changed("env-driven go-version")

    def test_matrix_reference_in_gotoolchain_tracks_the_key(self) -> None:
        self.write_job("t", "jobs:\n  t:\n    strategy:\n      matrix:\n        toolchain: [local]\n"
                       "        shard: [a]\n    env:\n      GOTOOLCHAIN: ${{ matrix.toolchain }}\n    steps:\n"
                       "      - run: go test ./...\n")
        self.edit(".github/workflows/t.yaml", "shard: [a]", "shard: [a, b]")
        self.assert_unchanged("unread matrix key")
        self.base = self.rev()
        self.edit(".github/workflows/t.yaml", "toolchain: [local]", "toolchain: [go1.27.3]")
        self.assert_changed("matrix-driven GOTOOLCHAIN")

    def test_matrix_reference_in_setup_go_condition_tracks_the_key(self) -> None:
        self.write_job("c", "jobs:\n  c:\n    strategy:\n      matrix:\n        install_go: [true]\n    steps:\n"
                       "      - uses: actions/setup-go@v7\n        if: matrix.install_go\n"
                       "        with:\n          go-version: '1.26'\n")
        self.edit(".github/workflows/c.yaml", "install_go: [true]", "install_go: [false]")
        self.assert_changed("matrix-driven setup-go condition")

    def test_local_action_inputs_are_tracked(self) -> None:
        self.write(".github/actions/go/action.yml",
                   "inputs:\n  go:\n    default: '1.26'\nruns:\n  using: composite\n  steps:\n"
                   "    - uses: actions/setup-go@v7\n      with:\n        go-version: ${{ inputs.go }}\n")
        self.write_job("l", "jobs:\n  l:\n    steps:\n      - uses: ./.github/actions/go\n        with:\n          go: '1.26'\n")
        self.edit(".github/workflows/l.yaml", "go: '1.26'", "go: '1.27'")
        self.assert_changed("version passed to a local action")
        self.base = self.rev()
        self.edit(".github/actions/go/action.yml", "default: '1.26'", "default: '1.27'")
        self.assert_changed("local action input default")

    def test_gotoolchain_run_step_condition_is_tracked(self) -> None:
        self.write_job("r", "jobs:\n  r:\n    steps:\n      - run: echo GOTOOLCHAIN=go1.27.3 >> \"$GITHUB_ENV\"\n"
                       "      - run: go test ./...\n")
        self.edit(".github/workflows/r.yaml", "      - run: echo GOTOOLCHAIN",
                  "      - if: false\n        run: echo GOTOOLCHAIN")
        self.assert_changed("disabled GOTOOLCHAIN writer")

    def test_swapping_setup_go_order_is_a_toolchain_change(self) -> None:
        self.write_job("o", "jobs:\n  o:\n    steps:\n"
                       "      - uses: actions/setup-go@v7\n        with: {go-version: '1.26'}\n"
                       "      - uses: actions/setup-go@v7\n        with: {go-version: '1.27'}\n")
        self.write(".github/workflows/o.yaml", "jobs:\n  o:\n    steps:\n"
                   "      - uses: actions/setup-go@v7\n        with: {go-version: '1.27'}\n"
                   "      - uses: actions/setup-go@v7\n        with: {go-version: '1.26'}\n")
        self.assert_changed("setup-go order swap")

    def test_go_version_file_contents_are_tracked(self) -> None:
        self.write("tools/go.mod", "module example.invalid/tools\n\ngo 1.26.0\n")
        self.write_job("v", "jobs:\n  v:\n    steps:\n      - uses: actions/setup-go@v7\n"
                       "        with:\n          go-version-file: ./tools/go.mod\n")
        self.write("tools/go.mod", "module example.invalid/tools\n\ngo 1.27.0\n")
        self.assert_changed("nested go-version-file edited, workflow unchanged")

    def test_expression_go_version_file_always_runs_the_proof(self) -> None:
        self.write_job("x", "jobs:\n  x:\n    steps:\n      - uses: actions/setup-go@v7\n"
                       "        with:\n          go-version-file: ${{ env.VERSION_FILE }}\n")
        self.write("internal/x.go", "package x\n")
        self.assert_changed("unrelated edit with an untrackable version file")

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
