#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Native fuzz target parity and upload-only workflow contracts."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts.test_specialist_workflow_triggers import job_block, step_run_script

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/go-fuzz.yaml"


def load_runner():
    spec = importlib.util.spec_from_file_location("fuzz_targets", ROOT / "scripts/fuzz-targets.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


# One parity check shared by make fuzz and the workflow's matrix job.
_RUNNER = load_runner()
MANIFEST = _RUNNER.MANIFEST
check_targets = _RUNNER.check_targets


class NativeFuzzWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / WORKFLOW).read_text()
        self.manifest = json.loads((ROOT / MANIFEST).read_text())

    def test_inventory_matches_every_native_go_fuzz_function(self):
        check_targets(ROOT, self.manifest)
        self.assertIn(
            {"package": "./internal/scanner", "target": "FuzzScanURL"},
            self.manifest["include"],
        )

    def test_parity_rejects_one_sided_additions_removals_and_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "fuzz_test.go"
            source.write_text("package fixture\nfunc FuzzExample(f *testing.F) {}\n")
            row = {"package": "./.", "target": "FuzzExample"}
            manifest = {"include": [row]}
            check_targets(root, manifest)
            with self.assertRaisesRegex(AssertionError, "missing"):
                check_targets(root, {"include": [row, {"package": "./.", "target": "FuzzAdded"}]})
            source.write_text(source.read_text() + "func FuzzAdded(f *testing.F) {}\n")
            with self.assertRaisesRegex(AssertionError, "unlisted"):
                check_targets(root, manifest)
            source.write_text("package fixture\nfunc FuzzExample(f *testing.F) {}\n")
            with self.assertRaisesRegex(AssertionError, "duplicate"):
                check_targets(root, {"include": [row, row]})
            with self.assertRaisesRegex(AssertionError, "empty"):
                check_targets(root, {"include": []})

    def test_matrix_is_read_from_manifest_after_parity_check(self):
        targets = job_block(self.workflow, "targets")
        self.assertIn("python3 -m unittest discover -s scripts -p 'test_go_fuzz_workflow.py'", targets)
        self.assertIn("matrix: ${{ steps.targets.outputs.matrix }}", targets)
        fuzz = job_block(self.workflow, "fuzz")
        self.assertIn("matrix: ${{ fromJSON(needs.targets.outputs.matrix) }}", fuzz)
        self.assertIn("fail-fast: false", fuzz)
        # Exercise the actual matrix-emission command without recursively running this suite.
        script = step_run_script(self.workflow, "targets", "Read checked-in targets")
        emit = script.splitlines()[-1]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            subprocess.run(["bash", "-euo", "pipefail", "-c", emit], cwd=ROOT,
                           env=dict(os.environ, GITHUB_OUTPUT=str(output)), check=True)
            self.assertEqual(json.loads(output.read_text().removeprefix("matrix=")), self.manifest)

    def test_make_uses_manifest_runner_and_anchored_names(self):
        makefile = (ROOT / "Makefile").read_text()
        recipe = makefile.split("\nfuzz:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(recipe, "\t@python3 scripts/fuzz-targets.py")
        runner = load_runner()
        with mock.patch("sys.argv", ["fuzz-targets.py"]), mock.patch.object(
            runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
        ) as run, mock.patch("builtins.print"):
            self.assertEqual(runner.main(), 0)
        self.assertEqual(run.call_count, len(self.manifest["include"]))
        for call, row in zip(run.call_args_list, self.manifest["include"]):
            self.assertEqual(call.args[0], ["go", "test", "-run=^$", f"-fuzz=^{row['target']}$",
                                           "-fuzztime=30s", row["package"]])
        with mock.patch("sys.argv", ["fuzz-targets.py"]), mock.patch.object(
            runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)
        ) as run, mock.patch("builtins.print"):
            self.assertEqual(runner.main(), 1)
            self.assertEqual(run.call_count, 1)
        # go test exits 0 for an unmatched -fuzz, so the runner itself must refuse
        # unknown and duplicate rows before invoking Go.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".github").mkdir()
            (root / "fuzz_test.go").write_text("package fixture\nfunc FuzzExample(f *testing.F) {}\n")
            known = {"package": "./.", "target": "FuzzExample"}
            for rows in ([{"package": "./.", "target": "FuzzGone"}], [known, known]):
                (root / MANIFEST).write_text(json.dumps({"include": rows}))
                with mock.patch.object(runner, "ROOT", root), mock.patch("sys.argv", ["fuzz-targets.py"]), \
                        mock.patch.object(runner.subprocess, "run") as run, mock.patch("sys.stderr"):
                    self.assertEqual(runner.main(), 1)
                    run.assert_not_called()

    def test_fuzz_failure_stays_red_and_uploads_target_inputs(self):
        fuzz = job_block(self.workflow, "fuzz")
        self.assertNotIn("continue-on-error", fuzz)
        self.assertIn("FUZZTIME: 30s", fuzz)
        self.assertIn('go test -run=\'^$\' -fuzz="^${FUZZ_TARGET}$" -fuzztime="$FUZZTIME" "$FUZZ_PACKAGE"', fuzz)
        self.assertIn("if: ${{ failure() && steps.fuzz.outcome == 'failure' }}", fuzz)
        self.assertIn("path: ${{ matrix.package }}/testdata/fuzz/${{ matrix.target }}/", fuzz)
        self.assertIn("name: fuzz-crash-${{ matrix.target }}", fuzz)
        self.assertIn("if-no-files-found: ignore", fuzz)

    def test_unbuilt_target_fails_before_fuzzing(self):
        # go test exits 0 when -fuzz matches nothing, so the step must prove the
        # target is built for this runner before fuzzing.
        fuzz = job_block(self.workflow, "fuzz")
        listing = fuzz.index('-list="^${FUZZ_TARGET}\\$" "$FUZZ_PACKAGE"')
        check = fuzz.index('grep -qxF "$FUZZ_TARGET"')
        refuse = fuzz.index("exit 1", check)
        run = fuzz.index('-fuzz="^${FUZZ_TARGET}$"')
        self.assertLess(listing, check)
        self.assertLess(refuse, run)

    def test_unprivileged_pr_workflow_never_restores_cross_run_state(self):
        self.assertIn("\npermissions: {}\n", self.workflow)
        self.assertIn("group: ${{ github.workflow }}-${{ github.event.pull_request.number }}", self.workflow)
        self.assertIn("cancel-in-progress: true", self.workflow)
        self.assertNotRegex(self.workflow, r"pull_request_target:|workflow_run:|secrets\.|download-artifact|actions/cache")
        for job in ("targets", "fuzz"):
            block = job_block(self.workflow, job)
            self.assertIn("permissions:\n      contents: read\n", block)
            self.assertEqual(block.count("uses: actions/checkout@"), block.count("persist-credentials: false"))
            self.assertIn("timeout-minutes: 5", block)
            # Job-level env expressions: contexts allowed by GitHub's availability table,
            # https://docs.github.com/en/actions/reference/workflows-and-actions/contexts
            # (jobs.<job_id>.env). Any other context invalidates the whole workflow file.
            env = re.search(r"(?m)^    env:\n((?:      .*\n)+)", block)
            for root in re.findall(r"\$\{\{\s*([A-Za-z_]+)", env.group(1) if env else ""):
                self.assertIn(root, {"github", "needs", "strategy", "matrix", "vars", "secrets", "inputs"})
        self.assertIn("cache: false", self.workflow)
        self.assertIn("GOCACHE: ${{ runner.temp }}/native-go-fuzz", self.workflow)
        self.assertIn("GOTOOLCHAIN: local", self.workflow)
        self.assertIn("go-version: '1.26'", self.workflow)
        # Pin to the same revisions the main CI workflow already uses.
        main = (ROOT / ".github/workflows/ci.yaml").read_text()
        for action in re.findall(r"uses: (\S+)", self.workflow):
            self.assertRegex(action, r"@[0-9a-f]{40}$")
            self.assertIn("uses: " + action, main)


if __name__ == "__main__":
    unittest.main()
