# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the failure classifier, the nightly flake hunter and the ceiling early warning."""

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import ci_flake_report as report
from scripts import ci_test_packages as planner

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def events(*items):
    return [json.dumps(item) for item in items]


class FailedTestsTest(unittest.TestCase):
    def test_top_level_failures_races_and_package_failures_are_separated(self):
        failed, bare, races = report.failed_tests(report.read_events(events(
            {"Action": "fail", "Package": "p", "Test": "TestA/sub"},
            {"Action": "fail", "Package": "p", "Test": "TestA"},
            {"Action": "output", "Package": "p", "Test": "TestRace", "Output": "WARNING: DATA RACE\n"},
            {"Action": "fail", "Package": "p", "Test": "TestRace"},
            {"Action": "fail", "Package": "p"},
            {"Action": "fail", "Package": "q"},
            {"Action": "pass", "Package": "p", "Test": "TestOK"},
        )))
        self.assertEqual(failed, {"p": ["TestA"]})
        self.assertEqual(races, {"p": ["TestRace"]})
        # q failed with no named test: a build error, panic or timeout.
        self.assertEqual(bare, ["q"])

    def test_classification(self):
        self.assertEqual(report.classify(5, 5), "DETERMINISTIC")
        self.assertEqual(report.classify(1, 5), "FLAKY")
        self.assertEqual(report.classify(0, 5), "FLAKY")
        self.assertEqual(report.classify(-1, 5), "UNKNOWN")


class RerunEndToEndTest(unittest.TestCase):
    SOURCE = '''package fixture
import "testing"
var runs int
// Fails only on the second run in one process.
func TestFlaky(t *testing.T) {
	runs++
	if runs == 2 {
		t.Fatal("second run")
	}
}
func TestBroken(t *testing.T) { t.Fatal("always") }
'''

    def test_flaky_and_deterministic_are_told_apart_and_exit_is_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.test/fixture\n\ngo 1.26\n")
            (root / "fixture_test.go").write_text(self.SOURCE)
            stream = "\n".join(events(
                {"Action": "fail", "Package": "example.test/fixture", "Test": "TestFlaky"},
                {"Action": "fail", "Package": "example.test/fixture", "Test": "TestBroken"},
                {"Action": "fail", "Package": "example.test/fixture"},
            ))
            out = io.StringIO()
            env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
            with patch.object(report, "ROOT", root), patch.dict(os.environ, env, clear=True), \
                 patch("sys.stdin", io.StringIO(stream)), patch("sys.argv", ["ci_flake_report.py", "--reruns", "3"]), \
                 redirect_stdout(out):
                status = report.main()
            text = out.getvalue()
            self.assertEqual(status, 0, "classification never changes the job result")
            self.assertIn("TestBroken failed all 3 reruns", text)
            self.assertIn("TestFlaky failed 1 of 3 reruns", text)
            self.assertIn("| example.test/fixture | TestFlaky | 1 of 3 | FLAKY |", text)

    def test_too_many_failures_are_not_rerun(self):
        stream = "\n".join(events(*[{"Action": "fail", "Package": "p", "Test": f"Test{i}"}
                                     for i in range(report.MAX_TESTS + 1)]))
        out = io.StringIO()
        with patch.object(report, "rerun", side_effect=AssertionError("must not rerun")), \
             patch.dict(os.environ, {}, clear=True), patch("sys.stdin", io.StringIO(stream)), \
             patch("sys.argv", ["ci_flake_report.py"]), redirect_stdout(out):
            self.assertEqual(report.main(), 0)
        self.assertIn("Too many failures to classify", out.getvalue())


class WorkflowContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = yaml.safe_load((WORKFLOWS / "ci.yaml").read_text(encoding="utf-8"))["jobs"]
        cls.hunter = yaml.safe_load((WORKFLOWS / "ci-flake-hunter.yaml").read_text(encoding="utf-8"))
        cls.drift = yaml.safe_load((WORKFLOWS / "ci-shard-drift.yaml").read_text(encoding="utf-8"))

    def test_hunter_runs_the_planner_shards_main_runs(self):
        shards = self.hunter["jobs"]["hunt"]["strategy"]["matrix"]["shard"]
        self.assertEqual(shards, list(planner.SHARDS))
        self.assertEqual(shards, self.ci["test-enterprise-go126"]["strategy"]["matrix"]["shard"])

    def test_hunter_is_scheduled_read_only_and_fails_closed(self):
        triggers = self.hunter[True] if True in self.hunter else self.hunter["on"]
        self.assertIn("schedule", triggers)
        self.assertNotIn("pull_request", triggers)
        self.assertNotIn("push", triggers)
        self.assertEqual(self.hunter["permissions"], {"contents": "read"})
        run = "\n".join(step.get("run", "") for step in self.hunter["jobs"]["hunt"]["steps"])
        self.assertIn('-count="$HUNT_COUNT"', run)
        self.assertIn("ci_flake_report.py", run)
        self.assertIn('exit "$test_status"', run, "a found flake must fail the run")

    def test_main_race_jobs_classify_failures_without_changing_the_result(self):
        for job in ("test-oss-go126", "test-enterprise-go126"):
            with self.subTest(job=job):
                run = "\n".join(step.get("run", "") for step in self.ci[job]["steps"])
                self.assertIn('if [ "$test_status" -ne 0 ]; then', run)
                self.assertIn("ci_flake_report.py", run)
                # The classifier runs before the original status is returned.
                self.assertLess(run.index("ci_flake_report.py"), run.index('exit "$test_status"'))

    def test_ceiling_early_warning_fails_closed_on_an_empty_scan(self):
        step = next(s for s in self.drift["jobs"]["drift"]["steps"]
                    if s.get("name") == "Find tests nearing the per-test ceiling")
        self.assertEqual(step["env"]["EARLY_CEILING_SECONDS"], "180")
        script = step["run"]
        with tempfile.TemporaryDirectory() as directory:
            timing = Path(directory) / "timing"
            timing.mkdir()
            env = {**os.environ, "RUNNER_TEMP": directory, "EARLY_CEILING_SECONDS": "180"}
            empty = subprocess.run(["bash", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(empty.returncode, 1, empty.stdout + empty.stderr)
            (timing / "slow.json").write_text("\n".join(events(
                {"Action": "run", "Package": "p", "Test": "TestSlow"},
                {"Action": "pass", "Package": "p", "Test": "TestSlow", "Elapsed": 200.0},
                {"Action": "pass", "Package": "p", "Elapsed": 200.0},
            )) + "\n")
            slow = subprocess.run(["bash", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(slow.returncode, 1, slow.stdout + slow.stderr)
            self.assertIn("TestSlow", slow.stdout)
            (timing / "slow.json").write_text("\n".join(events(
                {"Action": "run", "Package": "p", "Test": "TestFast"},
                {"Action": "pass", "Package": "p", "Test": "TestFast", "Elapsed": 30.0},
                {"Action": "pass", "Package": "p", "Elapsed": 30.0},
            )) + "\n")
            fast = subprocess.run(["bash", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(fast.returncode, 0, fast.stdout + fast.stderr)


if __name__ == "__main__":
    unittest.main()
