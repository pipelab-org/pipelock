# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Contracts for the failure classifier, the nightly flake hunter and the ceiling early warning."""

import io
import json
import os
import re
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

    def test_subtest_failure_before_race_is_classified_only_as_race(self):
        failed, bare, races = report.failed_tests(report.read_events(events(
            {"Action": "fail", "Package": "p", "Test": "TestA/sub1"},
            {"Action": "output", "Package": "p", "Test": "TestA/sub2", "Output": "WARNING: DATA RACE\n"},
            {"Action": "fail", "Package": "p", "Test": "TestA/sub2"},
            {"Action": "fail", "Package": "p", "Test": "TestA"},
            {"Action": "fail", "Package": "p"},
            {"Action": "output", "Package": "q", "Output": "WARNING: DATA RACE\n"},
            {"Action": "fail", "Package": "q"},
        )))
        self.assertEqual(failed, {})
        self.assertEqual(bare, [])
        self.assertEqual(races, {"p": ["TestA"], "q": ["(package)"]})

    def test_named_failure_in_a_package_level_race_is_the_race(self):
        failed, bare, races = report.failed_tests(report.read_events(events(
            {"Action": "fail", "Package": "p", "Test": "TestA"},
            {"Action": "output", "Package": "p", "Output": "WARNING: DATA RACE\n"},
            {"Action": "fail", "Package": "p"},
        )))
        self.assertEqual(failed, {})
        self.assertEqual(races, {"p": ["TestA"]})
        self.assertEqual(bare, [])

    def test_classification(self):
        self.assertEqual(report.classify(5, 5), "DETERMINISTIC")
        self.assertEqual(report.classify(1, 5), "FLAKY")
        self.assertEqual(report.classify(0, 5), "FLAKY")
        self.assertEqual(report.classify(-1, 5), "UNKNOWN")
        self.assertEqual(report.classify(report.RACE_DETECTED, 5), "DATA RACE")


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

    def test_rerun_that_dies_before_every_repeat_is_unknown(self):
        # One recorded failure, then the test process exits. That is not a
        # finished sample of three runs, so it must not be called flaky.
        source = '''package fixture
import (
	"os"
	"testing"
)
var runs int
func TestPartial(t *testing.T) {
	runs++
	if runs == 1 {
		t.Fatal("first")
	}
	os.Exit(2)
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.test/fixture\n\ngo 1.26\n")
            (root / "fixture_test.go").write_text(source)
            stream = "\n".join(events(
                {"Action": "fail", "Package": "example.test/fixture", "Test": "TestPartial"},
                {"Action": "fail", "Package": "example.test/fixture"},
            ))
            out = io.StringIO()
            env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
            with patch.object(report, "ROOT", root), patch.dict(os.environ, env, clear=True), \
                 patch("sys.stdin", io.StringIO(stream)), \
                 patch("sys.argv", ["ci_flake_report.py", "--reruns", "3"]), \
                 redirect_stdout(out):
                self.assertEqual(report.main(), 0)
            text = out.getvalue()
            self.assertIn("Unclassified failure", text)
            self.assertIn("| example.test/fixture | TestPartial | rerun did not finish | UNKNOWN |", text)
            self.assertNotIn("FLAKY", text)

    def test_package_level_race_during_multi_test_rerun_is_data_race(self):
        # A race line with no Test field is the package, not "none of these
        # tests". Counting the passes would label every one of them flaky.
        events_out = []
        for name in ("TestA", "TestB"):
            for _ in range(2):
                events_out.append({"Action": "pass", "Package": "example.test/p", "Test": name})
        events_out.append({"Action": "output", "Package": "example.test/p", "Output": "WARNING: DATA RACE\n"})
        completed = subprocess.CompletedProcess(args=["go", "test"], returncode=0,
                                                stdout="\n".join(json.dumps(event) for event in events_out),
                                                stderr="")
        with patch.object(report.subprocess, "run", return_value=completed):
            outcomes = report.rerun("example.test/p", ["TestA", "TestB"], "", 2, 30)
        self.assertEqual(outcomes, {"TestA": report.RACE_DETECTED, "TestB": report.RACE_DETECTED})

    def test_rerun_that_times_out_after_a_race_keeps_the_race(self):
        # The rerun printed a race and then stalled. The race is evidence;
        # a test with no race output stays unknown.
        output = "\n".join(json.dumps(event) for event in (
            {"Action": "output", "Package": "example.test/p", "Test": "TestA", "Output": "WARNING: DATA RACE\n"},
            {"Action": "pass", "Package": "example.test/p", "Test": "TestB"},
        )).encode()
        with patch.object(report.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired(["go", "test"], 90, output=output)):
            outcomes = report.rerun("example.test/p", ["TestA", "TestB"], "", 2, 30)
        self.assertEqual(outcomes, {"TestA": report.RACE_DETECTED, "TestB": -1})
        with patch.object(report.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired(["go", "test"], 90, output=None)):
            self.assertEqual(report.rerun("example.test/p", ["TestA"], "", 2, 30), {"TestA": -1})

    def test_summary_rows_are_written_before_the_next_rerun(self):
        # The caller's timeout can end a slow second rerun. The first
        # package's row must already be in the step summary by then.
        stream = "\n".join(events(
            {"Action": "fail", "Package": "a", "Test": "TestA"},
            {"Action": "fail", "Package": "b", "Test": "TestB"},
        ))
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            seen = []

            def fake_rerun(package, names, tags, reruns, timeout):
                seen.append(summary.read_text(encoding="utf-8") if summary.exists() else "")
                return {name: 1 for name in names}
            with patch.object(report, "rerun", side_effect=fake_rerun), \
                 patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}, clear=True), \
                 patch("sys.stdin", io.StringIO(stream)), patch("sys.argv", ["ci_flake_report.py"]), \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(report.main(), 0)
        self.assertIn("| Package | Test | Reruns failed | Kind |", seen[0])
        self.assertIn("| a | TestA | 1 of 5 | FLAKY |", seen[1])

    def test_data_race_during_rerun_is_classified_as_data_race_not_flaky(self):
        # A test that triggers a data race only on one rerun must be labeled
        # DATA RACE rather than FLAKY.
        source = '''package fixture
import (
	"sync"
	"testing"
)
var runs int
func TestIntermittentRace(t *testing.T) {
	runs++
	if runs == 2 {
		x := 0
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); x = 1 }()
		go func() { defer wg.Done(); x = 2 }()
		wg.Wait()
		_ = x
	}
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.test/fixture\n\ngo 1.26\n")
            (root / "fixture_test.go").write_text(source)
            stream = "\n".join(events(
                {"Action": "fail", "Package": "example.test/fixture", "Test": "TestIntermittentRace"},
                {"Action": "fail", "Package": "example.test/fixture"},
            ))
            out = io.StringIO()
            env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
            with patch.object(report, "ROOT", root), patch.dict(os.environ, env, clear=True), \
                 patch("sys.stdin", io.StringIO(stream)), \
                 patch("sys.argv", ["ci_flake_report.py", "--reruns", "3"]), \
                 redirect_stdout(out):
                self.assertEqual(report.main(), 0)
            text = out.getvalue()
            self.assertIn("Data race", text)
            self.assertIn("| example.test/fixture | TestIntermittentRace | data race during rerun | DATA RACE |", text)
            self.assertNotIn("FLAKY", text)

    def test_empty_stream_reports_unclassified_failure(self):
        out = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch("sys.stdin", io.StringIO("")), \
             patch("sys.argv", ["ci_flake_report.py", "--label", "empty shard"]), redirect_stdout(out):
            self.assertEqual(report.main(), 0)
        text = out.getvalue()
        self.assertIn("Unclassified failure", text)
        self.assertIn("| (none) | (no failed tests in JSON stream) | not rerun | UNKNOWN |", text)

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
        self.assertIn('if [ -z "$packages" ]; then', run)
        self.assertLess(run.index('if [ -z "$packages" ]; then'), run.index("go test"))
        self.assertIn('exit "$test_status"', run, "a found flake must fail the run")
        hunt_cap = int(re.search(r"\btimeout --kill-after=\S+ (\d+) go test\b", run).group(1))
        classify = int(re.search(r"\btimeout --kill-after=\S+ (\d+) python3 scripts/ci_flake_report.py", run).group(1))
        self.assertGreaterEqual(
            self.hunter["jobs"]["hunt"]["timeout-minutes"] * 60,
            hunt_cap + classify + 6 * 60,
            "the hunter job timeout must fit the whole-command hunt cap, classifier, and setup/upload margin",
        )

    def test_main_race_jobs_classify_failures_without_changing_the_result(self):
        for job in ("test-oss-go126", "test-enterprise-go126"):
            with self.subTest(job=job):
                run = "\n".join(step.get("run", "") for step in self.ci[job]["steps"])
                self.assertIn('if [ "$test_status" -ne 0 ]; then', run)
                self.assertIn("ci_flake_report.py", run)
                # The classifier runs before the original status is returned.
                self.assertLess(run.index("ci_flake_report.py"), run.index('exit "$test_status"'))
                self.assertIn('timeout --kill-after=10s 900 python3 scripts/ci_flake_report.py', run)
                attempt = int(re.search(r"--attempt-timeout-seconds (\d+)", run).group(1))
                classify = int(re.search(r"\btimeout --kill-after=\S+ (\d+) python3 scripts/ci_flake_report.py", run).group(1))
                # The previous 68-minute cap was two 31-minute attempts plus 6
                # minutes for setup, kill grace, and upload. Classification is
                # sequential with those attempts and has to leave the 6 minutes.
                setup_margin = 68 * 60 - 2 * 31 * 60
                self.assertEqual(setup_margin, 6 * 60)
                self.assertGreaterEqual(
                    self.ci[job]["timeout-minutes"] * 60,
                    2 * attempt + classify + setup_margin,
                    "the classifier must finish before the job timeout cancels the shard",
                )

    def test_ceiling_early_warning_fails_closed_on_an_empty_scan(self):
        step = next(s for s in self.drift["jobs"]["drift"]["steps"]
                    if s.get("name") == "Find tests nearing the per-test ceiling")
        self.assertEqual(step["env"]["EARLY_CEILING_SECONDS"], "180")
        script = step["run"]
        with tempfile.TemporaryDirectory() as directory:
            timing = Path(directory) / "timing"
            timing.mkdir()
            env = {**os.environ, "RUNNER_TEMP": directory, "EARLY_CEILING_SECONDS": "180"}
            empty = subprocess.run(["bash", "-e", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(empty.returncode, 1, empty.stdout + empty.stderr)
            (timing / "empty.json").write_text("")
            empty_file = subprocess.run(["bash", "-e", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(empty_file.returncode, 1, empty_file.stdout + empty_file.stderr)
            self.assertIn("Timing file empty", empty_file.stdout)
            (timing / "empty.json").write_text("\n".join(events(
                {"Action": "start", "Package": "p"},
            )) + "\n")
            start_only = subprocess.run(["bash", "-e", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(start_only.returncode, 1, start_only.stdout + start_only.stderr)
            self.assertIn("Timing file empty", start_only.stdout)
            (timing / "empty.json").write_text('not valid json "Action"\n')
            corrupt = subprocess.run(["bash", "-e", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(corrupt.returncode, 1, corrupt.stdout + corrupt.stderr)
            self.assertIn("Timing file empty", corrupt.stdout)
            (timing / "empty.json").unlink()
            (timing / "slow.json").write_text("\n".join(events(
                {"Action": "run", "Package": "p", "Test": "TestSlow"},
                {"Action": "pass", "Package": "p", "Test": "TestSlow", "Elapsed": 200.0},
                {"Action": "pass", "Package": "p", "Elapsed": 200.0},
            )) + "\n")
            slow = subprocess.run(["bash", "-e", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(slow.returncode, 1, slow.stdout + slow.stderr)
            self.assertIn("TestSlow", slow.stdout)
            (timing / "slow.json").write_text("\n".join(events(
                {"Action": "run", "Package": "p", "Test": "TestFast"},
                {"Action": "pass", "Package": "p", "Test": "TestFast", "Elapsed": 30.0},
                {"Action": "pass", "Package": "p", "Elapsed": 30.0},
            )) + "\n")
            fast = subprocess.run(["bash", "-e", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(fast.returncode, 0, fast.stdout + fast.stderr)


if __name__ == "__main__":
    unittest.main()
