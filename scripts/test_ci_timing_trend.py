#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Offline Actions JSON fixtures for the advisory main CI timing report."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

import yaml

from scripts import ci_timing_trend as trend
from scripts.yaml_contracts import WorkflowLoader

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scripts/testdata/ci-timing-trend/history.json"
WORKFLOW = ROOT / ".github/workflows/ci-timing-trend.yaml"


class TimingTrendTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(FIXTURE.read_text())
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def save(self):
        for name, key in (("current-run", "current_run"), ("current-jobs", "current_jobs"), ("runs", "runs")):
            (self.directory / f"{name}.json").write_text(json.dumps(self.data[key]))
        jobs = self.directory / "jobs"
        jobs.mkdir(exist_ok=True)
        for run_id, payload in self.data["jobs"].items():
            (jobs / f"{run_id}.json").write_text(json.dumps(payload))

    def report(self):
        self.save()
        return trend.compute(self.directory)

    def duration(self, job, seconds):
        job["completed_at"] = (trend.timestamp(job["started_at"]) + timedelta(seconds=seconds)).isoformat()

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = trend.main(list(args))
        return status, out.getvalue(), err.getvalue()

    def test_own_job_medians_regressions_and_slow_first_order(self):
        result = self.report()
        self.assertEqual([row["name"] for row in result["jobs"]], ["compile", "long", "new", "short"])
        rows = {row["name"]: row for row in result["jobs"]}
        self.assertTrue(rows["compile"]["regressed"])
        self.assertEqual(rows["compile"]["median_seconds"], 300)
        self.assertFalse(rows["long"]["regressed"])  # >60s but not >20%.
        self.assertFalse(rows["short"]["regressed"])  # >20% but not >60s.
        self.assertFalse(rows["new"]["regressed"])
        self.assertEqual(result["wall"], {"seconds": 1120, "samples": 5,
                                         "median_seconds": 1020, "p90_seconds": 1020})
        self.assertIn("ignored (<5 historical samples)", trend.summary(result))

    def test_strict_thresholds_and_zero_median(self):
        for baseline, duration, expected in ((1000, 1200, False), (100, 160, False),
                                             (100, 161, True), (100.5, 161, True),
                                             (0, 61, True), (0, 0, False)):
            with self.subTest(baseline=baseline, duration=duration):
                for payload in self.data["jobs"].values():
                    self.duration(payload["jobs"][0], baseline)
                self.duration(self.data["current_jobs"]["jobs"][0], duration)
                report = self.report()
                row = next(row for row in report["jobs"] if row["name"] == "compile")
                self.assertEqual(row["regressed"], expected)
                if baseline == 100.5:
                    self.assertIn("+60.5s", trend.summary(report))
                if baseline == 0:
                    self.assertIsNone(row["delta_percent"])

    def test_sparse_and_missing_jobs_never_become_zero_samples(self):
        jobs = self.data["current_jobs"]["jobs"]
        for state in ("skipped", "cancelled", "in_progress", "no_end", "no_start"):
            with self.subTest(state=state):
                original = copy.deepcopy(jobs[0])
                if state in ("skipped", "cancelled"):
                    jobs[0]["conclusion"] = state
                elif state == "in_progress":
                    jobs[0]["status"] = state
                else:
                    jobs[0]["completed_at" if state == "no_end" else "started_at"] = None
                row = next(row for row in self.report()["jobs"] if row["name"] == "compile")
                self.assertIsNone(row["seconds"])
                self.assertFalse(row["regressed"])
                jobs[0] = original
        self.data["jobs"]["1"]["jobs"][0]["conclusion"] = "skipped"
        row = next(row for row in self.report()["jobs"] if row["name"] == "compile")
        self.assertEqual(row["samples"], 4)
        self.assertFalse(row["regressed"])

    def test_failed_run_names_failures_at_the_top_and_exits_zero(self):
        self.data["current_run"]["conclusion"] = "failure"
        self.data["current_jobs"]["jobs"][0]["conclusion"] = "failure"
        self.data["current_jobs"]["jobs"][1]["conclusion"] = "timed_out"
        report = self.report()
        self.assertEqual(report["failed_jobs"], ["compile", "long"])
        rendered = trend.summary(report)
        self.assertLess(rendered.index("Failed jobs: compile, long"), rendered.index("| Run wall time"))
        status, output, error = self.cli("--data-dir", str(self.directory), "--output",
                                         str(self.directory / "report.json"), "--summary", str(self.directory / "summary.md"))
        self.assertEqual(status, 0, error)
        self.assertIn("::warning title=CI timing regression::compile", output)
        self.assertEqual(json.loads((self.directory / "report.json").read_text()), report)
        self.assertEqual((self.directory / "summary.md").read_text(), rendered)

    def test_cancelled_jobs_count_as_failures_only_in_a_failed_run(self):
        # A job that hits its timeout-minutes ends "cancelled"; in a failed main
        # run it is why main went red. A successful run keeps them out.
        jobs = self.data["current_jobs"]["jobs"]
        jobs[0]["conclusion"] = "cancelled"
        self.assertEqual(self.report()["failed_jobs"], [])
        self.data["current_run"]["conclusion"] = "failure"
        report = self.report()
        self.assertEqual(report["failed_jobs"], [jobs[0]["name"] + " (cancelled)"])
        self.assertIn(jobs[0]["name"] + " (cancelled)", trend.summary(report))

    def test_history_window_success_main_push_only_self_future_and_duplicates(self):
        history = self.data["runs"]["workflow_runs"]
        for field, invalid in (("event", "pull_request"), ("head_branch", "feature"),
                               ("path", ".github/workflows/other.yaml"), ("status", "in_progress"),
                               ("conclusion", "failure"), ("id", 99),
                               ("run_started_at", "2026-11-06T12:00:00Z"),
                               ("created_at", "2026-10-21T11:59:59Z")):
            with self.subTest(field=field, invalid=invalid):
                original = history[0][field]
                history[0][field] = invalid
                selected = trend.historical_runs(self.data["current_run"], self.data["runs"])
                self.assertNotIn(history[0], selected)
                history[0][field] = original
        history.append(copy.deepcopy(history[0]))
        self.data["runs"]["total_count"] += 1
        self.assertEqual(len(trend.historical_runs(self.data["current_run"], self.data["runs"])), 5)
        self.duration(self.data["jobs"]["1"]["jobs"][0], 90000)
        self.assertNotIn(1, self.report()["history_run_ids"])

    def test_pagination_completeness_and_attempt_identity(self):
        payload = self.data["current_jobs"]
        self.data["current_jobs"] = [{"total_count": 4, "jobs": payload["jobs"][:2]},
                                      {"total_count": 4, "jobs": payload["jobs"][2:]}]
        self.assertEqual(len(self.report()["jobs"]), 4)
        self.data["current_jobs"].pop()
        with self.assertRaisesRegex(ValueError, "incomplete jobs"):
            self.report()
        self.data["current_jobs"] = payload
        payload["jobs"][0]["run_attempt"] = 2
        with self.assertRaisesRegex(ValueError, "wrong run or attempt"):
            self.report()

    def test_rerun_queued_ghosts_do_not_hide_the_completed_job(self):
        jobs = self.data["current_jobs"]["jobs"]
        ghost = copy.deepcopy(jobs[0])
        ghost.update(status="queued", conclusion=None, completed_at=None)
        jobs.insert(0, ghost)
        jobs.append(copy.deepcopy(ghost))
        self.data["current_jobs"]["total_count"] += 2
        report = self.report()
        compile_job = next(row for row in report["jobs"] if row["name"] == "compile")
        self.assertEqual(compile_job["seconds"], 361)
        self.assertTrue(compile_job["regressed"])
        self.assertEqual(len(report["jobs"]), 4)

    def test_compute_errors_are_explicit_and_nonzero(self):
        self.save()
        for content in ("{", "null", "[]", '{"total_count":5,"jobs":[]}'):
            with self.subTest(content=content):
                (self.directory / "current-jobs.json").write_text(content)
                status, _, error = self.cli("--data-dir", str(self.directory), "--output",
                                            str(self.directory / "r.json"), "--summary", str(self.directory / "s.md"))
                self.assertEqual(status, 1)
                self.assertIn("Cannot compute CI timing report", error)
        self.data["current_run"]["event"] = "pull_request"
        with self.assertRaisesRegex(ValueError, "main-push"):
            self.report()

    def test_invalid_times_duplicate_names_and_absent_files_are_errors(self):
        job = self.data["current_jobs"]["jobs"][0]
        original = job["completed_at"]
        for invalid in ("bad", "2026-11-05T11:00:00", "2026-11-04T00:00:00Z"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                job["completed_at"] = invalid
                self.report()
        job["completed_at"] = original
        other = self.data["current_jobs"]["jobs"][1]
        other["name"] = job["name"]
        with self.assertRaisesRegex(ValueError, "duplicate job name"):
            self.report()
        other["name"] = "long"
        self.save()
        (self.directory / "jobs/1.json").unlink()
        with self.assertRaises(FileNotFoundError):
            trend.compute(self.directory)

    def test_empty_history_and_no_timings_are_explicit(self):
        self.data["runs"] = {"total_count": 0, "workflow_runs": []}
        for job in self.data["current_jobs"]["jobs"]:
            job["started_at"] = job["completed_at"] = None
        report = self.report()
        self.assertIsNone(report["wall"]["seconds"])
        self.assertIsNone(report["wall"]["p90_seconds"])
        self.assertIn("| missing | missing | missing | 0 |", trend.summary(report))
        self.assertTrue(all(not row["regressed"] for row in report["jobs"]))

    def test_percentile_interpolation_and_command_escaping(self):
        self.assertEqual(trend.percentile([10, 30, 20, 40, 50]), 46)
        self.assertEqual(trend.percentile([10]), 10)
        self.assertIsNone(trend.percentile([]))
        name = "job|<b>\n::error::bad%\r"
        self.data["current_jobs"]["jobs"][0]["name"] = name
        for payload in self.data["jobs"].values():
            payload["jobs"][0]["name"] = name
        self.save()
        status, out, err = self.cli("--data-dir", str(self.directory), "--output", str(self.directory / "r.json"),
                                    "--summary", str(self.directory / "s.md"))
        self.assertEqual(status, 0, err)
        self.assertNotIn("\n::error::bad", out)
        self.assertIn("job&#124;&lt;b&gt;", out)
        self.assertIn("%0A::error::bad%25%0D", out)

    def test_window_start_cli(self):
        self.save()
        status, out, err = self.cli("--window-start", str(self.directory / "current-run.json"))
        self.assertEqual((status, out.strip(), err), (0, "2026-10-22T12:00:00+00:00", ""))

    def test_remaining_input_error_paths_and_cli_entry(self):
        with self.assertRaisesRegex(ValueError, "invalid timestamp"):
            trend.timestamp(None)
        run = self.data["current_run"]
        jobs = self.data["current_jobs"]["jobs"]
        for job in jobs:
            job["completed_at"] = "2026-11-04T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "negative run wall time"):
            trend.wall_seconds(run, {job["name"]: job for job in jobs})
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            trend.main([])
        self.assertEqual(raised.exception.code, 2)
        result = subprocess.run(["python3", str(ROOT / "scripts/ci_timing_trend.py"),
                                 "--data-dir", str(self.directory), "--output", str(self.directory / "r.json"),
                                 "--summary", str(self.directory / "s.md")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Cannot compute CI timing report", result.stderr)


class TimingWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load(WORKFLOW.read_text(), Loader=WorkflowLoader)
        self.job = self.workflow["jobs"]["timing"]

    def test_trigger_read_only_pins_and_artifact_contract(self):
        self.assertEqual(self.workflow["on"], {"workflow_run": {"workflows": ["CI"],
                         "types": ["completed"], "branches": ["main"]}, "workflow_dispatch": None})
        self.assertEqual(self.workflow["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(self.workflow["on"]["workflow_run"]["workflows"],
                         [yaml.load((ROOT / ".github/workflows/ci.yaml").read_text(), Loader=WorkflowLoader)["name"]])
        self.assertIn("github.event.workflow_run.event == 'push'", self.job["if"])
        self.assertIn("github.event_name == 'workflow_dispatch'", self.job["if"])
        self.assertNotIn("permissions", self.job)
        for step in self.job["steps"]:
            if "uses" in step:
                self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
            self.assertNotIn("continue-on-error", step)
        checkout = self.job["steps"][0]
        self.assertEqual(checkout["with"], {"ref": "main", "persist-credentials": False})
        artifact = self.job["steps"][-1]
        self.assertEqual(artifact["with"]["retention-days"], 30)
        self.assertEqual(artifact["with"]["if-no-files-found"], "error")
        report = next(step for step in self.job["steps"] if step.get("name") == "Report CI timing")
        self.assertIn('--summary "$GITHUB_STEP_SUMMARY"', report["run"])

    def test_fetch_step_with_offline_paginated_api_and_dispatch(self):
        # Execute the shipped fetch step, including the Python/gh boundary.
        # The fixture gh responds to plain read calls; nothing contacts GitHub.
        fetch = next(step for step in self.job["steps"] if step.get("name") == "Fetch CI run history")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "gh"
            fake.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
data = json.loads(Path(os.environ['TIMING_FIXTURE']).read_text())
args = sys.argv[1:]
endpoint = next(arg for arg in args if arg.startswith('repos/'))
if os.environ.get('FAIL_FETCH'):
    sys.exit(9)
if '--jq' in args:
    print(99)
elif '/attempts/' in endpoint:
    if os.environ.get('RETRY_FETCH') and '?per_page=100' in endpoint:
        print('truncated JSON')
        sys.exit(0)
    run_id = endpoint.split('/runs/')[1].split('/')[0]
    payload = data['current_jobs'] if run_id == '99' else data['jobs'][run_id]
    jobs = payload['jobs']
    print(json.dumps([dict(total_count=len(jobs), jobs=jobs[:2]),
                      dict(total_count=len(jobs), jobs=jobs[2:])]))
elif '/workflows/' in endpoint:
    print(json.dumps([data['runs']]))
else:
    print(json.dumps(data['current_run']))
''')
            fake.chmod(0o700)
            env = os.environ | self.job["env"] | {"PATH": str(root) + os.pathsep + os.environ["PATH"],
                                "RUNNER_TEMP": str(root), "GITHUB_REPOSITORY": "example/project",
                                "TIMING_FIXTURE": str(FIXTURE)}
            for trigger, retry in (("99", ""), ("", ""), ("99", "1")):
                result = subprocess.run(["bash", "-c", fetch["run"]], cwd=ROOT,
                                        env=env | {"TRIGGER_RUN_ID": trigger, "RETRY_FETCH": retry}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                if retry:
                    self.assertIn("Retrying run 99 with smaller API pages", result.stdout)
                report = trend.compute(root / "ci-timing")
                self.assertEqual(report["wall"]["samples"], 5)
            result = subprocess.run(["bash", "-c", fetch["run"]], cwd=ROOT,
                                    env=env | {"TRIGGER_RUN_ID": "99", "FAIL_FETCH": "1"}, capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
