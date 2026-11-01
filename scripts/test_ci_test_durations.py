# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import json
import tempfile
import unittest
from pathlib import Path

from scripts.ci_test_durations import RACE_PARALLELISM, collect, collect_packages
from scripts.ci_test_packages import ROOT


class DurationTest(unittest.TestCase):
    def collect_events(self, *events):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, attempt in enumerate(events):
                path = Path(directory) / str(index)
                path.write_text("".join(json.dumps(dict(Package="example.test/internal/proxy", **event)) + "\n"
                                        for event in attempt), encoding="utf-8")
                paths.append(path)
            return collect(paths)["proxy"]

    def test_parallelism_matches_ci_race_shape(self):
        ci = (ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8")
        self.assertEqual(RACE_PARALLELISM, 2)
        self.assertEqual(ci.count("-parallel=2 -timeout=15m"), 4)

    def test_parallel_leaves_and_retry_deduplication(self):
        events = [
            {"Action": "run", "Test": "TestParallel"},
            {"Action": "run", "Test": "TestParallel/a"},
            {"Action": "pause", "Test": "TestParallel/a"},
            {"Action": "run", "Test": "TestParallel/b"},
            {"Action": "pause", "Test": "TestParallel/b"},
            {"Action": "cont", "Test": "TestParallel/a"},
            {"Action": "pass", "Test": "TestParallel/a", "Elapsed": 12},
            {"Action": "cont", "Test": "TestParallel/b"},
            {"Action": "pass", "Test": "TestParallel/b", "Elapsed": 10},
            {"Action": "pass", "Test": "TestParallel", "Elapsed": 1},
        ]
        self.assertEqual(self.collect_events(events, events)["TestParallel"], 12)

    def test_sequential_work_then_parallel_children(self):
        # Event order and elapsed values follow the real Go TestMixed producer.
        self.assertEqual(self.collect_events([
            {"Action": "run", "Test": "TestMixed"},
            {"Action": "run", "Test": "TestMixed/a"},
            {"Action": "pause", "Test": "TestMixed/a"},
            {"Action": "run", "Test": "TestMixed/b"},
            {"Action": "pause", "Test": "TestMixed/b"},
            {"Action": "cont", "Test": "TestMixed/a"},
            {"Action": "cont", "Test": "TestMixed/b"},
            {"Action": "pass", "Test": "TestMixed/a", "Elapsed": 0.4},
            {"Action": "pass", "Test": "TestMixed/b", "Elapsed": 0.4},
            {"Action": "pass", "Test": "TestMixed", "Elapsed": 0.4},
        ])["TestMixed"], 0.8)

    def test_sequential_parent_is_not_double_counted(self):
        self.assertEqual(self.collect_events([
            {"Action": "pass", "Test": "TestSequential", "Elapsed": 20},
            {"Action": "pass", "Test": "TestSequential/a", "Elapsed": 9},
            {"Action": "pass", "Test": "TestSequential/b", "Elapsed": 10},
        ])["TestSequential"], 20)

    def test_nested_parallel_and_skipped_child(self):
        self.assertEqual(self.collect_events([
            {"Action": "run", "Test": "TestNested"},
            {"Action": "run", "Test": "TestNested/group"},
            {"Action": "pause", "Test": "TestNested/group"},
            {"Action": "cont", "Test": "TestNested/group"},
            {"Action": "run", "Test": "TestNested/group/a"},
            {"Action": "pause", "Test": "TestNested/group/a"},
            {"Action": "cont", "Test": "TestNested/group/a"},
            {"Action": "pass", "Test": "TestNested/group/a", "Elapsed": 12},
            {"Action": "run", "Test": "TestNested/group/skipped"},
            {"Action": "pause", "Test": "TestNested/group/skipped"},
            {"Action": "cont", "Test": "TestNested/group/skipped"},
            {"Action": "skip", "Test": "TestNested/group/skipped", "Elapsed": 2},
            {"Action": "pass", "Test": "TestNested/group", "Elapsed": 4},
            {"Action": "pass", "Test": "TestNested", "Elapsed": 1},
        ])["TestNested"], 6.5)

    def test_failed_or_incomplete_package_does_not_replace_prior(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events"
            package = "example.test/internal/other"
            for action in ("fail", "start"):
                path.write_text(json.dumps({"Package": package, "Action": action, "Elapsed": 1}))
                self.assertEqual(collect_packages([path]), {})
            path.write_text("\n".join(json.dumps(event) for event in [
                {"Package": package, "Action": "run", "Test": "TestUnfinished"},
                {"Package": package, "Action": "pass", "Elapsed": 1},
            ]))
            self.assertEqual(collect_packages([path]), {})
            path.write_text(json.dumps({"Package": package, "Action": "pass", "Elapsed": 3}))
            self.assertEqual(collect_packages([path]), {package: 3})

    def test_incomplete_run_does_not_lower_previous_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            events = [
                {"Action": "run", "Test": "TestPartial"},
                {"Action": "run", "Test": "TestPartial/missing"},
                {"Action": "pass", "Test": "TestPartial/done", "Elapsed": 12},
            ]
            path.write_text("".join(json.dumps(dict(Package="example.test/internal/proxy", **event)) + "\n"
                                    for event in events), encoding="utf-8")
            measured = collect([path], {"proxy": {"TestPartial": 100}})
            self.assertEqual(measured["proxy"]["TestPartial"], 100)

    def test_complete_and_skipped_runs_can_lower_previous_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            events = [
                {"Action": "run", "Test": "TestPartial"},
                {"Action": "run", "Test": "TestPartial/skipped"},
                {"Action": "skip", "Test": "TestPartial/skipped"},
                {"Action": "pass", "Test": "TestPartial", "Elapsed": 4},
            ]
            path.write_text("".join(json.dumps(dict(Package="example.test/internal/proxy", **event)) + "\n"
                                    for event in events), encoding="utf-8")
            self.assertEqual(collect([path], {"proxy": {"TestPartial": 100}})["proxy"]["TestPartial"], 4)

    def test_incomplete_paused_child_keeps_previous(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events"
            path.write_text("\n".join(json.dumps(dict(Package="example.test/internal/proxy", **event)) for event in [
                {"Action": "run", "Test": "TestPartial"},
                {"Action": "run", "Test": "TestPartial/missing"},
                {"Action": "pause", "Test": "TestPartial/missing"},
                {"Action": "pass", "Test": "TestPartial", "Elapsed": 4},
            ]))
            self.assertEqual(collect([path], {"proxy": {"TestPartial": 10}})["proxy"]["TestPartial"], 10)


if __name__ == "__main__":
    unittest.main()
