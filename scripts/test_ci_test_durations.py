# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import json
import tempfile
import unittest
from pathlib import Path

from scripts.ci_test_durations import RACE_PARALLELISM, collect
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
        parent = {"Action": "pass", "Test": "TestParallel", "Elapsed": 1}
        a = {"Action": "pass", "Test": "TestParallel/a", "Elapsed": 12}
        b = {"Action": "pass", "Test": "TestParallel/b", "Elapsed": 10}
        self.assertEqual(self.collect_events([parent, a, b], [parent, a, b])["TestParallel"], 11)

    def test_sequential_parent_is_not_double_counted(self):
        self.assertEqual(self.collect_events([
            {"Action": "pass", "Test": "TestSequential", "Elapsed": 20},
            {"Action": "pass", "Test": "TestSequential/a", "Elapsed": 9},
            {"Action": "pass", "Test": "TestSequential/b", "Elapsed": 10},
        ])["TestSequential"], 20)

    def test_nested_leaves_not_intermediate_parents(self):
        self.assertEqual(self.collect_events([
            {"Action": "pass", "Test": "TestNested", "Elapsed": 1},
            {"Action": "pass", "Test": "TestNested/group", "Elapsed": 20},
            {"Action": "pass", "Test": "TestNested/group/a", "Elapsed": 8},
            {"Action": "pass", "Test": "TestNested/group/b", "Elapsed": 12},
        ])["TestNested"], 10)

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

    def test_incomplete_parent_and_leaf(self):
        self.assertEqual(self.collect_events([
            {"Action": "run", "Test": "TestPartial"},
            {"Action": "run", "Test": "TestPartial/missing"},
            {"Action": "pass", "Test": "TestPartial/done", "Elapsed": 12},
        ])["TestPartial"], 6)


if __name__ == "__main__":
    unittest.main()
