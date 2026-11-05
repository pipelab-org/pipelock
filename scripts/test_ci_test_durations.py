# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import ci_test_durations as durations

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

    def partial_packages(self, events, new, previous=100):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changed.json"
            path.write_text("".join(json.dumps({"Package": "example.test/rest", **event}) + "\n"
                                    for event in events))
            durations.selection_path(path).write_text(json.dumps({"new": new}))
            with patch.object(durations, "load_package_durations", return_value={"example.test/rest": previous}), \
                 patch.object(durations, "load_durations", return_value={}):
                return durations.partial_overrides([path])["packages"]["example.test/rest"]

    def test_partial_stream_adds_only_new_tests_to_rest_package(self):
        events = [
            {"Action": "run", "Test": "TestNew"},
            {"Action": "pass", "Test": "TestNew", "Elapsed": 70},
            {"Action": "run", "Test": "TestEdited"},
            {"Action": "pass", "Test": "TestEdited", "Elapsed": 50},
            {"Action": "pass", "Elapsed": 121},
        ]
        # The recorded total already holds TestEdited; only TestNew is added.
        self.assertEqual(self.partial_packages(events, {"example.test/rest": ["TestNew"]}), 170)
        # An edit-only run that stays under the recorded total changes nothing,
        # so committing the refresh repeatedly cannot ratchet the total.
        self.assertEqual(self.partial_packages(events[2:4] + [{"Action": "pass", "Elapsed": 51}], {}), 100)
        # An edited test that alone outruns the recorded total still counts.
        slow = [{"Action": "run", "Test": "TestEdited"},
                {"Action": "pass", "Test": "TestEdited", "Elapsed": 400},
                {"Action": "pass", "Elapsed": 401}]
        self.assertEqual(self.partial_packages(slow, {}), 401)

    def test_partial_stream_requires_complete_run_and_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "changed.json"
            path.write_text(json.dumps({"Package": "example.test/rest", "Action": "pass", "Elapsed": 1}) + "\n")
            with patch.object(durations, "load_package_durations", return_value={}), \
                 patch.object(durations, "load_durations", return_value={}):
                with self.assertRaisesRegex(ValueError, "selection file"):
                    durations.partial_overrides([path])
                path.write_text(json.dumps({"Package": "example.test/rest", "Action": "run", "Test": "TestNew"}))
                with self.assertRaisesRegex(ValueError, "incomplete or failed"):
                    durations.partial_overrides([path])

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
        ])["TestNested"], 10)  # 1 + (4 + 12 + 2) / 2: -parallel divides a paused subtree once

    @staticmethod
    def paused_tree(root, children, leaf_elapsed):
        # Mirrors the events of a real Go producer whose every subtest calls
        # t.Parallel: run, pause, cont and pass per test, parents passing with
        # 0 s because their elapsed time excludes paused children.
        events = [{"Action": "run", "Test": root}]
        for name, elapsed in [(name, leaf_elapsed if leaf else 0) for name, leaf in children]:
            events += [{"Action": action, "Test": f"{root}/{name}"} for action in ("run", "pause", "cont")]
            events.append({"Action": "pass", "Test": f"{root}/{name}", "Elapsed": elapsed})
        return events + [{"Action": "pass", "Test": root, "Elapsed": 0}]

    def test_three_paused_levels_divide_once(self):
        # Real producer: 2x2x2 paused leaves of 0.2 s ran in 0.802 s at -parallel=2.
        children = [(f"a{i}", False) for i in range(2)]
        children += [(f"a{i}/b{j}", False) for i in range(2) for j in range(2)]
        children += [(f"a{i}/b{j}/c{k}", True) for i in range(2) for j in range(2) for k in range(2)]
        self.assertEqual(self.collect_events(self.paused_tree("TestThree", children, 0.2))["TestThree"], 0.8)

    def test_slash_in_subtest_name_is_one_level(self):
        # t.Run("a/b0/c") under the top-level test, as the upload transport
        # tests do. Real producer: four 0.2 s paused leaves ran in 0.402 s.
        children = [(f"a/b{i}/c", True) for i in range(4)]
        self.assertEqual(self.collect_events(self.paused_tree("TestSlash", children, 0.2))["TestSlash"], 0.4)

    def test_slash_named_sibling_after_prefix_finishes(self):
        # Go emits a completed sibling "a" before starting the sibling "a/b".
        events = [
            {"Action": "run", "Test": "TestSlash"},
            {"Action": "run", "Test": "TestSlash/a"},
            {"Action": "pass", "Test": "TestSlash/a", "Elapsed": 0},
        ]
        for index in range(4):
            name = f"TestSlash/a/b{index}"
            events.extend({"Action": action, "Test": name} for action in ("run", "pause"))
        for index in range(4):
            name = f"TestSlash/a/b{index}"
            events.extend([
                {"Action": "cont", "Test": name},
                {"Action": "pass", "Test": name, "Elapsed": 0.25},
            ])
        events.append({"Action": "pass", "Test": "TestSlash", "Elapsed": 0})
        self.assertEqual(self.collect_events(events)["TestSlash"], 0.5)

    def test_retry_with_different_parent_does_not_lose_work(self):
        nested = [
            {"Action": "run", "Test": "TestRetry"},
            {"Action": "run", "Test": "TestRetry/a"},
            {"Action": "pause", "Test": "TestRetry/a"},
            {"Action": "cont", "Test": "TestRetry/a"},
            {"Action": "run", "Test": "TestRetry/a/b"},
            {"Action": "pause", "Test": "TestRetry/a/b"},
            {"Action": "cont", "Test": "TestRetry/a/b"},
            {"Action": "pass", "Test": "TestRetry/a/b", "Elapsed": 2},
            {"Action": "pass", "Test": "TestRetry/a", "Elapsed": 0},
            {"Action": "pass", "Test": "TestRetry", "Elapsed": 0},
        ]
        sibling = [
            {"Action": "run", "Test": "TestRetry"},
            {"Action": "run", "Test": "TestRetry/a"},
            {"Action": "pass", "Test": "TestRetry/a", "Elapsed": 0},
            {"Action": "run", "Test": "TestRetry/a/b"},
            {"Action": "pause", "Test": "TestRetry/a/b"},
            {"Action": "cont", "Test": "TestRetry/a/b"},
            {"Action": "pass", "Test": "TestRetry/a/b", "Elapsed": 2},
            {"Action": "pass", "Test": "TestRetry", "Elapsed": 0},
        ]
        self.assertEqual(self.collect_events(nested, sibling)["TestRetry"], 1.0)

    def test_retry_in_same_stream_does_not_inherit_stale_active_subtest(self):
        # Event order follows a real Go producer: the first attempt timed out in
        # the sequential subtest "a", and the retry, appended to the same
        # artifact as CI does, ran the parallel slash-named sibling "a/b" first.
        events = [
            {"Action": "run", "Test": "TestR"},
            {"Action": "run", "Test": "TestR/a"},
            {"Action": "run", "Test": "TestR"},
            {"Action": "run", "Test": "TestR/a/b"},
            {"Action": "pause", "Test": "TestR/a/b"},
            {"Action": "run", "Test": "TestR/a"},
            {"Action": "pass", "Test": "TestR/a", "Elapsed": 0},
            {"Action": "cont", "Test": "TestR/a/b"},
            {"Action": "pass", "Test": "TestR/a/b", "Elapsed": 1},
            {"Action": "pass", "Test": "TestR", "Elapsed": 0},
        ]
        self.assertEqual(self.collect_events(events)["TestR"], 0.5)

    def test_completed_retry_keeps_weight_of_interrupted_attempt(self):
        events = [
            {"Action": "run", "Test": "TestRetry"},
            {"Action": "run", "Test": "TestRetry/a"},
            {"Action": "run", "Test": "TestRetry"},
            {"Action": "run", "Test": "TestRetry/a"},
            {"Action": "pass", "Test": "TestRetry/a", "Elapsed": 1},
            {"Action": "pass", "Test": "TestRetry", "Elapsed": 1},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events"
            path.write_text("".join(json.dumps(dict(Package="example.test/internal/proxy", **event)) + "\n"
                                    for event in events), encoding="utf-8")
            self.assertEqual(collect([path], {"proxy": {"TestRetry": 10}})["proxy"]["TestRetry"], 10)

    def test_completed_repetition_can_reduce_weight(self):
        events = [
            {"Action": "run", "Test": "TestRepeat"},
            {"Action": "pass", "Test": "TestRepeat", "Elapsed": 1},
            {"Action": "run", "Test": "TestRepeat"},
            {"Action": "pass", "Test": "TestRepeat", "Elapsed": 2},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events"
            path.write_text("".join(json.dumps(dict(Package="example.test/internal/proxy", **event)) + "\n"
                                    for event in events), encoding="utf-8")
            self.assertEqual(collect([path], {"proxy": {"TestRepeat": 10}})["proxy"]["TestRepeat"], 2)

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

    def test_skipped_run_does_not_lower_previous_measurement(self):
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
            self.assertEqual(collect([path], {"proxy": {"TestPartial": 100}})["proxy"]["TestPartial"], 100)

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
