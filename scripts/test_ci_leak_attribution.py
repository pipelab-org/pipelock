# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Check that leaked CI processes are matched to the tests running when they started."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ci_leak_attribution as attribution  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci_leak_attribution.py"
PKG = "example.com/p/pkg"


def event(action: str, test: str, at: str, package: str = PKG) -> str:
    return json.dumps({"Time": at, "Action": action, "Package": package, "Test": test})


STREAM = [
    event("run", "TestEarly", "2026-11-17T10:00:00.000000001Z"),
    event("pass", "TestEarly", "2026-11-17T10:00:01Z"),
    event("run", "TestParent", "2026-11-17T10:00:02Z"),
    event("run", "TestParent/child", "2026-11-17T10:00:02.5Z"),
    event("run", "TestParallel", "2026-11-17T10:00:02.7Z", "example.com/p/other"),
    event("fail", "TestParent/child", "2026-11-17T10:00:04.123456789Z"),
    event("pass", "TestParent", "2026-11-17T10:00:05Z"),
    event("run", "TestHung", "2026-11-17T10:00:06Z"),
    "not json",
    json.dumps({"Action": "output", "Package": PKG, "Output": "ok\n"}),
]


def unix(text: str) -> float:
    return attribution.parse_time(text)


class TestLeakAttribution(unittest.TestCase):
    def test_parse_time_accepts_go_nanoseconds_and_rejects_garbage(self) -> None:
        self.assertAlmostEqual(unix("2026-11-17T10:00:04.123456789Z") % 10, 4.123456, places=5)
        self.assertEqual(unix("2026-11-17T10:00:00Z"), unix("2026-11-17T10:00:00+00:00"))
        for bad in (None, "", "yesterday", 7):
            self.assertIsNone(attribution.parse_time(bad))

    def test_running_tests_deepest_first(self) -> None:
        windows = attribution.collect_windows(STREAM)
        self.assertEqual(
            attribution.running_at(windows, unix("2026-11-17T10:00:03Z")),
            [f"{PKG} TestParent/child", "example.com/p/other TestParallel", f"{PKG} TestParent"],
        )

    def test_window_edges_and_unfinished_tests(self) -> None:
        windows = attribution.collect_windows(STREAM)
        # A spawn at a test's last instant still belongs to it.
        self.assertIn(f"{PKG} TestEarly", attribution.running_at(windows, unix("2026-11-17T10:00:01.01Z")))
        self.assertNotIn(f"{PKG} TestEarly", attribution.running_at(windows, unix("2026-11-17T10:00:01.5Z")))
        # A test with no terminal event ran until the stream ended.
        self.assertIn(f"{PKG} TestHung", attribution.running_at(windows, unix("2026-11-17T11:00:00Z")))
        self.assertEqual(attribution.running_at(windows, unix("2026-11-17T09:00:00Z")), [])

    def test_attribute_reports_each_process(self) -> None:
        report = {"cleanup_processes": [
            {"pid": 11, "name": "sleep", "started_unix": unix("2026-11-17T10:00:03Z")},
            {"pid": 12, "name": "sh", "started_unix": None},
            {"pid": 13, "name": "sleep", "started_unix": unix("2026-11-17T09:00:00Z")},
            "garbage",
        ]}
        messages = attribution.attribute(report, STREAM)
        self.assertEqual(len(messages), 3)
        self.assertIn("leaked process sleep (pid 11) started at 2026-11-17T10:00:03.000+00:00", messages[0])
        self.assertIn(f"{PKG} TestParent/child", messages[0])
        self.assertNotIn("TestEarly", messages[0])
        self.assertEqual(messages[1], "leaked process sh (pid 12): start time unavailable")
        self.assertIn("no test was running then", messages[2])

    def test_attribute_caps_long_lists(self) -> None:
        stream = [event("run", f"TestP{i:02d}", "2026-11-17T10:00:00Z") for i in range(25)]
        report = {"cleanup_processes": [{"pid": 1, "name": "sleep", "started_unix": unix("2026-11-17T10:00:01Z")}]}
        (message,) = attribution.attribute(report, stream)
        self.assertIn("(+5 more)", message)
        self.assertEqual(message.count(f"{PKG} TestP"), attribution.MAX_TESTS_PER_PROCESS)

    def test_attribute_ignores_reports_without_processes(self) -> None:
        self.assertEqual(attribution.attribute({}, STREAM), [])
        self.assertEqual(attribution.attribute({"cleanup_processes": "x"}, STREAM), [])

    def test_cli_never_fails_the_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            events = directory / "events.json"
            events.write_text("\n".join(STREAM) + "\n", encoding="utf-8")
            status = directory / "status.json"
            status.write_text(json.dumps({"cleanup_processes": [
                {"pid": 11, "name": "sleep", "started_unix": unix("2026-11-17T10:00:03Z")},
            ]}), encoding="utf-8")
            cases = {
                "report": (status, events, f"{PKG} TestParent/child"),
                "missing report": (directory / "absent", events, ""),
                "malformed report": (events, events, ""),
                "missing events": (status, directory / "absent", ""),
            }
            for name, (report, stream, expected) in cases.items():
                with self.subTest(name):
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), str(report), str(stream)],
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "")
                    if expected:
                        self.assertIn(expected, result.stderr)
                    else:
                        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
