# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the text DLP throughput gate comparator."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_throughput_gate as gate  # noqa: E402


def rows(name: str, values: list[float], size: int = 1 << 20) -> str:
    return "\n".join(
        f"{name}-4 \t 2 \t {value:.0f} ns/op \t {size / value:.2f} MB/s \t 100 B/op \t 10 allocs/op"
        for value in values
    ) + "\n"


HEADER = "goos: linux\ngoarch: amd64\npkg: github.com/luckyPipewrench/pipelock/internal/scanner\n"


class CompareTest(unittest.TestCase):
    def test_fastest_round_ignores_slow_outliers(self):
        base = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1000, 1010, 990, 1005, 995])
        head = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1000, 5000, 990, 1005, 995])
        result, failed = gate.compare(base, head, 20.0, 10.0)
        self.assertFalse(failed)
        self.assertEqual(result[0]["status"], "ok")

    def test_runner_load_on_later_rounds_does_not_fail(self):
        # Recorded on a loaded workstation: identical scanner code, the head's
        # second and third rounds slowed by other work. Its median is 25 percent
        # slower; its fastest round is not.
        base = HEADER + rows("BenchmarkTextDLPThroughput/short/1MiB", [318e6, 309e6, 304e6])
        head = HEADER + rows("BenchmarkTextDLPThroughput/short/1MiB", [313e6, 386e6, 446e6])
        result, failed = gate.compare(base, head, 20.0, 10.0)
        self.assertFalse(failed)
        self.assertEqual(result[0]["status"], "ok")

    def test_consistent_slowdown_fails(self):
        base = HEADER + rows("BenchmarkTextDLPThroughput/b64json/1MiB", [1000, 1010, 990, 1005, 995])
        head = HEADER + rows("BenchmarkTextDLPThroughput/b64json/1MiB", [1250, 1240, 1260, 1230, 1255])
        result, failed = gate.compare(base, head, 20.0, 10.0)
        self.assertTrue(failed)
        self.assertEqual(result[0]["status"], "FAIL")
        self.assertAlmostEqual(result[0]["delta_pct"], (1230 / 990 - 1) * 100, places=3)
        self.assertAlmostEqual(result[0]["base_mbps"], (1 << 20) / 990, places=1)

    def test_warn_band(self):
        base = HEADER + rows("BenchmarkTextDLPThroughput/short/1MiB", [1000, 1000, 1000])
        head = HEADER + rows("BenchmarkTextDLPThroughput/short/1MiB", [1150, 1150, 1150])
        result, failed = gate.compare(base, head, 20.0, 10.0)
        self.assertFalse(failed)
        self.assertEqual(result[0]["status"], "warn")

    def test_speedup_passes(self):
        base = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1000, 1000, 1000])
        head = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [500, 500, 500])
        _, failed = gate.compare(base, head, 20.0, 10.0)
        self.assertFalse(failed)

    def test_new_and_removed_rows_are_reported_not_compared(self):
        base = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1000, 1000, 1000]) + rows("BenchmarkTextDLPThroughput/old/1MiB", [1, 1, 1])
        head = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1000, 1000, 1000]) + rows("BenchmarkTextDLPThroughput/new/1MiB", [1, 1, 1])
        result, failed = gate.compare(base, head, 20.0, 10.0)
        self.assertFalse(failed)
        self.assertEqual({row["name"]: row["status"] for row in result},
                         {"BenchmarkTextDLPThroughput/prose/1MiB": "ok",
                          "BenchmarkTextDLPThroughput/new/1MiB": "new",
                          "BenchmarkTextDLPThroughput/old/1MiB": "removed"})

    def test_mismatched_rounds_refuse(self):
        base = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1000, 1000, 1000])
        head = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1000, 1000])
        with self.assertRaises(gate.GateError):
            gate.compare(base, head, 20.0, 10.0)

    def test_no_shared_rows_refuse(self):
        with self.assertRaises(gate.GateError):
            gate.compare(HEADER, HEADER, 20.0, 10.0)

    def test_summary_lists_every_row(self):
        base = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1000, 1000, 1000])
        head = HEADER + rows("BenchmarkTextDLPThroughput/prose/1MiB", [1300, 1300, 1300])
        result, _ = gate.compare(base, head, 20.0, 10.0)
        text = gate.summary(result, 20.0, 10.0)
        self.assertIn("| BenchmarkTextDLPThroughput/prose/1MiB |", text)
        self.assertIn("+30.0%", text)
        self.assertIn("FAIL", text)

    def test_benchmark_command_pins_count_and_name(self):
        command = gate.benchmark_command(5, "1x")
        self.assertIn("-count=5", command)
        self.assertIn("-bench=^BenchmarkTextDLPThroughput$", command)
        count, sample = bench_run_single(command)
        self.assertEqual(count, 5)
        self.assertIn("-count=1", sample)


class PrepareBaselineTest(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@invalid.example", *args],
                              check=True, capture_output=True, text=True).stdout.strip()

    def repo(self, root, bench):
        root.mkdir()
        self.git(root, "init", "-q")
        (root / "README").write_text("x\n")
        if bench is not None:
            (root / gate.BENCH_FILE).parent.mkdir(parents=True)
            (root / gate.BENCH_FILE).write_text(bench)
        self.git(root, "add", "-A")
        self.git(root, "commit", "-q", "-m", "init")
        return root

    def test_copies_and_commits_the_candidate_benchmark(self):
        for base_bench in (None, "old\n", "new\n"):
            with self.subTest(base_bench=base_bench), tempfile.TemporaryDirectory() as directory:
                base = self.repo(Path(directory) / "base", base_bench)
                head = self.repo(Path(directory) / "head", "new\n")
                before = self.git(base, "rev-parse", "HEAD")
                gate.prepare_baseline(base, head)
                self.assertEqual((base / gate.BENCH_FILE).read_text(), "new\n")
                self.assertEqual(self.git(base, "status", "--porcelain"), "")
                moved = self.git(base, "rev-parse", "HEAD") != before
                self.assertEqual(moved, base_bench != "new\n")

    def test_candidate_without_benchmark_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self.repo(Path(directory) / "base", None)
            head = self.repo(Path(directory) / "head", None)
            with self.assertRaises(gate.GateError):
                gate.prepare_baseline(base, head)


def bench_run_single(command):
    import bench_run
    return bench_run.single_sample_command(command)


if __name__ == "__main__":
    unittest.main()
