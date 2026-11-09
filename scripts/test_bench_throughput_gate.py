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


def run(shape: str, base_values: list[float], head_values: list[float], omit: str = ""):
    """Compare one shape's samples; the other expected shapes are unchanged."""
    base, head = HEADER, HEADER
    for name in gate.EXPECTED_SHAPES:
        full = f"{gate.BENCH_NAME}/{name}"
        b, h = (base_values, head_values) if name == shape else ([1000.0] * len(base_values),) * 2
        base += rows(full, b)
        if name != omit:
            head += rows(full, h)
    result, failed = gate.compare(base, head, 20.0, 10.0, len(base_values))
    return {row["name"].split("/", 1)[1]: row for row in result}, failed


class CompareTest(unittest.TestCase):
    def test_fastest_round_ignores_slow_outliers(self):
        result, failed = run("prose/1MiB", [1000, 1010, 990, 1005, 995], [1000, 5000, 990, 1005, 995])
        self.assertFalse(failed)
        self.assertEqual(result["prose/1MiB"]["status"], "ok")

    def test_runner_load_on_later_rounds_does_not_fail(self):
        # Recorded on a loaded workstation: identical scanner code, the head's
        # second and third rounds slowed by other work. Its median is 25 percent
        # slower; its fastest round is not.
        result, failed = run("short/1MiB", [318e6, 309e6, 304e6], [313e6, 386e6, 446e6])
        self.assertFalse(failed)
        self.assertEqual(result["short/1MiB"]["status"], "ok")

    def test_consistent_slowdown_fails(self):
        result, failed = run("b64json/1MiB", [1000, 1010, 990, 1005, 995], [1250, 1240, 1260, 1230, 1255])
        self.assertTrue(failed)
        row = result["b64json/1MiB"]
        self.assertEqual(row["status"], "FAIL")
        self.assertAlmostEqual(row["delta_pct"], (1230 / 990 - 1) * 100, places=3)
        self.assertAlmostEqual(row["base_mbps"], (1 << 20) / 990, places=1)

    def test_warn_band(self):
        result, failed = run("short/1MiB", [1000, 1000, 1000], [1150, 1150, 1150])
        self.assertFalse(failed)
        self.assertEqual(result["short/1MiB"]["status"], "warn")

    def test_speedup_passes(self):
        _, failed = run("prose/1MiB", [1000, 1000, 1000], [500, 500, 500])
        self.assertFalse(failed)

    def test_missing_or_extra_shapes_refuse(self):
        # A skipped shape (b.Skip, a failed sub-benchmark) is not a pass.
        with self.assertRaisesRegex(gate.GateError, "expected"):
            run("prose/1MiB", [1000, 1000, 1000], [1000, 1000, 1000], omit="b64json/1MiB")
        base = HEADER + "".join(rows(f"{gate.BENCH_NAME}/{n}", [1000] * 3) for n in gate.EXPECTED_SHAPES)
        extra = base + rows(f"{gate.BENCH_NAME}/new/1MiB", [1000] * 3)
        with self.assertRaisesRegex(gate.GateError, "expected"):
            gate.compare(base, extra, 20.0, 10.0, 3)

    def test_round_count_must_match_the_request(self):
        base = HEADER + "".join(rows(f"{gate.BENCH_NAME}/{n}", [1000] * 3) for n in gate.EXPECTED_SHAPES)
        for rounds in (2, 5):
            with self.subTest(rounds=rounds), self.assertRaisesRegex(gate.GateError, "rounds"):
                gate.compare(base, base, 20.0, 10.0, rounds)
        with self.assertRaisesRegex(gate.GateError, "rounds"):
            run("prose/1MiB", [1000, 1000, 1000], [1000, 1000])

    def test_no_rows_refuse(self):
        with self.assertRaises(gate.GateError):
            gate.compare(HEADER, HEADER, 20.0, 10.0, 3)

    def test_summary_lists_every_row(self):
        result, _ = run("prose/1MiB", [1000, 1000, 1000], [1300, 1300, 1300])
        text = gate.summary(list(result.values()), 20.0, 10.0)
        self.assertIn("| BenchmarkTextDLPThroughput/prose/1MiB |", text)
        self.assertIn("+30.0%", text)
        self.assertIn("FAIL", text)

    def test_failure_detail_reports_sample_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "baseline-1.stderr").write_text("internal/scanner/x_test.go:9: undefined: scanner.NewAPI\n")
            (output / "candidate-1.stderr").write_text("")
            detail = gate.failure_detail(output)
        self.assertIn("baseline-1.stderr", detail)
        self.assertIn("undefined: scanner.NewAPI", detail)
        self.assertNotIn("candidate-1.stderr", detail)

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

    def test_dirty_baseline_is_refused_before_any_change(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self.repo(Path(directory) / "base", "old\n")
            head = self.repo(Path(directory) / "head", "new\n")
            (base / "README").write_text("staged\n")
            self.git(base, "add", "README")
            before = self.git(base, "rev-parse", "HEAD")
            with self.assertRaises(gate.bench_run.RunError):
                gate.prepare_baseline(base, head)
            self.assertEqual(self.git(base, "rev-parse", "HEAD"), before)
            self.assertEqual((base / gate.BENCH_FILE).read_text(), "old\n")

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
