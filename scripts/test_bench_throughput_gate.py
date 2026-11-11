# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the text DLP throughput gate comparator."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

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
    def test_one_noisy_pair_does_not_decide(self):
        result, failed = run("prose/1MiB", [1000, 1010, 990, 1005, 995, 1000], [1000, 5000, 990, 1005, 995, 1000])
        self.assertFalse(failed)
        self.assertEqual(result["prose/1MiB"]["status"], "ok")

    def test_load_drift_hitting_both_sides_does_not_fail(self):
        # Identical code while the runner slows across the job: each pair runs
        # back to back, so the ratio stays near 1 even as both sides drift.
        base = [300e6, 390e6, 450e6, 320e6, 410e6, 300e6]
        head = [310e6, 380e6, 460e6, 315e6, 420e6, 305e6]
        result, failed = run("short/1MiB", base, head)
        self.assertFalse(failed)
        self.assertEqual(result["short/1MiB"]["status"], "ok")

    def test_consistent_slowdown_fails(self):
        base = [1000, 1010, 990, 1005, 995, 1000]
        head = [1250, 1240, 1260, 1230, 1255, 1250]
        result, failed = run("b64json/1MiB", base, head)
        self.assertTrue(failed)
        row = result["b64json/1MiB"]
        self.assertEqual(row["status"], "FAIL")
        ratios = sorted(h / b for b, h in zip(base, head))
        self.assertAlmostEqual(row["delta_pct"], ((ratios[2] + ratios[3]) / 2 - 1) * 100, places=3)
        self.assertAlmostEqual(row["base_mbps"], (1 << 20) / 1000, places=1)

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

    def test_nonpositive_or_nonfinite_samples_refuse(self):
        for bad in (0, float("inf")):
            with self.subTest(bad=bad), self.assertRaises(gate.GateError):
                with mock.patch.object(gate, "samples", side_effect=[
                    {f"{gate.BENCH_NAME}/{s}": [bad] * 6 for s in gate.EXPECTED_SHAPES},
                    {f"{gate.BENCH_NAME}/{s}": [1000] * 6 for s in gate.EXPECTED_SHAPES},
                ]):
                    gate.compare("", "", 20, 10, 6)

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

    def test_failure_detail_includes_benchmark_stdout(self):
        # go test prints a benchmark's b.Fatal to stdout, not stderr.
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "candidate-2.txt").write_text("--- FAIL: BenchmarkTextDLPThroughput/b64json/1MiB\n    benchmark input must scan clean\n")
            (output / "candidate-2.stderr").write_text("")
            (output / "inputs.json").write_text("{}")
            detail = gate.failure_detail(output)
        self.assertIn("candidate-2.txt", detail)
        self.assertIn("must scan clean", detail)
        self.assertNotIn("inputs.json", detail)

    def test_fence_cannot_be_closed_by_its_content(self):
        text = "error\n```\n# FAKE PASS\n````"
        block = gate.fenced(text)
        fence = block.split("\n", 1)[0]
        self.assertEqual(fence, "`" * 5)
        self.assertTrue(block.endswith("\n" + fence))
        self.assertNotIn("\n" + fence + "\n", block[len(fence):-len(fence)])

    def test_benchmark_command_pins_count_and_name(self):
        command = gate.benchmark_command(5, "1x")
        self.assertIn("-count=5", command)
        self.assertIn("-bench=^BenchmarkTextDLPThroughput$", command)
        count, sample = bench_run_single(command)
        self.assertEqual(count, 5)
        self.assertIn("-count=1", sample)


class FailureReportingTest(unittest.TestCase):
    def test_failing_invocation_leads_the_detail(self):
        # Six rounds of successful candidate output sort after the failing
        # baseline sample; the failure must survive the size cap.
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            records = []
            for number in range(1, 7):
                for side in ("baseline", "candidate"):
                    (output / f"{side}-{number}.txt").write_text("PASS\n" + "x" * 2000)
                    (output / f"{side}-{number}.stderr").write_text("")
                    records.append({"round": number, "side": side, "stdout": f"{side}-{number}.txt",
                                    "stderr": f"{side}-{number}.stderr"})
            (output / "baseline-6.txt").write_text("--- FAIL: PROBE_SHAPE_FATAL\n")
            records.append(records.pop(-2))  # baseline-6 ran last and failed
            (output / "execution.jsonl").write_text("\n".join(json.dumps(r) for r in records) + "\n")
            detail = gate.failure_detail(output)
        self.assertTrue(detail.startswith("baseline-6.txt:"), detail[:80])
        self.assertIn("PROBE_SHAPE_FATAL", detail)
        self.assertLessEqual(len(detail), 4000)

    def run_main(self, *argv):
        # A capture that always measures a 100 percent slowdown: only the
        # argument checks can keep it from deciding.
        def doubled(baseline, candidate, output, command):
            base = HEADER + "".join(rows(f"{gate.BENCH_NAME}/{s}", [1000.0] * 6) for s in gate.EXPECTED_SHAPES)
            head = HEADER + "".join(rows(f"{gate.BENCH_NAME}/{s}", [2000.0] * 6) for s in gate.EXPECTED_SHAPES)
            (output / "baseline.txt").write_text(base)
            (output / "current.txt").write_text(head)
        with mock.patch.object(sys, "argv", ["bench_throughput_gate.py", *argv]), \
             mock.patch.object(gate, "prepare_baseline"), \
             mock.patch.object(gate.bench_run, "capture_pair", side_effect=doubled) as capture, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                status = gate.main()
            except SystemExit as exit_:
                status = exit_.code
        return status, capture

    def test_doubled_capture_fails_with_default_thresholds(self):
        with tempfile.TemporaryDirectory() as directory:
            status, capture = self.run_main("--baseline", directory, "--candidate", directory,
                                            "--output", str(Path(directory) / "out"))
        self.assertEqual(status, 1)
        capture.assert_called_once()

    def test_odd_or_short_round_counts_are_undecided(self):
        with tempfile.TemporaryDirectory() as directory:
            for rounds in ("2", "3", "5"):
                with self.subTest(rounds=rounds):
                    status, capture = self.run_main("--baseline", directory, "--candidate", directory,
                                                    "--output", str(Path(directory) / "out"), "--rounds", rounds)
                    self.assertEqual(status, 2)
                    capture.assert_not_called()

    def test_unwritable_results_are_undecided(self):
        real = Path.write_text

        def fail_summary(path, *args, **kwargs):
            if path.name == "throughput-summary.md":
                raise OSError("disk full")
            return real(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(Path, "write_text", autospec=True, side_effect=fail_summary):
            status, capture = self.run_main("--baseline", directory, "--candidate", directory,
                                            "--output", str(Path(directory) / "out"))
        self.assertEqual(status, 2)
        capture.assert_called_once()

    def test_unexpected_capture_errors_reach_the_summary(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(sys, "argv", ["bench_throughput_gate.py", "--baseline", directory,
                                             "--candidate", directory, "--output", str(Path(directory) / "out")]), \
             mock.patch.object(gate, "prepare_baseline"), \
             mock.patch.object(gate.bench_run, "capture_pair",
                               side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad byte")), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = gate.run()
            summary = (Path(directory) / "out" / "throughput-summary.md").read_text()
        self.assertEqual(status, 2)
        self.assertIn("Not decided", summary)
        self.assertIn("bad byte", summary)

    def test_unexpected_errors_are_undecided(self):
        with mock.patch.object(gate, "main", side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            status = gate.run()
        self.assertEqual(status, 2)
        self.assertIn("UnicodeDecodeError", err.getvalue())

    def test_failure_detail_keeps_the_end_of_a_long_error(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "candidate-1.stderr").write_text("x" * 9000 + "\nFINAL_COMPILER_ERROR\n")
            (output / "baseline-1.stderr").write_text("y" * 9000 + "\n")
            (output / "execution.jsonl").write_text(json.dumps(
                {"round": 1, "side": "candidate", "stdout": "candidate-1.txt", "stderr": "candidate-1.stderr"}) + "\n")
            detail = gate.failure_detail(output)
        self.assertTrue(detail.startswith("candidate-1.stderr:"), detail[:40])
        self.assertTrue(detail.endswith("FINAL_COMPILER_ERROR"), detail[-40:])
        self.assertLessEqual(len(detail), 4000)

    def test_failure_detail_keeps_both_streams_of_the_failing_run(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "candidate-1.stderr").write_text("e" * 9000 + "\nSTDERR_END\n")
            (output / "candidate-1.txt").write_text("--- FAIL: BenchmarkX\nSTDOUT_FATAL\n")
            (output / "execution.jsonl").write_text(json.dumps(
                {"round": 1, "side": "candidate", "stdout": "candidate-1.txt", "stderr": "candidate-1.stderr"}) + "\n")
            detail = gate.failure_detail(output)
        self.assertIn("STDERR_END", detail)
        self.assertIn("STDOUT_FATAL", detail)
        self.assertLessEqual(len(detail), 4000)

    def test_invalid_thresholds_are_undecided(self):
        with tempfile.TemporaryDirectory() as directory:
            for bad in (("--fail-pct", "nan"), ("--warn-pct", "nan"), ("--fail-pct", "inf"),
                        ("--warn-pct", "30", "--fail-pct", "20"), ("--warn-pct", "-1")):
                with self.subTest(bad=bad):
                    status, capture = self.run_main("--baseline", directory, "--candidate", directory,
                                                    "--output", str(Path(directory) / "out"), *bad)
                    self.assertEqual(status, 2)
                    capture.assert_not_called()

    def test_unreadable_diagnostics_remain_undecided(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(gate, "prepare_baseline", side_effect=gate.GateError("capture failed")), \
             mock.patch.object(gate, "failure_detail", side_effect=OSError("unreadable")), \
             mock.patch.object(sys, "argv", ["gate", "--baseline", directory, "--candidate", directory,
                                            "--output", str(Path(directory) / "out")]), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(gate.main(), 2)

    def test_unusable_output_is_undecided_not_slower(self):
        with tempfile.TemporaryDirectory() as directory:
            blocker = Path(directory) / "file"
            blocker.write_text("not a directory")
            status, capture = self.run_main("--baseline", directory, "--candidate", directory, "--output", str(blocker))
        self.assertEqual(status, 2)
        capture.assert_not_called()

    def test_workflow_measures_unless_classifier_says_no(self):
        import yaml
        workflow = yaml.safe_load((Path(__file__).resolve().parent.parent / ".github/workflows/ci.yaml").read_text())
        condition = workflow["jobs"]["benchmark-throughput"]["if"]
        self.assertIn("needs.changed-files.outputs.benchmark_throughput != 'false'", condition)
        self.assertNotIn("benchmark_throughput == 'true'", condition)


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
