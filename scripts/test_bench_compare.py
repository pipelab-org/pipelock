# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/bench-compare.awk, the check-bench-regression.sh comparator."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("bench_run", Path(__file__).with_name("bench_run.py"))
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)

AWK = Path(__file__).resolve().parent / "bench-compare.awk"


def _line(name: str, nsop: int) -> str:
    return f"{name}-8\t1000\t{nsop} ns/op\t0 B/op\t0 allocs/op\n"


class BenchCompareTest(unittest.TestCase):
    def run_compare(self, base: str, cur: str) -> tuple[int, str, list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "base").write_text(base)
            (d / "cur").write_text(cur)
            missing = d / "missing"
            missing.write_text("")
            proc = subprocess.run(
                ["awk", "-v", "threshold=50", "-v", f"missing={missing}", "-f", str(AWK),
                 str(d / "base"), str(d / "cur")],
                capture_output=True, text=True, check=False,
            )
            return proc.returncode, proc.stdout, sorted(missing.read_text().split())

    def test_missing_baseline_name_is_reported_even_when_survivor_improves(self) -> None:
        base = _line("BenchmarkAlpha", 100) + _line("BenchmarkBeta", 100)
        rc, out, missing = self.run_compare(base, _line("BenchmarkAlpha", 90))
        self.assertEqual((rc, out), (0, ""))
        self.assertEqual(missing, ["BenchmarkBeta"])

    def test_complete_matching_set_reports_nothing(self) -> None:
        base = _line("BenchmarkAlpha", 100) + _line("BenchmarkBeta", 100)
        cur = _line("BenchmarkAlpha", 90) + _line("BenchmarkBeta", 90)
        self.assertEqual(self.run_compare(base, cur), (0, "", []))

    def test_regression_above_threshold_is_reported(self) -> None:
        base = _line("BenchmarkAlpha", 100) + _line("BenchmarkBeta", 100)
        cur = _line("BenchmarkAlpha", 160) + _line("BenchmarkBeta", 90)
        self.assertEqual(self.run_compare(base, cur), (0, "BenchmarkAlpha +60.00%\n", []))

    def test_repeated_samples_do_not_create_missing_names(self) -> None:
        base = _line("BenchmarkAlpha", 100) * 3
        cur = _line("BenchmarkAlpha", 120) + _line("BenchmarkAlpha", 95)
        self.assertEqual(self.run_compare(base, cur), (0, "", []))

    def test_rise_from_zero_baseline_is_reported(self) -> None:
        base = _line("BenchmarkAlpha", 0) + _line("BenchmarkBeta", 100)
        cur = _line("BenchmarkAlpha", 5) + _line("BenchmarkBeta", 100)
        self.assertEqual(
            self.run_compare(base, cur),
            (0, "BenchmarkAlpha rose from a 0 ns/op baseline to 5 ns/op\n", []),
        )

    def test_zero_baseline_that_stays_zero_is_not_reported(self) -> None:
        base = _line("BenchmarkAlpha", 0) + _line("BenchmarkBeta", 100)
        cur = _line("BenchmarkAlpha", 0) + _line("BenchmarkBeta", 100)
        self.assertEqual(self.run_compare(base, cur), (0, "", []))

    def test_zero_baseline_overlap_alone_is_still_overlap(self) -> None:
        base = _line("BenchmarkAlpha", 0)
        self.assertEqual(self.run_compare(base, _line("BenchmarkAlpha", 0)), (0, "", []))

    def test_no_overlap_exits_3(self) -> None:
        rc, _, missing = self.run_compare(_line("BenchmarkAlpha", 100), _line("BenchmarkGamma", 100))
        self.assertEqual(rc, 3)
        self.assertEqual(missing, ["BenchmarkAlpha"])



class SmokeRunTest(unittest.TestCase):
    def test_smoke_propagates_benchmark_failure_and_supplies_fixtures(self):
        real_run = subprocess.run
        for status in (0, 1):
            with self.subTest(status=status):
                def run(command, **kwargs):
                    if command[0] != "go":
                        return real_run(command, **kwargs)
                    for key in ("PIPELOCK_BROWSER_REPRO_BENCH_DIR", "RESPONSE_BENCH_DIR", "PIPELOCK_RESPONSE_BENCH_DIR"):
                        directory = Path(kwargs["env"][key])
                        self.assertTrue((directory / "generated-js-marker.js").is_file())
                        self.assertTrue((directory / "monaco.js").is_file())
                    self.assertTrue(Path(kwargs["env"]["PIPELOCK_RESPONSE_PASS_SAMPLE"]).is_file())
                    self.assertIn("-run=^$", command)
                    self.assertIn("-benchtime=1x", command)
                    self.assertIn("-bench=.", command)
                    self.assertIn("./...", command)
                    self.assertEqual(command[command.index("-tags") + 1], "enterprise")
                    return subprocess.CompletedProcess(command, status)
                with patch.object(RUN.subprocess, "run", side_effect=run):
                    self.assertEqual(RUN.smoke_benchmarks(), status)


SPEC = importlib.util.spec_from_file_location("bench_run", AWK.with_name("bench_run.py"))
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


def allocation_rows(name="BenchmarkExample", allocs=(999, 10), package="example/pkg", bytes_op=100):
    # A (warm-up, steady) pair expands to the real repetition count.
    if len(allocs) == 2:
        allocs = (allocs[0],) + (allocs[1],) * (RUN.ALLOCATION_REPETITIONS - 1)
    return f"pkg: {package}\n" + "".join(
        f"{name}-4 200 100 ns/op {bytes_op} B/op {value} allocs/op\n" for value in allocs)


class AllocationReportTest(unittest.TestCase):
    def test_default_repetitions_catch_variation_after_warmup(self):
        values, notes = RUN.allocation_samples(allocation_rows(allocs=(100, 10, 11, 10)))
        self.assertEqual(values, {})
        self.assertIn("allocs/op varies after warm-up: 10, 11, 10", next(iter(notes.values())))
        self.assertGreaterEqual(RUN.ALLOCATION_REPETITIONS, 3)

    def test_command_covers_subpackages_with_matching_count(self):
        command = RUN.ALLOCATION_COMMAND
        for root in ("scanner", "proxy", "mcp"):
            self.assertIn(f"./internal/{root}/...", command)
        self.assertIn(f"-count={RUN.ALLOCATION_REPETITIONS}", command)

    def test_command_skips_only_benchmarks_without_a_stable_case(self):
        skip = [arg for arg in RUN.ALLOCATION_COMMAND if arg.startswith("-skip=")]
        self.assertEqual(skip, [f"-skip=^({'|'.join(RUN.ALLOCATION_SKIPPED)})$"])
        self.assertIn("BenchmarkDecodeBudget", RUN.ALLOCATION_SKIPPED)
        self.assertNotIn("BenchmarkScanResponse_Large", RUN.ALLOCATION_SKIPPED)
        for name in RUN.ALLOCATION_SKIPPED:
            self.assertRegex(name, r"^Benchmark\w+$")

    def test_skipped_names_are_defined_only_in_their_excluded_package(self):
        root = Path(__file__).resolve().parent.parent
        prefix = "github.com/luckyPipewrench/pipelock/"
        for name in RUN.ALLOCATION_SKIPPED:
            with self.subTest(name=name):
                excluded = {package.removeprefix(prefix) for package, benchmark in RUN.ALLOCATION_EXCLUSIONS
                            if benchmark.split("/", 1)[0] == name}
                defined = {path.parent.relative_to(root).as_posix()
                           for tree in ("scanner", "proxy", "mcp")
                           for path in (root / "internal" / tree).rglob("*_test.go")
                           if re.search(rf"^func {name}\(", path.read_text(encoding="utf-8"), re.M)}
                self.assertEqual(defined, excluded)

    def test_skipped_exclusions_are_listed_not_new_or_removed(self):
        report = RUN.allocation_report("", "")
        self.assertIn("internal/scanner / BenchmarkDecodeBudget/hex: allocs/op varies", report)
        self.assertIn("(skipped, not run)", report)
        self.assertNotIn("| new |", report)
        self.assertNotIn("| removed |", report)
        self.assertNotIn("BenchmarkScanResponse_Large", report)

    def test_warmup_discard_and_bytes_not_compared(self):
        report = RUN.allocation_report(allocation_rows(allocs=(999, 10)),
                                       allocation_rows(allocs=(123, 10), bytes_op=101))
        self.assertIn("Changed rows: 0", report)
        self.assertIn("Unchanged benchmarks: 1", report)
        self.assertIn("B/op and timing are not compared", report)

    def test_deterministic_changed_rows_then_new_removed(self):
        base = allocation_rows("BenchmarkZ") + allocation_rows("BenchmarkA") + allocation_rows("BenchmarkOld")
        head = allocation_rows("BenchmarkZ", (9, 11)) + allocation_rows("BenchmarkA", (8, 0)) + allocation_rows("BenchmarkNew")
        report = RUN.allocation_report(base, head)
        self.assertEqual(report, RUN.allocation_report(
            allocation_rows("BenchmarkOld") + allocation_rows("BenchmarkA") + allocation_rows("BenchmarkZ"),
            allocation_rows("BenchmarkNew") + allocation_rows("BenchmarkA", (8, 0)) + allocation_rows("BenchmarkZ", (9, 11))))
        self.assertLess(report.index("pkg / BenchmarkA"), report.index("pkg / BenchmarkZ"))
        self.assertLess(report.index("pkg / BenchmarkZ"), report.index("pkg / BenchmarkNew"))
        self.assertIn("| 10 | 0 | -10 |", report)
        self.assertIn("BenchmarkNew | new |", report)
        self.assertIn("BenchmarkOld | removed |", report)

    def test_package_qualifies_duplicate_names(self):
        rows = allocation_rows(package="one") + allocation_rows(package="two")
        self.assertIn("Unchanged benchmarks: 2", RUN.allocation_report(rows, rows))

    def test_duplicate_and_malformed_rows_are_excluded(self):
        cases = [allocation_rows() * 2,
                 allocation_rows() + "BenchmarkExample-4 nonsense\n",
                 allocation_rows(allocs=(1,)),
                 allocation_rows().replace("10 allocs/op", "oops allocs/op"),
                 allocation_rows().replace("100 ns/op", "oops ns/op")]
        for rows in cases:
            with self.subTest(rows=rows):
                report = RUN.allocation_report(rows, allocation_rows())
                self.assertIn("Unchanged benchmarks: 0", report)
                self.assertIn("### Excluded benchmarks\n\n-", report)
                self.assertNotIn("BenchmarkExample | new", report)

    def test_processor_mismatch_is_not_compared(self):
        base = allocation_rows()
        head = allocation_rows().replace("BenchmarkExample-4", "BenchmarkExample-8")
        report = RUN.allocation_report(base, head)
        self.assertIn("GOMAXPROCS differs", report)
        self.assertIn("Unchanged benchmarks: 0", report)
        mixed = base.replace("BenchmarkExample-4", "BenchmarkExample-8", 1)
        self.assertIn("mixed effective GOMAXPROCS", RUN.allocation_report(mixed, base))

    def test_zero_allocations(self):
        report = RUN.allocation_report(allocation_rows(allocs=(2, 0)), allocation_rows(allocs=(1, 3)))
        self.assertIn("| 0 | 3 | +3 |", report)
        self.assertIn("Unchanged benchmarks: 1", RUN.allocation_report(allocation_rows(allocs=(1, 0)), allocation_rows(allocs=(2, 0))))

    def test_varying_after_warmup_is_excluded_without_tolerance(self):
        values, notes = RUN.allocation_samples(allocation_rows(allocs=(100, 10, 11, 10)), repetitions=4)
        self.assertEqual(values, {})
        self.assertIn("varies after warm-up: 10, 11, 10", next(iter(notes.values())))
        from unittest.mock import patch
        with patch.dict(RUN.ALLOCATION_EXCLUSIONS, {("example/pkg", "BenchmarkExample"): "observed varying: 10, 11, 10"}):
            report = RUN.allocation_report(allocation_rows(), allocation_rows())
        self.assertIn("observed varying: 10, 11, 10", report)
        self.assertIn("Unchanged benchmarks: 0", report)

    def test_new_excluded_benchmark_is_still_listed_as_new(self):
        from unittest.mock import patch
        with patch.dict(RUN.ALLOCATION_EXCLUSIONS, {("example/pkg", "BenchmarkExample"): "observed varying"}):
            report = RUN.allocation_report("", allocation_rows())
        self.assertIn("BenchmarkExample | new |", report)
        self.assertIn("observed varying", report)

    def test_optional_throughput_and_custom_metrics(self):
        rows = allocation_rows().replace("100 ns/op", "100 ns/op 5 MB/s").replace("allocs/op", "allocs/op 7 custom/op")
        self.assertIn("Unchanged benchmarks: 1", RUN.allocation_report(rows, rows))

    def test_empty_outputs_are_visible(self):
        self.assertIn("No comparable allocation samples", RUN.allocation_report("", ""))


if __name__ == "__main__":
    unittest.main()
