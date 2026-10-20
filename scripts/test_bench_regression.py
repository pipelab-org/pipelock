# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Synthetic admission/runner tests; no Go executable or benchmark is run."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "check-bench-regression.sh"
SPEC = importlib.util.spec_from_file_location("bench_run", HERE / "bench_run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)
COMMAND = ["go", "test", "-bench=.", "-benchmem", "-count=6", "-benchtime=100ms", "-run=^$", "./internal/scanner/", "./internal/mcp/"]


def inputs(source="baseline-source"):
    return {
        "source": source, "go": "go version go1.27.0 linux/amd64",
        "machine": "Linux synthetic-kernel x86_64 GNU/Linux", "command": list(COMMAND),
        "go_env": {"GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "", "GOEXPERIMENT": "", "CGO_ENABLED": "1"},
    }


def samples(name="BenchmarkExample-4", ns=100, package="scanner"):
    return ("goos: linux\ngoarch: amd64\n"
            f"pkg: github.com/luckyPipewrench/pipelock/internal/{package}\n"
            f"cpu: Synthetic Processor\n{name} 1000 {ns} ns/op 0 B/op 0 allocs/op\n")


class InputsTest(unittest.TestCase):
    def test_matching_inputs(self):
        RUN.validate_inputs(inputs(), inputs("candidate-source"))

    def test_input_mismatches_and_missing_fields(self):
        for key in ("go", "machine", "command", "go_env"):
            with self.subTest(key=key):
                other = inputs()
                other[key] = "different"
                with self.assertRaisesRegex(RUN.RunError, "mismatch"):
                    RUN.validate_inputs(inputs(), other)
                other.pop(key)
                with self.assertRaisesRegex(RUN.RunError, "missing"):
                    RUN.validate_inputs(inputs(), other)
        for key in inputs()["go_env"]:
            with self.subTest(environment=key):
                base = inputs()
                base["go_env"].pop(key)
                with self.assertRaisesRegex(RUN.RunError, "missing"):
                    RUN.validate_inputs(base, copy.deepcopy(base))
                other = inputs()
                other["go_env"][key] = "different"
                with self.assertRaisesRegex(RUN.RunError, "mismatch"):
                    RUN.validate_inputs(inputs(), other)

    def test_actual_versions_are_resolved_in_each_directory(self):
        directory = Path("/synthetic-source")
        answers = ["go version go1.27.0 linux/amd64", inputs()["machine"], json.dumps(inputs()["go_env"])]
        with patch.object(RUN, "command_output", side_effect=answers) as output:
            got = RUN.run_inputs(directory, "source-id", COMMAND)
        self.assertEqual(got["source"], "source-id")
        self.assertEqual(got["command"], COMMAND)
        self.assertEqual(output.call_args_list[0].args, (["go", "version"], directory))
        self.assertTrue(all(call.args[1] == directory for call in output.call_args_list))

    def test_subprocess_output_is_checked(self):
        with patch.object(RUN.subprocess, "run") as process:
            process.return_value.stdout = " result\n"
            self.assertEqual(RUN.command_output(["go", "version"], Path("/source")), "result")
        self.assertTrue(process.call_args.kwargs["check"])

    def test_checkout_root_clean_and_dirty(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for dirty in ("?? new.txt", " M modified.txt", "M  staged.txt"):
                with self.subTest(status=dirty), patch.object(RUN, "command_output", side_effect=[str(root), dirty]):
                    with self.assertRaisesRegex(RUN.RunError, "clean"):
                        RUN.checkout_state(root)
            with patch.object(RUN, "command_output", side_effect=[str(root), "", "source-id"]):
                self.assertEqual(RUN.checkout_state(root), "source-id")
            with patch.object(RUN, "command_output", return_value=str(root.parent)):
                with self.assertRaisesRegex(RUN.RunError, "checkout root"):
                    RUN.checkout_state(root)


class OutputTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        self.base, self.cur = self.directory / "base.txt", self.directory / "cur.txt"

    def compare(self, base, cur):
        self.base.write_text(base)
        self.cur.write_text(cur)
        RUN.validate_outputs(self.base, self.cur, inputs())

    def test_repeated_package_headers_and_one_cpu_without_suffix(self):
        text = samples() + samples(package="mcp")
        self.compare(text, text)
        self.compare(samples("BenchmarkOne"), samples("BenchmarkOne-1"))
        text = samples("BenchmarkOne-2") + samples("BenchmarkOne-4")
        self.compare(text, text)

    def test_mismatched_headers(self):
        for key, new_value in (("goos", "other-os"), ("goarch", "other-arch"), ("cpu", "Other Processor")):
            with self.subTest(key=key):
                text = samples()
                old = next(line for line in text.splitlines() if line.startswith(key + ":"))
                with self.assertRaisesRegex(RUN.RunError, "header mismatch"):
                    self.compare(text, text.replace(old, f"{key}: {new_value}"))

    def test_headers_must_match_resolved_target(self):
        text = samples().replace("goos: linux", "goos: other-os")
        with self.assertRaisesRegex(RUN.RunError, "resolved Go environment"):
            self.compare(text, text)

    def test_missing_or_inconsistent_headers(self):
        for key in ("goos", "goarch", "cpu"):
            text = samples()
            header = next(line for line in text.splitlines() if line.startswith(key + ":"))
            for bad in (text.replace(header + "\n", ""), text + f"{key}: other\n", text.replace(header, f"{key}: ")):
                with self.subTest(key=key, bad=bad), self.assertRaisesRegex(RUN.RunError, "missing or inconsistent"):
                    self.compare(bad, samples())

    def test_effective_processors_match_per_shared_benchmark(self):
        for cur in (samples("BenchmarkExample-16"), samples("BenchmarkExample-4") + samples("BenchmarkExample-16")):
            with self.subTest(cur=cur), self.assertRaisesRegex(RUN.RunError, "GOMAXPROCS"):
                self.compare(samples(), cur)

    def test_missing_names_and_no_overlap_remain_comparator_decisions(self):
        self.compare(samples() + samples("BenchmarkRemoved-16"), samples())
        self.compare(samples(), samples("BenchmarkOther-8"))

    def test_missing_package_or_samples_is_refused(self):
        for text in (samples().replace("pkg: github.com/luckyPipewrench/pipelock/internal/scanner\n", ""), "", "BenchmarkProgress-4\n"):
            with self.subTest(text=text), self.assertRaises(RUN.RunError):
                self.compare(text, samples())

    def test_malformed_nsop_cannot_be_scored_as_zero(self):
        for value in ("broken", "NaN", "-1", "1e3"):
            with self.subTest(value=value), self.assertRaisesRegex(RUN.RunError, "invalid benchmark ns/op"):
                self.compare(samples(), samples().replace("100 ns/op", f"{value} ns/op"))
        for row in ("BenchmarkExample-4 0 100 ns/op", "BenchmarkExample-4 1000 extra 100 ns/op"):
            with self.subTest(row=row), self.assertRaisesRegex(RUN.RunError, "invalid benchmark ns/op"):
                self.compare(samples(), samples().replace("BenchmarkExample-4 1000 100 ns/op", row))


class PairTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="bench pair ")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.base, self.cur, self.out = (self.root / name for name in ("base", "cur", "output"))
        for directory in (self.base, self.cur, self.out):
            directory.mkdir()
        self.sources = {self.base: "baseline-source", self.cur: "candidate-source"}
        self.calls = []
        self.failure = None
        self.raw_candidate = samples()
        self.source_patch = patch.object(RUN, "checkout_state", side_effect=lambda path: self.sources[path])
        self.input_patch = patch.object(RUN, "run_inputs", side_effect=lambda path, source, command: inputs(source))
        self.process_patch = patch.object(RUN.subprocess, "run", side_effect=self.measurement)
        for mock in (self.source_patch, self.input_patch, self.process_patch):
            mock.start()
            self.addCleanup(mock.stop)

    def measurement(self, command, *, cwd, check, stdout, stderr):
        self.assertTrue(check)
        self.calls.append((cwd, list(command)))
        stdout.write(samples() if cwd == self.base else self.raw_candidate)
        stderr.write("synthetic stderr\n")
        if cwd == self.failure:
            raise subprocess.CalledProcessError(9, command)

    def capture(self):
        RUN.capture_pair(self.base, self.cur, self.out, list(COMMAND))

    def test_sequential_identical_commands_and_retained_inputs(self):
        self.capture()
        self.assertEqual(self.calls, [(self.base, COMMAND), (self.cur, COMMAND)])
        recorded = json.loads((self.out / "inputs.json").read_text())
        self.assertEqual(recorded["baseline"], inputs())
        self.assertEqual(recorded["candidate"], inputs("candidate-source"))
        for name in ("inputs.json", "baseline.txt", "current.txt", "baseline.stderr", "current.stderr"):
            path = self.out / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn("# Source: candidate-source", (self.out / "current.txt").read_text())

    def test_same_source_refused_before_measurement(self):
        self.sources[self.cur] = self.sources[self.base]
        with self.assertRaisesRegex(RUN.RunError, "distinct source"):
            self.capture()
        self.assertEqual(self.calls, [])

    def test_mismatched_inputs_stop_before_measurement(self):
        def changed(path, source, command):
            data = inputs(source)
            if path == self.cur:
                data["go"] = "go version go1.26.0 linux/amd64"
            return data
        with patch.object(RUN, "run_inputs", side_effect=changed), self.assertRaisesRegex(RUN.RunError, "mismatch: go"):
            self.capture()
        self.assertEqual(self.calls, [])

    def test_failed_measurement_stops_pair_and_validation(self):
        for failed in (self.base, self.cur):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory(dir=self.root) as directory:
                self.out = Path(directory)
                self.calls = []
                self.failure = failed
                with patch.object(RUN, "validate_outputs") as validate, self.assertRaises(subprocess.CalledProcessError):
                    self.capture()
                validate.assert_not_called()
                self.assertEqual(len(self.calls), 1 if failed == self.base else 2)

    def test_output_mismatch_is_not_an_accepted_pair(self):
        self.raw_candidate = samples("BenchmarkExample-8")
        with self.assertRaisesRegex(RUN.RunError, "GOMAXPROCS"):
            self.capture()

    def test_preexisting_capture_and_symlink_not_overwritten(self):
        sentinel = self.root / "sentinel"
        sentinel.write_text("keep")
        (self.out / "inputs.json").symlink_to(sentinel)
        with self.assertRaises(FileExistsError):
            self.capture()
        self.assertEqual(sentinel.read_text(), "keep")
        self.assertEqual(self.calls, [])

    def test_output_must_stay_outside_checkouts(self):
        inside = self.cur / "output"
        inside.mkdir()
        with self.assertRaisesRegex(RUN.RunError, "outside"):
            RUN.capture_pair(self.base, self.cur, inside, COMMAND)
        self.assertEqual(self.calls, [])

    def test_source_or_toolchain_change_is_refused(self):
        original = RUN.measure
        for key in ("source", "inputs"):
            with self.subTest(key=key), tempfile.TemporaryDirectory(dir=self.root) as directory:
                self.out = Path(directory)
                self.sources[self.cur] = "candidate-source"
                def measure(path, source, metadata, output, command):
                    original(path, source, metadata, output, command)
                    if key == "source":
                        self.sources[self.base] = "changed-source"
                self.sources[self.base] = "baseline-source"
                if key == "source":
                    with patch.object(RUN, "measure", side_effect=measure), self.assertRaisesRegex(RUN.RunError, "source changed"):
                        self.capture()
                else:
                    real_inputs = inputs()
                    changed_inputs = inputs()
                    changed_inputs["go"] = "changed"
                    sequence = [real_inputs, inputs("candidate-source"), changed_inputs]
                    with patch.object(RUN, "run_inputs", side_effect=sequence), self.assertRaisesRegex(RUN.RunError, "inputs changed before"):
                        self.capture()

    def test_measure_rejects_changes_after_command(self):
        answers = ["baseline-source", "changed-source"]
        with patch.object(RUN, "checkout_state", side_effect=answers), self.assertRaisesRegex(RUN.RunError, "inputs changed while"):
            RUN.measure(self.base, "baseline-source", inputs(), self.out / "sample.txt", COMMAND)


class ShellTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.base, self.cur = self.root / "base.txt", self.root / "current.txt"
        self.base.write_text(samples())
        self.cur.write_text(samples())
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("BENCH_")}
        self.env.update(TMPDIR=str(self.root), GOTMPDIR=str(self.root), GOCACHE=str(self.root))

    def shell(self, body, *args):
        return subprocess.run(["bash", "-c", 'source "$1"\n' + body, "synthetic-test", str(SCRIPT), *map(str, args)],
                              env=self.env, capture_output=True, text=True, timeout=10, check=False)

    def compare(self, base, cur, *, pattern=".", summary=""):
        self.base.write_text(base)
        self.cur.write_text(cur)
        self.env["BENCH_PATTERN"] = pattern
        return self.shell('compare_measurements "$2" "$3" "$4" "$5"', self.base, self.cur, self.root, summary)

    def test_existing_numeric_semantics(self):
        for before, after, status in ((100, 150, 0), (100, 151, 1), (0, 0, 0), (0, 1, 1)):
            with self.subTest(before=before, after=after):
                result = self.compare(samples(ns=before), samples(ns=after))
                self.assertEqual(result.returncode, status, result.stderr)
        result = self.compare(samples(ns=100) + samples(ns=200), samples(ns=160) + samples(ns=90))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_names_full_vs_narrowed_and_no_overlap(self):
        base = samples() + samples("BenchmarkRemoved-4")
        self.assertEqual(self.compare(base, samples()).returncode, 1)
        narrowed = self.compare(base, samples(), pattern="Example")
        self.assertEqual(narrowed.returncode, 0, narrowed.stderr)
        self.assertIn("not compared", narrowed.stderr)
        result = self.compare(samples(), samples("BenchmarkOther-4"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("no benchmark names overlap", result.stderr)

    def test_summary_failure_is_display_only(self):
        summary = self.root / "synthetic-summary"
        summary.write_text("#!/bin/sh\necho display-failure >&2\nexit 1\n")
        summary.chmod(0o700)
        result = self.compare(samples(), samples(), summary=str(summary))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("summary unavailable", result.stderr)
        result = self.compare(samples(), samples(ns=160), summary=str(summary))
        self.assertEqual(result.returncode, 1)
        self.assertIn("+60.00%", result.stderr)

    def test_unexpected_comparator_error_is_not_a_pass(self):
        result = self.shell('ROOT_DIR="$4"\ncompare_measurements "$2" "$3" "$4" ""', self.base, self.cur, self.root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("failed unexpectedly", result.stderr)

    def test_missing_baseline_invalid_threshold_unknown_argument(self):
        for name, value, args, message in (("BENCH_BASELINE_DIR", "", [], "set BENCH_BASELINE_DIR"),
                                          ("BENCH_REGRESSION_THRESHOLD_PCT", "invalid", [], "non-negative"),
                                          ("BENCH_BASELINE_DIR", "", ["--unknown"], "unknown argument")):
            with self.subTest(name=name, args=args):
                self.env[name] = value
                result = self.shell('main "${@:2}"', *args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(message, result.stderr)
                self.env.pop(name)

    def test_main_stops_after_measurement_failure_without_scoring(self):
        self.env["BENCH_BASELINE_DIR"] = str(self.root / "baseline-source")
        historical = self.root / "historical.txt"
        historical.write_text("historical sentinel")
        self.env["BENCH_BASELINE"] = str(historical)
        result = self.shell('''
capture_measurements() { echo synthetic-capture-failure >&2; return 2; }
benchstat_path() { echo unexpected-summary >&2; }
compare_measurements() { echo unexpected-comparison >&2; }
status=0
main || status=$?
exit "$status"
''')
        self.assertEqual(result.returncode, 2)
        self.assertIn("synthetic-capture-failure", result.stderr)
        self.assertNotIn("unexpected", result.stderr)
        self.assertEqual(historical.read_text(), "historical sentinel")

    def test_explicit_historical_writer_stays_separate(self):
        result = self.shell('write_baseline() { echo explicit-writer; }\nmain --update-baseline')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "explicit-writer\n")


class CLITest(unittest.TestCase):
    def test_helper_errors_return_configuration_status(self):
        args = ["bench_run.py", "--baseline", "/baseline", "--candidate", "/candidate", "--output", "/output", "--", *COMMAND]
        for error in (RUN.RunError("incompatible"), FileNotFoundError("missing"), subprocess.CalledProcessError(9, COMMAND), json.JSONDecodeError("invalid", "", 0)):
            with self.subTest(error=error), patch.object(RUN.sys, "argv", args), patch.object(RUN, "capture_pair", side_effect=error), contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(RUN.main(), 2)
                self.assertIn("measurement refused", stderr.getvalue())
        with patch.object(RUN.sys, "argv", args), patch.object(RUN, "capture_pair"):
            self.assertEqual(RUN.main(), 0)
        with patch.object(RUN.sys, "argv", [*args[:-len(COMMAND)], "other-command"]), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            RUN.main()
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
