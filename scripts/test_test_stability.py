#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
"""Exercise discovery and search failures through the real stability gate."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("check-test-stability.sh")
CI_WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yaml"
ANALYZER = pathlib.Path(__file__).with_name("teststability") / "main.go"

SLEEP = "package example\nfunc f() { time.Sleep(1) }\n"

RETRY_FATAL = """package example

func TestReload(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		select {
		case err := <-errCh:
			t.Fatalf("run exited: %v", err)
		case <-ready:
		}
		return nil
	})
}
"""


@unittest.skipUnless(shutil.which("go"), "go toolchain not on PATH")
class StabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        (self.root / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.root / "scripts/check-test-stability.sh")
        self.git("init", "-q")
        self.add_analyzer()

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.root, env=self.env, check=True, capture_output=True, timeout=10
        )

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def run_gate(self, timeout=300):
        return subprocess.run(
            ["bash", "scripts/check-test-stability.sh"],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=timeout,
        )

    def add_analyzer(self):
        self.write("go.mod", "module example\n\ngo 1.26\n")
        for source in sorted(ANALYZER.parent.glob("*.go")):
            if not source.name.endswith("_test.go"):
                self.write(f"scripts/teststability/{source.name}", source.read_text(encoding="utf-8"))

    def test_clean_new_root_and_root_level_file(self):
        self.write("new component/clean_test.go", "package example\n")
        self.write("root_test.go", "package example\n")
        self.assertEqual(self.run_gate().returncode, 0)

    def test_discovery_without_mapfile(self):
        self.write("shell-env", "if type -t mapfile >/dev/null; then enable -n mapfile; fi\n")
        self.env["BASH_ENV"] = str(self.root / "shell-env")
        self.write("new component/clean_test.go", "package example\n")
        self.assertEqual(self.run_gate().returncode, 0)
        self.write("new component/clean_test.go", SLEEP)
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("new component/clean_test.go:2:", result.stderr)

    def test_sleep_in_each_previously_omitted_root(self):
        for root in ("scripts", "configs", "future component"):
            with self.subTest(root=root):
                name = f"{root}/sample_test.go"
                self.write(name, "package example\nfunc test() { time.Sleep(1) }\n")
                result = self.run_gate()
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"{name}:2:", result.stderr)
                (self.root / name).unlink()

    def test_fixed_port_in_new_root(self):
        self.write("future/port_test.go", 'package example\nfunc f() { net.Listen("tcp", "127.0.0.1:9999") }\n')
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("fixed local ports", result.stderr)

    def test_ignored_files_are_excluded_but_tracked_files_are_not(self):
        self.write(".gitignore", "ignored/\n")
        self.write("ignored/bad_test.go", SLEEP)
        self.write("internal/clean_test.go", "package example\n")
        self.assertEqual(self.run_gate().returncode, 0)
        self.git("add", "-f", "ignored/bad_test.go")
        self.assertEqual(self.run_gate().returncode, 1)

    def test_allowlist_keeps_filename_for_single_file(self):
        self.write("internal/allowed_test.go", SLEEP)
        self.write("scripts/test-stability-allowlist.txt", "internal/allowed_test.go:2:func f() { time.Sleep(1) }\n")
        self.assertEqual(self.run_gate().returncode, 0)

    def test_missing_tracked_file_is_search_error(self):
        self.write("internal/missing_test.go", "package example\n")
        self.git("add", "internal/missing_test.go")
        (self.root / "internal/missing_test.go").unlink()
        result = self.run_gate()
        self.assertGreater(result.returncode, 1)
        self.assertIn("search exited", result.stderr)

    def test_empty_inventory_is_error(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("no Go tests found", result.stderr)

    def test_grep_fallback(self):
        tools = self.root / "bin"
        tools.mkdir()
        for tool in ("bash", "git", "dirname", "mktemp", "rm", "cat", "grep", "go"):
            (tools / tool).symlink_to(shutil.which(tool))
        self.env["PATH"] = str(tools)
        self.write("new component/clean_test.go", "package example\n")
        self.assertEqual(self.run_gate().returncode, 0)
        self.write("new component/clean_test.go", SLEEP)
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("new component/clean_test.go:2:", result.stderr)

    def test_retry_callback_that_cannot_retry(self):
        self.write("internal/reload_test.go", RETRY_FATAL)
        result = self.run_gate(timeout=300)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("internal/reload_test.go:7:", result.stderr)
        self.assertIn("testport.WithRetry callbacks must return run errors", result.stderr)

        fixed = RETRY_FATAL.replace('t.Fatalf("run exited: %v", err)', "return err")
        self.write("internal/reload_test.go", fixed)
        result = self.run_gate(timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_retry_finding_allowlist(self):
        self.write("internal/reload_test.go", RETRY_FATAL)
        self.write(
            "scripts/test-stability-allowlist.txt",
            'internal/reload_test.go:7:\t\t\tt.Fatalf("run exited: %v", err)\n',
        )
        result = self.run_gate(timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_retry_analyzer_parse_error_is_error(self):
        self.write("internal/broken_test.go", "package example\nfunc (\n")
        result = self.run_gate(timeout=300)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("port retry analyzer exited with 2", result.stderr)

    def test_retry_analyzer_without_go_is_error(self):
        tools = self.root / "bin"
        tools.mkdir()
        for tool in ("bash", "git", "dirname", "mktemp", "rm", "cat", "grep"):
            (tools / tool).symlink_to(shutil.which(tool))
        self.env["PATH"] = str(tools)
        self.write("internal/clean_test.go", "package example\n")
        result = self.run_gate()
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertIn("go is not on PATH", result.stderr)

    def test_discovery_failure_is_error(self):
        shutil.rmtree(self.root / ".git")
        result = self.run_gate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot discover", result.stderr)

    def test_missing_analyzer_fails_closed_and_restoring_it_passes(self):
        analyzer = self.root / "scripts/teststability"
        saved = self.root / "saved-teststability"
        self.write("internal/clean_test.go", "package example\n")
        self.assertEqual(self.run_gate().returncode, 0)

        shutil.move(analyzer, saved)
        result = self.run_gate()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("port retry analyzer (scripts/teststability) is missing", result.stderr)

        shutil.move(saved, analyzer)
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_analyzer_does_not_hide_a_retry_violation(self):
        self.write("internal/reload_test.go", RETRY_FATAL)
        shutil.rmtree(self.root / "scripts/teststability")
        result = self.run_gate()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("is missing", result.stderr)


class StabilityWiringTests(unittest.TestCase):
    def test_ci_runs_the_gate_as_a_blocking_step(self):
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        marker = "      - name: Test stability policy\n"
        self.assertEqual(workflow.count(marker), 1)
        start = workflow.index(marker) + len(marker)
        end = workflow.find("\n      - ", start)
        step = workflow[start : end if end != -1 else len(workflow)]
        self.assertIn("run: bash scripts/check-test-stability.sh", step)
        self.assertNotIn("continue-on-error", step)
        self.assertNotIn("||", step)

    def test_analyzer_ships_with_the_gate(self):
        self.assertTrue(ANALYZER.is_file(), ANALYZER)


if __name__ == "__main__":
    unittest.main()
