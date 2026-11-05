# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise the AST selector against actual Git revisions and Go build tags."""

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from scripts import ci_test_packages as planner


class ChangedTestsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.capture.name) / "select-tests"
        subprocess.run(["go", "build", "-o", str(cls.binary),
                        str(planner.ROOT / "scripts/ci_changed_tests.go")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.capture.cleanup()

    def test_git_selection_and_build_constraints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                # CI runners have no Git identity; fixture commits supply one.
                return subprocess.run(["git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", *args],
                                      cwd=root, check=True,
                                      text=True, capture_output=True).stdout.strip()
            def commit():
                git("add", ".")
                git("commit", "-m", "test fixture")
                return git("rev-parse", "HEAD")
            git("init", "-q")
            (root / "go.mod").write_text("module example.test/fixture\n\ngo 1.26\n")
            (root / "lib.go").write_text("package fixture\n")
            source = root / "lib_test.go"
            source.write_text('''package fixture
import "testing"
func TestUnchanged(t *testing.T) { t.Log("keep") }
func TestBody(t *testing.T) { t.Log("before") }
func TestDeleted(t *testing.T) {}
func TestOldName(t *testing.T) {}
func TestMoved(t *testing.T) {}
// func TestComment(t *testing.T) {}
func Testhelper() {}
''')
            base = commit()
            source.write_text('''package fixture
import "testing"
func TestUnchanged(t *testing.T) { t.Log("keep") }
func TestBody(t *testing.T) { t.Log("after") }
func TestRenamed(t *testing.T) {}
func TestNew(
 t *testing.T,
) { t.Log("new") }
// func TestComment(t *testing.T) { changed }
func TestMain(m *testing.M) { m.Run() }
func TestNotRunnable(value int) {}
type T = testing.T
func TestAlias(t *T) {}
func Testhelper() {}
''')
            (root / "moved_test.go").write_text(
                'package fixture\nimport "testing"\nfunc TestMoved(t *testing.T) {}\n')
            (root / "enterprise_test.go").write_text(
                '//go:build enterprise\n\npackage fixture\nimport "testing"\nfunc TestEnterprise(t *testing.T) {}\n')
            (root / "platform_windows_test.go").write_text(
                'package fixture\nimport "testing"\nfunc TestWindows(t *testing.T) {}\n')
            (root / "race_test.go").write_text(
                '//go:build race\n\npackage fixture\nimport "testing"\nfunc TestRace(t *testing.T) {}\n')
            (root / "testdata").mkdir()
            (root / "testdata" / "fixture_test.go").write_text("intentionally invalid fixture")
            (root / "_ignored_test.go").write_text("intentionally invalid fixture")
            head = commit()
            result = subprocess.run([str(self.binary), "--base", base, "--head", head],
                                    cwd=root, check=True, capture_output=True, text=True)
            tests = json.loads(result.stdout)
            self.assertEqual({test["name"] for test in tests},
                             {"TestAlias", "TestBody", "TestRenamed", "TestNew", "TestEnterprise", "TestWindows", "TestRace", "TestMoved"})
            # A body edit or a move to another file of the same package is not new.
            self.assertEqual({test["name"] for test in tests if not test["new"]}, {"TestBody", "TestMoved"})
            with patch.object(planner, "ROOT", root):
                oss = planner.runnable_changed_tests(tests, "")
                enterprise = planner.runnable_changed_tests(tests, "enterprise")
            self.assertEqual(oss, {"example.test/fixture": ["TestAlias", "TestBody", "TestMoved", "TestNew", "TestRace", "TestRenamed"]})
            self.assertEqual(enterprise, {"example.test/fixture": ["TestAlias", "TestBody", "TestEnterprise", "TestMoved", "TestNew", "TestRace", "TestRenamed"]})
            unchanged = subprocess.run([str(self.binary), "--base", head, "--head", head],
                                      cwd=root, check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(unchanged.stdout), [])
            invalid = subprocess.run([str(self.binary), "--base", "missing-ref", "--head", head],
                                    cwd=root, capture_output=True, text=True)
            self.assertNotEqual(invalid.returncode, 0)
            source.write_text("package fixture\nfunc TestBroken( {\n")
            broken = commit()
            result = subprocess.run([str(self.binary), "--base", head, "--head", broken],
                                    cwd=root, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("parse", result.stderr)

    def test_race_measurement_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                # CI runners have no Git identity; fixture commits supply one.
                return subprocess.run(["git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", *args],
                                      cwd=root, check=True,
                                      text=True, capture_output=True).stdout.strip()
            git("init", "-q")
            (root / "go.mod").write_text("module example.test/fixture\n\ngo 1.26\n")
            (root / "lib.go").write_text("package fixture\n")
            git("add", ".")
            git("commit", "-m", "fixture base")
            (root / "lib_test.go").write_text(
                'package fixture\nimport "testing"\nfunc TestNew(t *testing.T) { t.Log("selected") }\n')
            (root / "enterprise_test.go").write_text(
                '//go:build enterprise\n\npackage fixture\nimport "testing"\nfunc TestEnterprise(t *testing.T) {}\n')
            git("add", ".")
            git("commit", "-m", "fixture tests")
            result = subprocess.run([str(self.binary), "--base", "HEAD~1", "--head", "HEAD"],
                                    cwd=root, check=True, capture_output=True, text=True)
            tests = json.loads(result.stdout)
            with patch.object(planner, "ROOT", root), redirect_stdout(io.StringIO()):
                for tags in ("", "enterprise"):
                    stream = root / (tags or "oss") / "changed.json"
                    self.assertEqual(planner.measure_changed_tests(tests, tags, stream), 0)
                    events = [json.loads(line) for line in stream.read_text().splitlines()]
                    passed = {event["Test"] for event in events if event.get("Test") and event["Action"] == "pass"}
                    self.assertEqual(passed, {"TestNew", "TestEnterprise"} if tags else {"TestNew"})
                    selection = json.loads(stream.with_suffix(".selection.json").read_text())
                    self.assertEqual(selection["new"], {"example.test/fixture": sorted(passed)})



class ChangedTestRunnerTest(unittest.TestCase):
    def test_no_tests_is_fast_success(self):
        with patch.object(planner, "runnable_changed_tests") as resolve, \
             patch.object(planner, "check_budget") as budget, redirect_stdout(io.StringIO()):
            self.assertEqual(planner.measure_changed_tests([], "", Path("unused.json")), 0)
            resolve.assert_not_called()
            budget.assert_not_called()

    def test_runner_measurements_reach_budget_and_refresh_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "changed.json"
            package = "example.test/internal/proxy"
            def run(command, **kwargs):
                for event in ({"Action": "run", "Test": "TestNew"},
                              {"Action": "pass", "Test": "TestNew", "Elapsed": 700},
                              {"Action": "pass", "Elapsed": 701}):
                    kwargs["stdout"].write(json.dumps({"Package": package, **event}) + "\n")
                return subprocess.CompletedProcess(command, 0)
            with patch.object(planner, "runnable_changed_tests", return_value={package: ["TestNew"]}), \
                 patch.object(planner.subprocess, "run", side_effect=run), \
                 patch.object(planner, "check_budget", return_value=1) as budget, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as error:
                self.assertEqual(planner.measure_changed_tests([{}], "", target), 1)
                self.assertEqual(budget.call_args.args[2]["trees"]["proxy"]["TestNew"], 700)
                self.assertIn("TestNew", error.getvalue())
                self.assertIn("scripts/ci_test_durations.py --partial --write", error.getvalue())
                self.assertIn(str(target), error.getvalue())

    def test_runner_flags_and_missing_results(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "changed.json"
            commands = []
            def run(command, **kwargs):
                commands.append(command)
                kwargs["stdout"].write(json.dumps({"Package": "example.test/internal/proxy",
                    "Action": "pass", "Elapsed": 1}) + "\n")
                return subprocess.CompletedProcess(command, 0)
            with patch.object(planner, "runnable_changed_tests", return_value={"example.test/internal/proxy": ["TestNew"]}), \
                 patch.object(planner.subprocess, "run", side_effect=run), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "no terminal result"):
                    planner.measure_changed_tests([{}], "enterprise", target)
            command = commands[0]
            for flag in ("-race", "-parallel=2", "-count=1", "-json", "-timeout=15m", "-covermode=atomic"):
                self.assertIn(flag, command)
            self.assertEqual(command[command.index("-tags") + 1], "enterprise")
            self.assertTrue(planner.selector_selects(next(arg for arg in command if arg.startswith("-run=")), "TestNew"))
            self.assertFalse(planner.selector_selects(next(arg for arg in command if arg.startswith("-run=")), "TestNewSuffix"))


if __name__ == "__main__":
    unittest.main()
