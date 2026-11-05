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
            (root / "plat_windows_test.go").write_text(
                'package fixture\nimport "testing"\nfunc TestPlatform(t *testing.T) {}\n')
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
            # Linux builds never saw the Windows-only TestPlatform, so it is new here.
            (root / "plat_linux_test.go").write_text(
                'package fixture\nimport "testing"\nfunc TestPlatform(t *testing.T) { t.Log("linux") }\n')
            (root / "race_test.go").write_text(
                '//go:build race\n\npackage fixture\nimport "testing"\nfunc TestRace(t *testing.T) {}\n')
            (root / "testdata").mkdir()
            (root / "testdata" / "fixture_test.go").write_text("intentionally invalid fixture")
            (root / "_ignored_test.go").write_text("intentionally invalid fixture")
            head = commit()
            def select(tags):
                result = subprocess.run([str(self.binary), "--tags", tags, "--base", base, "--head", head],
                                        cwd=root, check=True, capture_output=True, text=True)
                return json.loads(result.stdout)
            common = {"TestAlias", "TestBody", "TestRenamed", "TestNew", "TestRace", "TestMoved", "TestPlatform"}
            oss_tests, enterprise_tests = select(""), select("enterprise")
            # Each variant sees only files it builds: no Windows file on Linux,
            # and the enterprise-tagged file only under -tags enterprise.
            self.assertEqual({test["name"] for test in oss_tests}, common)
            self.assertEqual({test["name"] for test in enterprise_tests}, common | {"TestEnterprise"})
            # A body edit or a move to another file of the same package is not new;
            # a name only another platform's base file declared is.
            self.assertEqual({test["name"] for test in oss_tests if not test["new"]}, {"TestBody", "TestMoved"})
            tests = enterprise_tests
            with patch.object(planner, "ROOT", root):
                oss = planner.runnable_changed_tests(oss_tests, "")
                enterprise = planner.runnable_changed_tests(tests, "enterprise")
            self.assertEqual(oss, {"example.test/fixture": ["TestAlias", "TestBody", "TestMoved", "TestNew", "TestPlatform", "TestRace", "TestRenamed"]})
            self.assertEqual(enterprise, {"example.test/fixture": ["TestAlias", "TestBody", "TestEnterprise", "TestMoved", "TestNew", "TestPlatform", "TestRace", "TestRenamed"]})
            unchanged = subprocess.run([str(self.binary), "--tags", "", "--base", head, "--head", head],
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
            with patch.object(planner, "ROOT", root), redirect_stdout(io.StringIO()):
                for tags in ("", "enterprise"):
                    result = subprocess.run([str(self.binary), "--tags", tags, "--base", "HEAD~1", "--head", "HEAD"],
                                            cwd=root, check=True, capture_output=True, text=True)
                    tests = json.loads(result.stdout)
                    stream = root / (tags or "oss") / "changed.json"
                    self.assertEqual(planner.measure_changed_tests(tests, tags, stream), 0)
                    events = [json.loads(line) for line in stream.read_text().splitlines()]
                    passed = {event["Test"] for event in events if event.get("Test") and event["Action"] == "pass"}
                    self.assertEqual(passed, {"TestNew", "TestEnterprise"} if tags else {"TestNew"})
                    selection = json.loads(stream.with_suffix(".selection.json").read_text())
                    self.assertEqual(selection["new"], {"example.test/fixture": sorted(passed)})
                    # A rest package (outside the split trees) runs whole.
                    self.assertEqual(selection["whole"], ["example.test/fixture"])



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
            for flag in ("-race", "-parallel=2", "-count=1", "-json", "-timeout=900s", "-covermode=atomic"):
                self.assertIn(flag, command)
            self.assertEqual(command[command.index("-tags") + 1], "enterprise")
            self.assertTrue(planner.selector_selects(next(arg for arg in command if arg.startswith("-run=")), "TestNew"))
            self.assertFalse(planner.selector_selects(next(arg for arg in command if arg.startswith("-run=")), "TestNewSuffix"))

    def scripted_run(self, commands, elapsed=1):
        def run(command, **kwargs):
            commands.append(command)
            package = command[-1]
            selector = next((arg for arg in command if arg.startswith("-run=")), None)
            for name in ("TestNew", "TestEdited"):
                if selector is None or planner.selector_selects(selector, name):
                    for event in ({"Action": "run", "Test": name},
                                  {"Action": "pass", "Test": name, "Elapsed": elapsed}):
                        kwargs["stdout"].write(json.dumps({"Package": package, **event}) + "\n")
            kwargs["stdout"].write(json.dumps({"Package": package, "Action": "pass", "Elapsed": elapsed + 1}) + "\n")
            return subprocess.CompletedProcess(command, 0)
        return run

    def test_rest_packages_run_whole_and_new_tests_go_first(self):
        tree, rest = "example.test/internal/proxy", "example.test/internal/rest"
        selected = {rest: ["TestEdited"], tree: ["TestNew"]}
        tests = [{"package": "./internal/proxy", "name": "TestNew", "new": True},
                 {"package": "./internal/rest", "name": "TestEdited", "new": False}]
        def resolve(tests, tags, import_paths):
            import_paths.update({"./internal/proxy": tree, "./internal/rest": rest})
            return selected
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "changed.json"
            commands = []
            with patch.object(planner, "runnable_changed_tests", side_effect=resolve), \
                 patch.object(planner.subprocess, "run", side_effect=self.scripted_run(commands)), \
                 patch.object(planner, "check_budget", return_value=0) as budget, redirect_stdout(io.StringIO()):
                self.assertEqual(planner.measure_changed_tests(tests, "", target), 0)
            self.assertEqual([command[-1] for command in commands], [tree, rest])
            self.assertTrue(any(arg.startswith("-run=") for arg in commands[0]))
            self.assertFalse(any(arg.startswith("-run=") for arg in commands[1]))
            overrides = budget.call_args.args[2]
            self.assertEqual(overrides["packages"], {rest: 2})
            selection = json.loads(target.with_suffix(".selection.json").read_text())
            self.assertEqual((selection["whole"], selection["skipped"]), ([rest], []))

    def test_deadline_skips_edited_packages_and_refuses_unmeasured_new_tests(self):
        first, second = "example.test/internal/alpha", "example.test/internal/beta"
        def clock_after(*readings):
            values = iter(readings)
            return lambda: next(values)
        for second_is_new, want in ((False, 0), (True, 1)):
            tests = [{"package": "./a", "name": "TestNew", "new": True},
                     {"package": "./b", "name": "TestEdited", "new": second_is_new}]
            def resolve(tests, tags, import_paths):
                import_paths.update({"./a": first, "./b": second})
                return {first: ["TestNew"], second: ["TestEdited"]}
            with self.subTest(second_is_new=second_is_new), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "changed.json"
                commands = []
                # Start, then before alpha (300s left), then before beta (30s left).
                clock = clock_after(0, 100, 370)
                with patch.object(planner, "runnable_changed_tests", side_effect=resolve), \
                     patch.object(planner.subprocess, "run", side_effect=self.scripted_run(commands)), \
                     patch.object(planner, "check_budget", return_value=0), \
                     redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(planner.measure_changed_tests(tests, "", target, 400, clock), want)
                self.assertEqual([command[-1] for command in commands], [first])
                # The package that started got only the time left as its timeout.
                self.assertIn("-timeout=300s", commands[0])
                if want:
                    self.assertIn("TestEdited", error.getvalue())
                else:
                    self.assertIn("kept its recorded weight", out.getvalue())


if __name__ == "__main__":
    unittest.main()
