# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise the AST selector against actual Git revisions and Go build tags."""

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import nullcontext, redirect_stdout, redirect_stderr
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
            (root / "lib_test.go").write_text(
                'package fixture\nimport "testing"\nfunc TestEdited(t *testing.T) { t.Log("before") }\n')
            git("add", ".")
            git("commit", "-m", "fixture base")
            (root / "lib_test.go").write_text(
                'package fixture\nimport "testing"\nfunc TestEdited(t *testing.T) { t.Log("after") }\n'
                'func TestNew(t *testing.T) { t.Log("selected") }\n')
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
                    self.assertEqual(planner.measure_changed_tests(tests, tags, stream, "HEAD~1"), 0)
                    events = [json.loads(line) for line in stream.read_text().splitlines()]
                    passed = {event["Test"] for event in events if event.get("Test") and event["Action"] == "pass"}
                    self.assertEqual(passed, {"TestEdited", "TestNew", "TestEnterprise"} if tags else {"TestEdited", "TestNew"})
                    selection = json.loads(stream.with_suffix(".selection.json").read_text())
                    self.assertEqual(selection["new"], {"example.test/fixture": sorted(passed - {"TestEdited"})})
                    base_events = [json.loads(line) for line in stream.with_suffix(".base.json").read_text().splitlines()]
                    self.assertEqual({event["Test"] for event in base_events
                                      if event.get("Test") and event["Action"] == "pass"}, {"TestEdited"})
                    # A rest package (outside the split trees) runs whole.
                    self.assertEqual(selection["whole"], ["example.test/fixture"])



class ChangedTestRunnerTest(unittest.TestCase):
    package = "example.test/internal/proxy"

    def fixture_tests(self, new=False):
        return [{"package": "./internal/proxy", "file": "internal/proxy/lib_test.go",
                 "name": "TestChanged", "new": new}]

    def resolve(self, tests, tags, import_paths):
        import_paths.update({test["package"]: self.package for test in tests})
        return {self.package: [test["name"] for test in tests]}

    def scripted_run(self, commands, events=None, status=0):
        def run(command, stream, root, remaining):
            commands.append((command, root, remaining))
            output = events if events is not None else [
                {"Action": "run", "Test": "TestChanged"},
                {"Action": "pass", "Test": "TestChanged", "Elapsed": 1},
                {"Action": "pass", "Elapsed": 2},
            ]
            for event in output:
                stream.write(json.dumps({"Package": command[-1], **event}) + "\n")
            return status
        return run

    def test_base_worktree_cleanup_removes_untracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args, check=True):
                return subprocess.run(["git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", *args],
                                      cwd=root, check=check, text=True, capture_output=True)
            git("init", "-q")
            git("commit", "-q", "--allow-empty", "-m", "base")
            revision = git("rev-parse", "HEAD").stdout.strip()
            with patch.object(planner, "ROOT", root):
                with planner.measurement_base(revision) as base:
                    (base / "untracked.txt").write_text("dirt", encoding="utf-8")
                listed = git("worktree", "list", "--porcelain").stdout
                self.assertNotIn(str(base), listed)
                with self.assertRaisesRegex(ValueError, "boom"):
                    with planner.measurement_base(revision) as base:
                        (base / "untracked.txt").write_text("dirt", encoding="utf-8")
                        raise ValueError("boom")
                listed = git("worktree", "list", "--porcelain").stdout
                self.assertNotIn("untracked.txt", listed)
                self.assertEqual(listed.count("worktree "), 1)

    def test_empty_selection_still_resolves_base(self):
        with patch.object(planner, "measurement_base", return_value=nullcontext(Path("base"))) as base, \
             patch.object(planner, "runnable_changed_tests") as resolve, redirect_stdout(io.StringIO()):
            self.assertEqual(planner.measure_changed_tests([], "", Path("unused.json"), "base-sha"), 0)
            base.assert_called_once_with("base-sha")
            resolve.assert_not_called()

    def test_unresolved_base_is_not_empty_selection(self):
        with patch.object(planner.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "git")):
            with self.assertRaises(subprocess.CalledProcessError):
                planner.measure_changed_tests([], "", Path("unused.json"), "missing-ref")

    def test_unknown_classifier_fails(self):
        for test in ({}, {**self.fixture_tests()[0], "new": "false"}):
            with self.subTest(test=test), \
                 patch.object(planner, "measurement_base", return_value=nullcontext(Path("base"))):
                with self.assertRaisesRegex(ValueError, "unknown changed-test classification"):
                    planner.measure_changed_tests([test], "", Path("unused.json"), "base-sha")

    def test_unknown_go_list_result_is_not_empty_selection(self):
        for info in ([], {}, {"ImportPath": self.package},
                     {"ImportPath": self.package, "TestGoFiles": ["other_test.go"]}):
            with self.subTest(info=info), patch.object(planner.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, stdout=json.dumps(info))):
                with self.assertRaises(ValueError):
                    planner.runnable_changed_tests(self.fixture_tests(), "")

    def test_file_excluded_by_this_build_is_left_to_the_other_edition(self):
        # An enterprise-only test file in a package that also builds without
        # tags is go list's IgnoredGoFiles in the OSS run, not unclassified.
        excluded = {**self.fixture_tests()[0], "file": "internal/proxy/lib_enterprise_test.go", "name": "TestEnterprise"}
        cases = (
            ([excluded], {}),
            ([self.fixture_tests()[0], excluded], {self.package: ["TestChanged"]}),
        )
        for tests, want in cases:
            info = {"ImportPath": self.package, "TestGoFiles": ["lib_test.go"],
                    "IgnoredGoFiles": ["lib_enterprise_test.go"]}
            with self.subTest(tests=[test["name"] for test in tests]), \
                 patch.object(planner.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, stdout=json.dumps(info))):
                self.assertEqual(planner.runnable_changed_tests(tests, ""), want)

    def test_existing_changed_test_requires_base_package(self):
        with patch.object(planner, "measurement_base", return_value=nullcontext(Path("base"))), \
             patch.object(planner, "runnable_changed_tests", side_effect=self.resolve), \
             patch.object(planner, "list_packages", return_value=[]):
            with self.assertRaisesRegex(ValueError, "no base package"):
                planner.measure_changed_tests(self.fixture_tests(), "", Path("unused.json"), "base-sha")

    def test_paired_invocation_and_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "changed.json"
            commands = []
            with patch.object(planner, "measurement_base", return_value=nullcontext(Path("base"))), \
                 patch.object(planner, "runnable_changed_tests", side_effect=self.resolve), \
                 patch.object(planner, "list_packages", return_value=[self.package]), \
                 patch.object(planner, "run_measurement", side_effect=self.scripted_run(commands)), \
                 patch.object(planner, "check_budget", return_value=0) as budget, redirect_stdout(io.StringIO()):
                self.assertEqual(planner.measure_changed_tests(self.fixture_tests(), "enterprise", target, "base-sha"), 0)
            self.assertEqual(len(commands), 2)
            self.assertEqual(commands[0][0], commands[1][0])
            self.assertEqual([root for _, root, _ in commands], [Path("base"), planner.ROOT])
            command = commands[0][0]
            for flag in ("-race", "-p=1", "-parallel=2", "-count=1", "-json", "-timeout=900s"):
                self.assertIn(flag, command)
            self.assertFalse(any(arg.startswith("-cover") for arg in command))
            self.assertEqual(command[command.index("-tags") + 1], "enterprise")
            self.assertEqual(budget.call_args.args[2], budget.call_args.args[3])
            self.assertEqual(budget.call_args.args[2]["trees"]["proxy"]["TestChanged"], 1)
            self.assertEqual(budget.call_args.kwargs["introduced"], {"trees": {}, "packages": []})

    def test_new_test_has_zero_base_and_full_head_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "changed.json"
            commands = []
            with patch.object(planner, "measurement_base", return_value=nullcontext(Path("base"))), \
                 patch.object(planner, "runnable_changed_tests", side_effect=self.resolve), \
                 patch.object(planner, "list_packages", return_value=[self.package]), \
                 patch.object(planner, "run_measurement", side_effect=self.scripted_run(commands)), \
                 patch.object(planner, "check_budget", return_value=1) as budget, redirect_stdout(io.StringIO()):
                self.assertEqual(planner.measure_changed_tests(self.fixture_tests(new=True), "", target, "base-sha"), 1)
            self.assertEqual(len(commands), 1)
            self.assertEqual(budget.call_args.args[2]["trees"]["proxy"]["TestChanged"], 1)
            self.assertEqual(budget.call_args.args[3]["trees"]["proxy"]["TestChanged"], 0)
            self.assertEqual(budget.call_args.kwargs["introduced"],
                             {"trees": {"proxy": ["TestChanged"]}, "packages": []})

    def test_rest_packages_measure_whole_on_both_sides(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "changed.json"
            commands = []
            package = "example.test/internal/rest"
            tests = [{"package": "./internal/rest", "file": "internal/rest/lib_test.go",
                      "name": "TestChanged", "new": True}]
            with patch.object(self, "package", package), \
                 patch.object(planner, "measurement_base", return_value=nullcontext(Path("base"))), \
                 patch.object(planner, "runnable_changed_tests", side_effect=self.resolve), \
                 patch.object(planner, "list_packages", return_value=[package]), \
                 patch.object(planner, "run_measurement", side_effect=self.scripted_run(commands)), \
                 patch.object(planner, "check_budget", return_value=0) as budget, redirect_stdout(io.StringIO()):
                self.assertEqual(planner.measure_changed_tests(tests, "", target, "base-sha"), 0)
            self.assertEqual(len(commands), 2)
            self.assertFalse(any(arg.startswith("-run=") for command, _, _ in commands for arg in command))
            self.assertEqual(budget.call_args.args[2]["packages"], {package: 2})
            self.assertEqual(budget.call_args.args[3]["packages"], {package: 2})
            # The package exists on the base, so its new test is inside the
            # paired whole-package total rather than a zero-base charge.
            self.assertEqual(budget.call_args.kwargs["introduced"], {"trees": {}, "packages": []})

    def test_missing_skipped_failed_or_invalid_terminal_events_fail_closed(self):
        cases = [
            [{"Action": "pass", "Elapsed": 1}],
            [{"Action": "pass", "Test": "TestChanged", "Elapsed": 1}],
            [{"Action": "run", "Test": "TestChanged"}, {"Action": "pass", "Elapsed": 1}],
            [{"Action": "skip", "Test": "TestChanged"}, {"Action": "pass", "Elapsed": 1}],
            [{"Action": "fail", "Test": "TestChanged", "Elapsed": 1}],
            [{"Action": "pass", "Test": "TestChanged", "Elapsed": float("nan")}],
            [{"Action": "pass", "Test": "TestChanged", "Elapsed": -1}],
        ]
        for events in cases:
            with self.subTest(events=events), tempfile.TemporaryDirectory() as directory, \
                 patch.object(planner, "run_measurement", side_effect=self.scripted_run([], events)), \
                 redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):
                    planner.measured_selection({self.package: ["TestChanged"]}, [], "", Path(directory) / "run.json",
                                               planner.ROOT, lambda: planner.MEASURE_DEADLINE_SECONDS)

    def test_build_output_and_subtest_skips_are_not_failures(self):
        # A successful build's toolchain output is a build event keyed by
        # ImportPath (go help buildjson), and a selected test may skip some
        # subtests; neither is a missing or skipped measurement.
        events = [
            {"Action": "run", "Test": "TestChanged"},
            {"Action": "run", "Test": "TestChanged/linux"},
            {"Action": "skip", "Test": "TestChanged/windows", "Elapsed": 0},
            {"Action": "pass", "Test": "TestChanged/linux", "Elapsed": 1},
            {"Action": "pass", "Test": "TestChanged", "Elapsed": 1},
            {"Action": "pass", "Elapsed": 2},
        ]
        def run(command, stream, root, remaining):
            stream.write(json.dumps({"ImportPath": command[-1], "Action": "build-output", "Output": "warning\n"}) + "\n")
            for event in events:
                stream.write(json.dumps({"Package": command[-1], **event}) + "\n")
            return 0
        with tempfile.TemporaryDirectory() as directory, patch.object(planner, "run_measurement", side_effect=run), \
             redirect_stdout(io.StringIO()):
            overrides = planner.measured_selection({self.package: ["TestChanged"]}, [], "", Path(directory) / "run.json",
                                                   planner.ROOT, lambda: planner.MEASURE_DEADLINE_SECONDS)
        self.assertEqual(overrides["trees"]["proxy"]["TestChanged"], 1)
        # A build failure still has no Package and is not a successful result.
        def failed(command, stream, root, remaining):
            stream.write(json.dumps({"ImportPath": command[-1], "Action": "build-fail"}) + "\n")
            return 0
        with tempfile.TemporaryDirectory() as directory, patch.object(planner, "run_measurement", side_effect=failed), \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "unexpected measurement event"):
                planner.measured_selection({self.package: ["TestChanged"]}, [], "", Path(directory) / "run.json",
                                           planner.ROOT, lambda: planner.MEASURE_DEADLINE_SECONDS)

    def test_base_package_discovery_is_inside_the_deadline(self):
        with patch.object(planner.subprocess, "run", side_effect=subprocess.TimeoutExpired("go list", 1)) as run:
            with self.assertRaisesRegex(ValueError, "measurement timeout: package discovery"):
                planner.list_packages("race", root=Path("base"), tests_only=True, timeout=1)
        self.assertEqual(run.call_args.kwargs["timeout"], 1)

    def test_base_package_discovery_receives_remaining_pair_deadline(self):
        for elapsed in (2, 30):
            with self.subTest(elapsed=elapsed), \
                 patch.object(planner, "measurement_base", return_value=nullcontext(Path("base"))), \
                 patch.object(planner, "runnable_changed_tests", side_effect=self.resolve), \
                 patch.object(planner, "prediction_plan", return_value={}), \
                 patch.object(planner, "list_packages", side_effect=ValueError("discovery timeout")) as discovery, \
                 patch.object(planner, "run_measurement") as run:
                # The first read checks expiry; the next read supplies the
                # subprocess timeout. Both share the pair's start time.
                ticks = iter([10, 10 + elapsed, 10 + elapsed + 1])
                message = "discovery timeout" if elapsed < 30 else "deadline reached before base package discovery"
                with self.assertRaisesRegex(ValueError, message):
                    planner.measure_changed_tests(self.fixture_tests(), "enterprise", Path("unused.json"), "base-sha",
                                                  deadline_seconds=30, clock=lambda: next(ticks))
                if elapsed < 30:
                    discovery.assert_called_once_with("race,enterprise", root=Path("base"),
                                                      tests_only=True, timeout=27)
                else:
                    discovery.assert_not_called()
                run.assert_not_called()

    def test_deadline_refuses_edited_and_new_tests(self):
        for new in (False, True):
            with self.subTest(new=new), tempfile.TemporaryDirectory() as directory, \
                 patch.object(planner, "measurement_base", return_value=nullcontext(Path("base"))), \
                 patch.object(planner, "runnable_changed_tests", side_effect=self.resolve), \
                 patch.object(planner, "list_packages", return_value=[self.package]), \
                 patch.object(planner, "run_measurement") as run:
                ticks = iter([0, planner.MEASURE_DEADLINE_SECONDS])
                with self.assertRaisesRegex(ValueError, "measurement deadline"):
                    planner.measure_changed_tests(self.fixture_tests(new=new), "", Path(directory) / "run.json", "base-sha",
                                                  clock=lambda: next(ticks, planner.MEASURE_DEADLINE_SECONDS))
                run.assert_not_called()

    def test_process_failure_and_timeout_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(planner, "run_measurement", side_effect=self.scripted_run([], status=1)), \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "race run failed"):
                planner.measured_selection({self.package: ["TestChanged"]}, [], "", Path(directory) / "run.json",
                                           planner.ROOT, lambda: planner.MEASURE_DEADLINE_SECONDS)
        with patch.object(planner.subprocess, "Popen") as popen, patch.object(planner.os, "killpg") as kill:
            process = popen.return_value.__enter__.return_value
            process.wait.side_effect = [subprocess.TimeoutExpired("go test", 1), 0]
            with self.assertRaisesRegex(ValueError, "measurement timeout"):
                planner.run_measurement(["go", "test"], io.StringIO(), planner.ROOT, 1)
            kill.assert_called_once_with(process.pid, planner.signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
