# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise the pull-request repeat gate against real Git revisions and go test."""

import io
import json
import math
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts import ci_test_packages as planner

FIXTURE_MODULE = "example.test/fixture"


class FixtureRepo:
    """A throwaway Go module under Git with a base and a head commit."""

    def __init__(self, root: Path):
        self.root = root
        self.git("init", "-q")
        (root / "go.mod").write_text(f"module {FIXTURE_MODULE}\n\ngo 1.26\n")
        (root / "lib.go").write_text("package fixture\n")

    def git(self, *args):
        # CI runners have no Git identity; fixture commits supply one.
        return subprocess.run(["git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", *args],
                              cwd=self.root, check=True, text=True, capture_output=True).stdout.strip()

    def commit(self, files: dict[str, str]) -> str:
        for name, text in files.items():
            (self.root / name).write_text(text)
        self.git("add", ".")
        self.git("commit", "-q", "--allow-empty", "-m", "fixture")
        return self.git("rev-parse", "HEAD")


class SupportSelectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.capture.name) / "select-tests"
        subprocess.run(["go", "build", "-o", str(cls.binary),
                        str(planner.ROOT / "scripts/ci_changed_tests.go")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.capture.cleanup()

    def select(self, repo: FixtureRepo, base: str, head: str, support: bool) -> set[str]:
        command = [str(self.binary), "--base", base, "--head", head]
        if support:
            command.append("--include-support")
        result = subprocess.run(command, cwd=repo.root, check=True, capture_output=True, text=True)
        return {test["name"] for test in json.loads(result.stdout)}

    def test_changed_helper_selects_the_tests_that_reach_it(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            helpers = '''package fixture
func leaf() int { return 1 }
func middle() int { return leaf() }
func unrelated() int { return 2 }
'''
            base = repo.commit({
                "helpers_test.go": helpers,
                "a_test.go": '''package fixture
import "testing"
func TestDirect(t *testing.T) { _ = leaf() }
func TestTransitive(t *testing.T) { _ = middle() }
func TestUnrelated(t *testing.T) { _ = unrelated() }
''',
                # The helper lives in another file of the same package.
                "b_test.go": '''package fixture
import "testing"
func TestOtherFile(t *testing.T) { _ = middle() }
''',
            })
            head = repo.commit({"helpers_test.go": helpers.replace("return 1", "return 3")})
            self.assertEqual(self.select(repo, base, head, support=False), set(),
                             "the race measurement's selection must not change")
            self.assertEqual(self.select(repo, base, head, support=True),
                             {"TestDirect", "TestTransitive", "TestOtherFile"})

    def test_changed_testmain_or_init_selects_the_whole_package(self):
        for hook in ("func TestMain(m *testing.M) { m.Run() }", 'func init() { _ = "x" }'):
            with self.subTest(hook=hook.split("(")[0]), tempfile.TemporaryDirectory() as directory:
                repo = FixtureRepo(Path(directory))
                tests = '''package fixture
import "testing"
func TestOne(t *testing.T) {}
func TestTwo(t *testing.T) {}
'''
                base = repo.commit({"a_test.go": tests})
                head = repo.commit({"main_test.go": 'package fixture\nimport "testing"\nvar _ testing.M\n' + hook + "\n"})
                self.assertEqual(self.select(repo, base, head, support=True), {"TestOne", "TestTwo"})

    def test_new_declaration_does_not_select_unchanged_tests(self):
        # PR #2298 added a Done method on a new test type; matching by name
        # selected every test that called ctx.Done().
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            uses = '''package fixture
import ("context"; "testing")
func TestUsesDone(t *testing.T) { <-context.Background().Done() }
'''
            base = repo.commit({"a_test.go": uses})
            head = repo.commit({"b_test.go": '''package fixture
import "testing"
type parked struct{}
func (parked) Done() <-chan struct{} { return nil }
func TestNew(t *testing.T) { _ = parked{}.Done() }
'''})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestNew"})

    def test_changed_method_selects_tests_reaching_its_type(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            types = '''package fixture
type fake struct{}
func (f *fake) Done() int { return 1 }
func newFake() *fake { return &fake{} }
'''
            base = repo.commit({
                "fake_test.go": types,
                "a_test.go": '''package fixture
import ("context"; "testing")
func TestViaConstructor(t *testing.T) { _ = newFake().Done() }
func TestViaType(t *testing.T) { var f fake; _ = f.Done() }
func TestOtherDone(t *testing.T) { <-context.Background().Done() }
''',
            })
            head = repo.commit({"fake_test.go": types.replace("return 1", "return 2")})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestViaConstructor", "TestViaType"})

    def test_moving_a_helper_between_files_is_not_a_change(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            helper = "func helper() int { return 1 }\n"
            test = 'package fixture\nimport "testing"\nfunc TestUses(t *testing.T) { _ = helper() }\n'
            base = repo.commit({"a_test.go": test + helper, "b_test.go": "package fixture\n"})
            head = repo.commit({"a_test.go": test, "b_test.go": "package fixture\n" + helper})
            self.assertEqual(self.select(repo, base, head, support=True), set())

    def test_external_test_package_is_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({
                "internal_test.go": 'package fixture\nimport "testing"\nfunc helper() int { return 1 }\nfunc TestInternal(t *testing.T) { _ = helper() }\n',
                "external_test.go": 'package fixture_test\nimport "testing"\nfunc helper() int { return 1 }\nfunc TestExternal(t *testing.T) { _ = helper() }\n',
            })
            head = repo.commit({
                "internal_test.go": 'package fixture\nimport "testing"\nfunc helper() int { return 2 }\nfunc TestInternal(t *testing.T) { _ = helper() }\n',
            })
            self.assertEqual(self.select(repo, base, head, support=True), {"TestInternal"})


class RepeatRunsTest(unittest.TestCase):
    def test_count_follows_the_budget_between_its_bounds(self):
        self.assertEqual(planner.repeat_runs(0.0), planner.REPEAT_MAX_RUNS)
        self.assertEqual(planner.repeat_runs(0.2), planner.REPEAT_MAX_RUNS)
        self.assertEqual(planner.repeat_runs(1.1), int(planner.REPEAT_BUDGET_SECONDS // 1.1))
        self.assertEqual(planner.repeat_runs(planner.REPEAT_BUDGET_SECONDS * 10), planner.REPEAT_MIN_RUNS)

    def test_unusable_calibration_fails(self):
        for value in (-1.0, math.nan, math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                planner.repeat_runs(value)

    def test_cap_catches_the_flake_that_reached_main(self):
        # TestMCPV3EarlyResponseDropRecordsRefusal failed 5 of 600 race runs.
        self.assertGreater(planner.detection(planner.REPEAT_MAX_RUNS, 120), 0.98)


class RepeatGateEndToEndTest(unittest.TestCase):
    FLAKY = '''package fixture
import "testing"
var runs int
// Fails only on the second run in one process: a single run always passes.
func TestFlaky(t *testing.T) {
	runs++
	if runs == 2 {
		t.Fatal("second run")
	}
}
'''
    STABLE = 'package fixture\nimport "testing"\nfunc TestStable(t *testing.T) {}\n'

    @classmethod
    def setUpClass(cls):
        cls.capture = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.capture.name) / "select-tests"
        subprocess.run(["go", "build", "-o", str(cls.binary),
                        str(planner.ROOT / "scripts/ci_changed_tests.go")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.capture.cleanup()

    def gate(self, repo: FixtureRepo, base: str, head: str, **kwargs) -> tuple[int, str]:
        selection = subprocess.run([str(self.binary), "--include-support", "--base", base, "--head", head],
                                   cwd=repo.root, check=True, capture_output=True, text=True)
        out = io.StringIO()
        with patch.object(planner, "ROOT", repo.root), redirect_stdout(out):
            status = planner.repeat_changed_tests(json.loads(selection.stdout), "",
                                                  repo.root / "out" / "repeat.json", **kwargs)
        return status, out.getvalue()

    def test_flaky_test_passes_once_and_fails_the_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({})
            head = repo.commit({"flaky_test.go": self.FLAKY})
            single = subprocess.run(["go", "test", "-race", "-count=1", "."], cwd=repo.root,
                                    capture_output=True, text=True)
            self.assertEqual(single.returncode, 0, single.stdout + single.stderr)
            status, output = self.gate(repo, base, head)
            self.assertEqual(status, 1, output)
            self.assertIn("TestFlaky failed 1 of", output)
            self.assertIn("::error title=Changed test failed a repeated race run::", output)
            # Vacuity: with the repeats removed, the same change passes.
            with patch.object(planner, "repeat_runs", return_value=1):
                status, output = self.gate(repo, base, head)
            self.assertEqual(status, 0, output)

    def test_stable_test_passes_and_reports_its_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({})
            head = repo.commit({"stable_test.go": self.STABLE})
            status, output = self.gate(repo, base, head)
            self.assertEqual(status, 0, output)
            self.assertIn(f"passed {planner.REPEAT_MAX_RUNS} race runs each", output)

    def test_no_changed_tests_is_a_successful_no_op(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({"stable_test.go": self.STABLE})
            head = repo.commit({"lib.go": "package fixture\n\nconst unused = 1\n"})
            status, output = self.gate(repo, base, head)
            self.assertEqual(status, 0, output)
            self.assertIn("nothing to repeat", output)

    def test_build_failure_fails_the_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({})
            head = repo.commit({"broken_test.go": self.STABLE + "func TestBroken(t *testing.T) { undefined() }\n"})
            status, output = self.gate(repo, base, head)
            self.assertEqual(status, 1, output)

    def test_deadline_before_a_package_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({})
            head = repo.commit({"stable_test.go": self.STABLE})
            with self.assertRaisesRegex(ValueError, "repeat deadline reached"):
                self.gate(repo, base, head, deadline_seconds=0)


class RepeatResultsTest(unittest.TestCase):
    def stream(self, events: list) -> Path:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(Path(handle.name).unlink)
        with handle:
            for event in events:
                handle.write((event if isinstance(event, str) else json.dumps(event)) + "\n")
        return Path(handle.name)

    def test_package_failure_without_test_failure_is_attributed(self):
        path = self.stream([
            {"Action": "run", "Package": "p", "Test": "TestA"},
            "panic: test timed out",
            {"Action": "fail", "Package": "p", "Elapsed": 1.0},
        ])
        passes, failures, _ = planner.repeat_results(path, {"p": ["TestA"]})
        self.assertEqual(passes, {})
        self.assertEqual(failures, {("p", "TestA"): 1})

    def test_invalid_elapsed_fails(self):
        path = self.stream([{"Action": "pass", "Package": "p", "Test": "TestA", "Elapsed": -1}])
        with self.assertRaises(ValueError):
            planner.repeat_results(path, {"p": ["TestA"]})

    def test_subtests_and_unselected_tests_are_ignored(self):
        path = self.stream([
            {"Action": "fail", "Package": "p", "Test": "TestA/sub", "Elapsed": 0.1},
            {"Action": "fail", "Package": "p", "Test": "TestOther", "Elapsed": 0.1},
            {"Action": "pass", "Package": "p", "Test": "TestA", "Elapsed": 0.5},
        ])
        passes, failures, seconds = planner.repeat_results(path, {"p": ["TestA"]})
        self.assertEqual((passes, failures, seconds), ({("p", "TestA"): 1}, {}, 0.5))


if __name__ == "__main__":
    unittest.main()
