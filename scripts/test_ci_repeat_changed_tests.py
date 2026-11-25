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

    def test_reordered_inits_select_the_whole_package(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            original = '''package fixture
import "testing"
func init() { _ = "a" }
func init() { _ = "b" }
func TestOne(t *testing.T) {}
func TestTwo(t *testing.T) {}
'''
            base = repo.commit({"a_test.go": original})
            head = repo.commit({"a_test.go": original.replace("func init() { _ = \"a\" }\nfunc init() { _ = \"b\" }",
                                                             "func init() { _ = \"b\" }\nfunc init() { _ = \"a\" }")})
            self.assertEqual(self.select(repo, base, head, support=False), set())
            self.assertEqual(self.select(repo, base, head, support=True), {"TestOne", "TestTwo"})

    def test_hook_reaching_a_changed_helper_selects_the_whole_package(self):
        hooks = (
            "func init() { leaf() }\n",
            "func TestMain(m *testing.M) { leaf(); m.Run() }\n",
        )
        for hook in hooks:
            with self.subTest(hook=hook.split("(")[0]), tempfile.TemporaryDirectory() as directory:
                repo = FixtureRepo(Path(directory))
                base = repo.commit({
                    "h_test.go": 'package fixture\nimport "testing"\nfunc leaf() int { return 1 }\n' + hook,
                    "a_test.go": 'package fixture\nimport "testing"\nfunc TestUnrelated(t *testing.T) {}\n',
                })
                head = repo.commit({
                    "h_test.go": 'package fixture\nimport "testing"\nfunc leaf() int { return 2 }\n' + hook,
                })
                self.assertEqual(self.select(repo, base, head, support=True), {"TestUnrelated"})

    def test_unchanged_init_does_not_select_tests(self):
        # The helper change selects TestOne. The unchanged init must not pull
        # in a test that does not reach the helper.
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            original = '''package fixture
import "testing"
func init() { _ = "a" }
func helper() int { return 1 }
func TestOne(t *testing.T) { _ = helper() }
func TestOther(t *testing.T) {}
'''
            base = repo.commit({"a_test.go": original})
            head = repo.commit({"a_test.go": original.replace("return 1", "return 2")})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestOne"})

    def test_blank_import_change_selects_the_whole_package(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({
                "a_test.go": 'package fixture\nimport ("testing"; _ "errors")\nfunc TestOne(t *testing.T) {}\n',
            })
            head = repo.commit({
                "a_test.go": 'package fixture\nimport ("testing"; _ "fmt")\nfunc TestOne(t *testing.T) {}\n',
            })
            self.assertEqual(self.select(repo, base, head, support=False), set())
            self.assertEqual(self.select(repo, base, head, support=True), {"TestOne"})

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

    def select_full(self, repo: FixtureRepo, base: str, head: str) -> dict[str, str]:
        result = subprocess.run([str(self.binary), "--base", base, "--head", head, "--include-support"],
                                cwd=repo.root, check=True, capture_output=True, text=True)
        return {test["name"]: test["reason"] for test in json.loads(result.stdout)}

    def test_reason_separates_edited_from_reached_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            helper = "package fixture\nfunc helper() int { return 1 }\n"
            tests = 'package fixture\nimport "testing"\nfunc TestUses(t *testing.T) { _ = helper() }\nfunc TestEdited(t *testing.T) {}\n'
            base = repo.commit({"h_test.go": helper, "a_test.go": tests})
            head = repo.commit({"h_test.go": helper.replace("1", "2"),
                                "a_test.go": tests.replace("TestEdited(t *testing.T) {}", "TestEdited(t *testing.T) { t.Log(1) }")})
            self.assertEqual(self.select_full(repo, base, head), {"TestUses": "support", "TestEdited": "changed"})
            plain = subprocess.run([str(self.binary), "--base", base, "--head", head],
                                   cwd=repo.root, check=True, capture_output=True, text=True)
            self.assertNotIn("reason", plain.stdout, "the measurement selection keeps its shape")

    def test_declaration_kind_change_is_a_change(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            uses = 'package fixture\nimport "testing"\nfunc TestUses(t *testing.T) { _ = limit }\n'
            base = repo.commit({"h_test.go": "package fixture\nvar limit = 1\n", "a_test.go": uses})
            head = repo.commit({"h_test.go": "package fixture\nconst limit = 1\n"})
            # Same literal: only the declaration kind changed.
            self.assertEqual(self.select(repo, base, head, support=True), {"TestUses"})

    def test_grouped_constant_inherits_the_previous_expression(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            uses = 'package fixture\nimport "testing"\nfunc TestLimit(t *testing.T) { _ = limit }\nfunc TestOther(t *testing.T) {}\n'
            base = repo.commit({"h_test.go": "package fixture\nconst (\n\tseed = 1\n\tlimit\n)\n", "a_test.go": uses})
            head = repo.commit({"h_test.go": "package fixture\nconst (\n\tseed = 2\n\tlimit\n)\n"})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestLimit"})

    def test_iota_constant_position_change_is_a_change(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            uses = 'package fixture\nimport "testing"\nfunc TestB(t *testing.T) { _ = b }\n'
            base = repo.commit({"h_test.go": "package fixture\nconst (\n\ta = iota\n\tb\n)\n", "a_test.go": uses})
            head = repo.commit({"h_test.go": "package fixture\nconst (\n\ta = iota\n\tinserted\n\tb\n)\n"})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestB"})

    def test_new_method_shadowing_a_promoted_method_is_a_change(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            types = 'package fixture\ntype leaf struct{}\nfunc (leaf) Step() int { return 1 }\ntype outer struct{ leaf }\ntype other struct{}\nfunc (other) Step() int { return 3 }\n'
            uses = ('package fixture\nimport "testing"\nfunc TestOuter(t *testing.T) { _ = outer{}.Step() }\n'
                    'func TestOther(t *testing.T) { _ = other{}.Step() }\n')
            base = repo.commit({"types_test.go": types, "a_test.go": uses})
            head = repo.commit({"types_test.go": types + "func (outer) Step() int { return 2 }\n"})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestOuter"})

    def test_external_wrapper_of_a_changed_internal_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            export = "package fixture\nfunc Helper() int { return 1 }\n"
            base = repo.commit({
                "export_test.go": export,
                "in_test.go": 'package fixture\nimport "testing"\nfunc TestInternal(t *testing.T) {}\n',
                "x_test.go": ('package fixture_test\nimport ("testing"; fixture "example.test/fixture")\n'
                              'func wrapper() int { return fixture.Helper() }\nfunc TestX(t *testing.T) { _ = wrapper() }\n'),
            })
            head = repo.commit({"export_test.go": export.replace("1", "2")})
            # The wrapper reaches the changed helper; only an external hook
            # would reach back to internal tests.
            self.assertEqual(self.select(repo, base, head, support=True), {"TestX"})
            hook = repo.commit({"export_test.go": export.replace("1", "3"),
                                "hook_test.go": 'package fixture_test\nimport fixture "example.test/fixture"\nfunc init() { _ = fixture.Helper() }\n'})
            self.assertEqual(self.select(repo, head, hook, support=True), {"TestX", "TestInternal"})

    def test_named_variable_initializer_call_is_a_package_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            hook = 'package fixture\nfunc register() bool {{ return {value} }}\nvar registered = register()\n'
            base = repo.commit({
                "hook_test.go": hook.format(value="true"),
                "a_test.go": 'package fixture\nimport "testing"\nfunc TestOne(t *testing.T) {}\n',
            })
            head = repo.commit({"hook_test.go": hook.format(value="false")})
            # No test names registered, but its initializer runs for every test.
            self.assertEqual(self.select(repo, base, head, support=True), {"TestOne"})

    def test_versioned_import_path_binds_its_package_name(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            helpers = 'package fixture\nimport "gopkg.in/yaml.{v}"\nfunc encode() any {{ return yaml.Marshal }}\nfunc plain() int {{ return 1 }}\n'
            uses = ('package fixture\nimport "testing"\nfunc TestEncode(t *testing.T) { _ = encode() }\n'
                    'func TestPlain(t *testing.T) { _ = plain() }\n')
            base = repo.commit({"h_test.go": helpers.format(v="v2"), "a_test.go": uses})
            head = repo.commit({"h_test.go": helpers.format(v="v3")})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestEncode"})

    def test_rebound_import_selects_only_its_users(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            helpers = ('package fixture\nimport codec "{path}"\nfunc encode() bool {{ return codec.ErrUnsupported != nil }}\n'
                       'func plain() int {{ return 1 }}\n')
            uses = ('package fixture\nimport "testing"\nfunc TestEncode(t *testing.T) { _ = encode() }\n'
                    'func TestPlain(t *testing.T) { _ = plain() }\n')
            base = repo.commit({"h_test.go": helpers.format(path="errors"), "a_test.go": uses})
            head = repo.commit({"h_test.go": helpers.format(path="example.test/fixture/codec")})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestEncode"})
            # Importing the same path from one more file is not a rebinding.
            again = repo.commit({"b_test.go": 'package fixture\nimport codec "example.test/fixture/codec"\nfunc other() bool { return codec.ErrUnsupported != nil }\n'})
            self.assertEqual(self.select(repo, head, again, support=True), set())

    def test_internal_helper_reaches_the_external_test_package(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            export = "package fixture\nfunc Helper() int { return 1 }\n"
            base = repo.commit({
                "export_test.go": export,
                "x_test.go": 'package fixture_test\nimport ("testing"; fixture "example.test/fixture")\nfunc TestX(t *testing.T) { _ = fixture.Helper() }\n',
            })
            head = repo.commit({"export_test.go": export.replace("1", "2")})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestX"})

    def test_blank_variable_initializer_change_selects_the_whole_package(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({
                "hook_test.go": 'package fixture\nfunc register(int) bool { return true }\nvar _ = register(1)\n',
                "a_test.go": 'package fixture\nimport "testing"\nfunc TestOne(t *testing.T) {}\n',
            })
            head = repo.commit({"hook_test.go": 'package fixture\nfunc register(int) bool { return true }\nvar _ = register(2)\n'})
            self.assertEqual(self.select(repo, base, head, support=True), {"TestOne"})

    def test_blank_variable_callee_change_selects_the_whole_package(self):
        # The initializer text is unchanged. init() already selects every test
        # when its callee changes; a blank variable runs at init too, including
        # for the external test package in the same test binary.
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({
                "hook_test.go": 'package fixture\nfunc register(int) bool { return true }\nvar _ = register(1)\n',
                "a_test.go": 'package fixture\nimport "testing"\nfunc TestOne(t *testing.T) {}\n',
                "x_test.go": 'package fixture_test\nimport "testing"\nfunc TestX(t *testing.T) {}\n',
            })
            head = repo.commit({
                "hook_test.go": 'package fixture\nfunc register(int) bool { return false }\nvar _ = register(1)\n',
            })
            self.assertEqual(self.select(repo, base, head, support=True), {"TestOne", "TestX"})

    def test_external_hook_reaches_internal_tests(self):
        # go test links both packages into one binary: a TestMain in the
        # external package runs the internal tests too. Two TestMains fail
        # the build, so there is one hook.
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({
                "a_test.go": 'package fixture\nimport "testing"\nfunc TestOne(t *testing.T) {}\n',
                "x_test.go": 'package fixture_test\nimport "testing"\nfunc TestX(t *testing.T) {}\n',
            })
            head = repo.commit({
                "x_test.go": 'package fixture_test\nimport "testing"\nfunc TestMain(m *testing.M) { m.Run() }\nfunc TestX(t *testing.T) {}\n',
            })
            self.assertEqual(self.select(repo, base, head, support=True), {"TestOne", "TestX"})

    def test_repeated_blank_import_is_not_a_change(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({
                "a_test.go": 'package fixture\nimport ("testing"; _ "errors")\nfunc TestOne(t *testing.T) {}\n',
            })
            head = repo.commit({"b_test.go": 'package fixture\nimport _ "errors"\n'})
            self.assertEqual(self.select(repo, base, head, support=True), set())

    def test_external_package_name_collision_over_selects(self):
        # Matching is by name, so an external test package's own helper with
        # the same name as a changed internal one is also selected. That costs
        # repeat budget, never coverage; the reverse direction stays separate.
        with tempfile.TemporaryDirectory() as directory:
            repo = FixtureRepo(Path(directory))
            base = repo.commit({
                "internal_test.go": 'package fixture\nimport "testing"\nfunc helper() int { return 1 }\nfunc TestInternal(t *testing.T) { _ = helper() }\n',
                "external_test.go": 'package fixture_test\nimport "testing"\nfunc helper() int { return 1 }\nfunc TestExternal(t *testing.T) { _ = helper() }\n',
            })
            head = repo.commit({
                "internal_test.go": 'package fixture\nimport "testing"\nfunc helper() int { return 2 }\nfunc TestInternal(t *testing.T) { _ = helper() }\n',
            })
            self.assertEqual(self.select(repo, base, head, support=True), {"TestInternal", "TestExternal"})
            # An external helper change never reaches the internal package.
            head2 = repo.commit({
                "internal_test.go": 'package fixture\nimport "testing"\nfunc helper() int { return 1 }\nfunc TestInternal(t *testing.T) { _ = helper() }\n',
                "external_test.go": 'package fixture_test\nimport "testing"\nfunc helper() int { return 3 }\nfunc TestExternal(t *testing.T) { _ = helper() }\n',
            })
            self.assertEqual(self.select(repo, base, head2, support=True), {"TestExternal"})


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


class BoundedReachedTest(unittest.TestCase):
    def test_keeps_the_cheapest_tests_within_the_budget(self):
        trees = {"proxy": {"TestCheap": 1.0, "TestMid": 30.0, "TestHeavy": 500.0}}
        packages = {"example.test/rest": 50.0}
        reached = {"github.com/luckyPipewrench/pipelock/internal/proxy": ["TestHeavy", "TestMid", "TestCheap", "TestUnrecorded"],
                   "example.test/rest": ["TestA", "TestB"]}
        with patch.object(planner, "load_durations", return_value=trees), \
             patch.object(planner, "load_package_durations", return_value=packages):
            kept, dropped, spent = planner.bounded_reached(reached, budget=90.0)
        # 1 + 1 (unrecorded) + 30 + 50 (rest package as a group) = 82 <= 90; the 500s test is left out.
        self.assertEqual(kept, {"github.com/luckyPipewrench/pipelock/internal/proxy": ["TestCheap", "TestMid", "TestUnrecorded"],
                                "example.test/rest": ["TestA", "TestB"]})
        self.assertEqual((dropped, spent), (1, 82.0))

    def test_nothing_fits_keeps_nothing(self):
        with patch.object(planner, "load_durations", return_value={}), \
             patch.object(planner, "load_package_durations", return_value={"example.test/rest": 400.0}):
            kept, dropped, spent = planner.bounded_reached({"example.test/rest": ["TestA"]}, budget=120.0)
        self.assertEqual((kept, dropped, spent), ({}, 1, 0.0))


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
            self.assertIn("-parallel=2", output)
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
            with self.assertRaisesRegex(ValueError, "deadline reached"):
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

    def test_skip_time_counts_toward_calibration(self):
        path = self.stream([{"Action": "skip", "Package": "p", "Test": "TestA", "Elapsed": 5.0}])
        passes, failures, seconds = planner.repeat_results(path, {"p": ["TestA"]})
        self.assertEqual((passes, failures, seconds), ({("p", "TestA"): 1}, {}, 5.0))

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
