#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise stable CI timestamps using real git checkouts and Go's test cache."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci_stable_mtimes.py"


class StableMtimesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pipelock-stable-mtimes-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "source"
        self.repo.mkdir()
        self.git(self.repo, "init", "-q", "-b", "main")
        self.write("testdata/value.txt", "good")
        self.write("testdata/listed/entry.txt", "entry")
        self.write("other/unchanged.txt", "unchanged")
        self.commit()
        spec = importlib.util.spec_from_file_location("ci_stable_mtimes", SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def git(self, repo: Path, *args: str) -> str:
        return subprocess.run(
            ["git", "-c", "user.name=ci", "-c", "user.email=ci@example.invalid", *args],
            cwd=repo, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def write(self, path: str, text: str) -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self) -> None:
        self.git(self.repo, "add", "-A")
        self.git(self.repo, "commit", "-q", "-m", "fixture")

    def clone(self, name: str) -> Path:
        path = self.base / name
        self.git(self.base, "clone", "-q", "--no-local", str(self.repo), str(path))
        return path

    def stamp(self, repo: Path) -> str:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(repo)],
            check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()

    def mtimes(self, repo: Path) -> dict[str, int]:
        return {
            path: (repo / path).lstat().st_mtime_ns
            for path in (".", "testdata", "testdata/listed", "testdata/value.txt",
                         "testdata/listed/entry.txt", "other", "other/unchanged.txt")
        }

    def test_object_identity_controls_files_and_ancestor_directories(self) -> None:
        first = self.clone("first")
        self.stamp(first)
        before = self.mtimes(first)
        second = self.clone("second")
        self.stamp(second)
        self.assertEqual(before, self.mtimes(second))
        self.write("testdata/value.txt", "next")
        self.commit()
        changed = self.clone("changed")
        self.stamp(changed)
        after = self.mtimes(changed)
        self.assertEqual(
            {path for path in before if before[path] != after[path]},
            {".", "testdata", "testdata/value.txt"},
        )
        self.assertTrue(all(value < time.time_ns() - 2_000_000_000 for value in after.values()))

    def content_mtime(self, text: str) -> int:
        digest = hashlib.sha256(text.encode()).hexdigest().encode()
        return self.module.object_mtime_ns(digest)

    def test_dirty_and_untracked_paths_keep_their_ancestor_timestamps(self) -> None:
        self.write("testdata/value.txt", "evil")
        self.write("other/new.txt", "new")
        self.write(".gitignore", "other/ignored.txt\n")
        self.write("other/ignored.txt", "ignored")
        names = (".", "testdata", "other", "other/new.txt", "other/ignored.txt")
        before = {name: (self.repo / name).stat().st_mtime_ns for name in names}
        output = self.stamp(self.repo)
        self.assertEqual(before, {name: (self.repo / name).stat().st_mtime_ns for name in names})
        # A dirty tracked file is stamped from the bytes on disk, never from
        # the committed blob, so it cannot borrow the clean file's cache entry.
        self.assertEqual((self.repo / "testdata/value.txt").stat().st_mtime_ns, self.content_mtime("evil"))
        self.assertIn("dirty=1", output)
        self.assertIn("untracked=3", output)
        self.assertIn("directories stamped=1", output)

    def test_staged_change_does_not_use_heads_ancestor_tree_ids(self) -> None:
        self.write("testdata/value.txt", "next")
        self.git(self.repo, "add", "testdata/value.txt")
        before = {name: (self.repo / name).stat().st_mtime_ns for name in (".", "testdata")}
        self.stamp(self.repo)
        self.assertEqual(before, {name: (self.repo / name).stat().st_mtime_ns for name in before})
        self.assertLess((self.repo / "testdata/value.txt").stat().st_mtime_ns, time.time_ns() - 2_000_000_000)

    def test_index_flags_cannot_hide_changed_contents(self) -> None:
        # git diff does not report a change to an assume-unchanged or
        # skip-worktree entry, and a smudge filter can turn the same blob into
        # different bytes. The file must still be stamped from what is on disk,
        # and its directories must keep their checkout times.
        clean = self.clone("clean")
        self.stamp(clean)
        clean_value = (clean / "testdata/value.txt").stat().st_mtime_ns
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                repo = self.clone(f"flagged{flag}")
                self.git(repo, "update-index", flag, "testdata/value.txt")
                (repo / "testdata/value.txt").write_text("evil", encoding="utf-8")  # same size
                self.assertEqual(self.git(repo, "diff", "--name-only"), "")
                before = {name: (repo / name).stat().st_mtime_ns for name in (".", "testdata")}
                self.stamp(repo)
                value = (repo / "testdata/value.txt").stat().st_mtime_ns
                self.assertNotEqual(value, clean_value)
                self.assertEqual(value, self.content_mtime("evil"))
                self.assertEqual(before, {name: (repo / name).stat().st_mtime_ns for name in before})

    def test_staged_directory_replaced_by_symlink_never_stamps_outside(self) -> None:
        # A newly staged directory is not in HEAD's tree, so the directory
        # checks never see it; the file's own parent check must catch it.
        self.write("fresh/inner.txt", "inner")
        self.git(self.repo, "add", "fresh/inner.txt")
        self.git(self.repo, "update-index", "--skip-worktree", "fresh/inner.txt")
        (self.repo / "fresh").rename(self.base / "outside")
        (self.repo / "fresh").symlink_to(self.base / "outside", target_is_directory=True)
        target = self.base / "outside/inner.txt"
        before = target.stat().st_mtime_ns
        self.stamp(self.repo)
        self.assertEqual(target.stat().st_mtime_ns, before)

    def test_missing_sparse_path_and_symlinks_are_skipped(self) -> None:
        outside = self.base / "external.txt"
        outside.write_text("external", encoding="utf-8")
        (self.repo / "link").symlink_to(outside)
        self.commit()
        link_before = (self.repo / "link").lstat().st_mtime_ns
        target_before = outside.stat().st_mtime_ns
        self.git(self.repo, "update-index", "--skip-worktree", "testdata/value.txt")
        (self.repo / "testdata/value.txt").unlink()
        before = (self.repo / "testdata").stat().st_mtime_ns
        output = self.stamp(self.repo)
        self.assertIn("missing=1", output)
        self.assertIn("links/submodules=1", output)
        self.assertEqual((self.repo / "testdata").stat().st_mtime_ns, before)
        self.assertEqual((self.repo / "link").lstat().st_mtime_ns, link_before)
        self.assertEqual(outside.stat().st_mtime_ns, target_before)

    def test_replaced_parent_directory_never_stamps_external_files(self) -> None:
        self.git(self.repo, "update-index", "--skip-worktree", "other/unchanged.txt")
        (self.repo / "other").rename(self.base / "external")
        (self.repo / "other").symlink_to(self.base / "external", target_is_directory=True)
        target = self.base / "external/unchanged.txt"
        before = target.stat().st_mtime_ns
        self.stamp(self.repo)
        self.assertEqual(target.stat().st_mtime_ns, before)

    def test_git_errors_exit_nonzero_before_stamping(self) -> None:
        (self.repo / ".git").rename(self.repo / "git-disabled")
        before = self.mtimes(self.repo)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.repo)], capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stable mtimes:", result.stderr)
        self.assertEqual(before, self.mtimes(self.repo))

    def test_workflow_stamps_immediately_before_unit_tests_on_every_event(self) -> None:
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8"))["jobs"]
        steps = jobs["test-unit-go126"]["steps"]
        index = next(i for i, step in enumerate(steps) if step.get("name") == "Run tests (no race)")
        self.assertEqual(steps[index - 1]["run"], "python3 scripts/ci_stable_mtimes.py")
        self.assertNotIn("if", steps[index - 1])
        self.assertEqual(sum("ci_stable_mtimes.py" in str(job) for job in jobs.values()), 1)

    @unittest.skipUnless(shutil.which("go"), "go is not on PATH; real test-cache round trip requires Go")
    def test_real_go_cache_round_trip(self) -> None:
        self.write("go.mod", "module cache.example/fixture\n\ngo 1.20\n")
        self.write("fixture.go", "package fixture\n")
        self.write("fixture_test.go", '''package fixture
import ("os"; "testing")
func TestValue(t *testing.T) {
    data, err := os.ReadFile("testdata/value.txt")
    if err != nil || string(data) != "good" { t.Fatalf("value=%q err=%v", data, err) }
}
func TestDirectory(t *testing.T) {
    entries, err := os.ReadDir("testdata/listed")
    if err != nil || len(entries) != 1 { t.Fatalf("entries=%v err=%v", entries, err) }
}
''')
        self.commit()
        initial = self.git(self.repo, "rev-parse", "HEAD")
        env = {**os.environ, "GOCACHE": str(self.base / "go-cache"), "GOFLAGS": "-mod=mod", "GOWORK": "off"}

        def run(repo: Path, selector: str) -> subprocess.CompletedProcess[str]:
            result = subprocess.run(
                ["go", "test", "-run=" + selector, "."], cwd=repo, env=env,
                capture_output=True, text=True, timeout=180,
            )
            print(f"go test -run={selector} .: {result.stdout.strip()} {result.stderr.strip()}", flush=True)
            return result

        # CI uses the same absolute checkout path on each runner. Go hashes
        # absolute input paths too, so retain clones separately then replace the
        # checkout at that path, rather than asserting portability Go doesn't offer.
        first = self.clone("checkout")
        self.stamp(first)
        for selector in ("TestValue", "TestDirectory"):
            result = run(first, selector)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("(cached)", result.stdout)
        first.rename(self.base / "saved-first")
        second = self.clone("checkout")
        self.stamp(second)
        for selector in ("TestValue", "TestDirectory"):
            result = run(second, selector)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("(cached)", result.stdout, "fresh checkout must reuse the cached result")
        second.rename(self.base / "saved-second")
        self.write("testdata/value.txt", "evil")  # Same size, different blob.
        self.commit()
        changed = self.clone("checkout")
        self.stamp(changed)
        result = run(changed, "TestValue")
        self.assertNotEqual(result.returncode, 0, "same-size content change must not reuse a stale pass")
        self.assertIn('value="evil"', result.stdout)
        self.assertNotIn("(cached)", result.stdout)
        changed.rename(self.base / "saved-changed")
        self.git(self.repo, "switch", "-q", "--detach", initial)
        self.write("testdata/listed/added.txt", "added")
        self.commit()
        added = self.clone("checkout")
        self.stamp(added)
        result = run(added, "TestDirectory")
        self.assertNotEqual(result.returncode, 0, "a new directory entry must invalidate the cached pass")
        self.assertIn("added.txt", result.stdout)
        self.assertNotIn("(cached)", result.stdout)


if __name__ == "__main__":
    unittest.main()
