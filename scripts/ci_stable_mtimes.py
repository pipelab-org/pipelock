#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Normalize checkout mtimes so Go can reuse test results across CI checkouts.

Rule source: cmd/go/internal/test/test.go, hashOpen and hashWriteStat. Go
hashes size, mode, mtime and directory status for opened files, and the names
and stats of directory entries. It rejects recently modified regular files.
Git blob/tree IDs give clean inputs reproducible, old timestamps without
rewriting their contents. The mapping below is the CI contract.

Dirty and untracked inputs (including ignored files) retain their timestamps,
as do their ancestor directories. Staged changes also exclude ancestor trees:
the index's blobs are current, but HEAD's tree IDs aren't. Symlinks are skipped
because Go's os.Stat follows them; stamping a link cannot stabilize its target.
Run after all checkout preparation and immediately before tests, with no
concurrent worktree writers. This script makes no network requests.
"""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path


EPOCH_SECONDS = 946684800
SPAN_SECONDS = 631152000


def object_mtime_ns(oid: bytes) -> int:
    seconds = EPOCH_SECONDS + int(oid[:15], 16) % SPAN_SECONDS
    nanos = int(oid[15:23], 16) % 1_000_000_000
    return seconds * 1_000_000_000 + nanos


def git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True,
    ).stdout


def paths(output: bytes) -> set[Path]:
    return {Path(os.fsdecode(name)) for name in output.split(b"\0") if name}


def ancestors(path: Path) -> set[Path]:
    return set(path.parents)


def stabilize(root: Path) -> str:
    # Collect every git result before stamping: a failed query must stop us.
    entries = git(root, "ls-files", "-s", "-z").split(b"\0")
    trees = git(root, "ls-tree", "-r", "-d", "-z", "HEAD").split(b"\0")
    root_tree = git(root, "rev-parse", "HEAD^{tree}").strip()
    dirty = paths(git(root, "diff", "--name-only", "-z", "--no-ext-diff"))
    untracked = paths(git(root, "ls-files", "--others", "-z"))
    staged = paths(git(root, "diff", "--cached", "--name-only", "-z", "HEAD", "--no-ext-diff"))
    files: dict[Path, bytes] = {}
    directories = {Path("."): root_tree}
    skipped_links = 0
    for entry in entries:
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, oid, stage = metadata.split()
        path = Path(os.fsdecode(name))
        if stage != b"0":
            dirty.add(path)
        elif mode in (b"100644", b"100755"):
            files[path] = oid
        else:
            # Symlinks and submodules have no regular-file timestamp to use.
            skipped_links += 1
            dirty.add(path)
    for entry in trees:
        if entry:
            metadata, name = entry.split(b"\t", 1)
            directories[Path(os.fsdecode(name))] = metadata.split()[2]

    excluded = set()
    for path in dirty | untracked | staged:
        excluded.update(ancestors(path))
    missing = set()
    # Check directories from the root down; never traverse a replaced parent
    # symlink to stamp files outside this checkout.
    invalid = set()
    for path in sorted(directories, key=lambda p: len(p.parts)):
        if ancestors(path) & invalid:
            invalid.add(path)
            continue
        try:
            mode = (root / path).lstat().st_mode
        except FileNotFoundError:
            missing.add(path)
            invalid.add(path)
        else:
            if not stat.S_ISDIR(mode):
                invalid.add(path)
                dirty.add(path)
    for path in invalid:
        excluded.add(path)
        excluded.update(ancestors(path))

    files_stamped = 0
    for path, oid in files.items():
        if ancestors(path) & invalid:
            continue
        try:
            info = (root / path).lstat()
        except FileNotFoundError:
            missing.add(path)
            excluded.update(ancestors(path))
            continue
        if path in dirty:
            continue
        if not stat.S_ISREG(info.st_mode):
            dirty.add(path)
            excluded.update(ancestors(path))
            continue
        timestamp = object_mtime_ns(oid)
        os.utime(root / path, ns=(timestamp, timestamp), follow_symlinks=False)
        files_stamped += 1

    directories_stamped = 0
    for path, oid in directories.items():
        if path in excluded:
            continue
        timestamp = object_mtime_ns(oid)
        os.utime(root / path, ns=(timestamp, timestamp), follow_symlinks=False)
        directories_stamped += 1
    return (
        f"stable mtimes: files stamped={files_stamped}, directories stamped={directories_stamped}, "
        f"skipped dirty={len(dirty)}, untracked={len(untracked)}, missing={len(missing)}, "
        f"links/submodules={skipped_links}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository checkout root")
    args = parser.parse_args()
    try:
        root = args.root.resolve(strict=True)
        actual_root = Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel").rstrip(b"\n")))
        if root != actual_root:
            raise ValueError("--root must be the repository checkout root")
        print(stabilize(root))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"stable mtimes: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
