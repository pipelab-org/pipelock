#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Run the same native Go fuzz targets as the pull-request workflow."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ".github/fuzz-targets.json"
# Go's native fuzz declaration: https://go.dev/doc/security/fuzz/ (Writing a fuzz test).
# Limit discovery to Go test source; strings in policy-test fixtures aren't targets.
FUZZ_DECLARATION = re.compile(r"(?m)^func\s+(Fuzz\w+)\s*\(\s*\w+\s+\*testing\.F\s*\)")


def check_targets(root, manifest):
    declared = {
        ("./" + path.parent.relative_to(root).as_posix(), target)
        for path in root.rglob("*_test.go")
        for target in FUZZ_DECLARATION.findall(path.read_text(encoding="utf-8"))
    }
    rows = manifest["include"]
    listed = {(row["package"], row["target"]) for row in rows}
    if not declared or not listed:
        raise AssertionError("empty fuzz inventory")
    if len(listed) != len(rows) or len({row["target"] for row in rows}) != len(rows):
        raise AssertionError("duplicate fuzz target or artifact name")
    if declared != listed:
        raise AssertionError(f"fuzz target drift: unlisted={declared - listed}, missing={listed - declared}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fuzztime", default="30s", help="Go fuzz budget per target (default: 30s)")
    args = parser.parse_args()
    manifest = json.loads((ROOT / MANIFEST).read_text())
    # go test exits 0 when -fuzz matches nothing, so an unknown row would pass silently.
    try:
        check_targets(ROOT, manifest)
    except AssertionError as err:
        print(f"fuzz-targets: {err}", file=sys.stderr)
        return 1
    for row in manifest["include"]:
        command = [
            "go", "test", "-run=^$", f"-fuzz=^{row['target']}$",
            f"-fuzztime={args.fuzztime}", row["package"],
        ]
        print(" ".join(command), flush=True)
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
