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
# Go documents its execution counter at https://go.dev/doc/security/fuzz/.
FUZZ_EXECUTIONS = re.compile(r"(?m)^fuzz: elapsed: [^,\n]+, execs: [1-9][0-9]* ")


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


def run_target(row, fuzztime):
    command = [
        "go", "test", "-json", "-run=^$", f"-fuzz=^{row['target']}$",
        f"-fuzztime={fuzztime}", row["package"],
    ]
    print(" ".join(command), flush=True)
    passed = executed = False
    valid = True
    # The test2json Test/Action fields distinguish a target pass from a package
    # pass or skip: https://pkg.go.dev/cmd/test2json. Missing and skipped fuzz
    # targets can exit zero, so process success alone is not execution evidence.
    with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("non-object test event")
            except ValueError:
                print(line, end="", flush=True)
                valid = False
                continue
            output = event.get("Output", "")
            print(output, end="", flush=True)
            if event.get("Test") == row["target"]:
                passed = passed or event.get("Action") == "pass"
                executed = executed or (event.get("Action") == "output" and
                                        FUZZ_EXECUTIONS.search(output) is not None)
        result = process.wait()
    if result:
        return result
    if not valid or not passed or not executed:
        print(f"fuzz-targets: {row['target']} did not complete fuzzing with positive executions",
              file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fuzztime", default="30s", help="Go fuzz budget per target (default: 30s)")
    parser.add_argument("--package", help="Run only this manifest package and --target")
    parser.add_argument("--target", help="Run only this manifest target and --package")
    args = parser.parse_args()
    if bool(args.package) != bool(args.target):
        parser.error("--package and --target must be supplied together")
    manifest = json.loads((ROOT / MANIFEST).read_text())
    # go test exits 0 when -fuzz matches nothing, so an unknown row would pass silently.
    try:
        check_targets(ROOT, manifest)
    except AssertionError as err:
        print(f"fuzz-targets: {err}", file=sys.stderr)
        return 1
    rows = manifest["include"]
    if args.target:
        rows = [row for row in rows if (row["package"], row["target"]) == (args.package, args.target)]
        if not rows:
            parser.error("requested package and target are not in the fuzz manifest")
    for row in rows:
        result = run_target(row, args.fuzztime)
        if result:
            return result
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
