# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""Check installed receipt v3 verifiers against canonical corpus documents."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import difflib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

LANES = ("GO_V3", "WASM_V3", "TS_V3", "RUST_V3", "PY_V3")
CORPUS = Path(__file__).resolve().parent / "testdata/v3"


def request_flags(request):
    flags = []
    for field, flag in (
        ("keys", "--key"),
        ("accept_discontinuities", "--accept-discontinuity"),
        ("allow_partial_histories", "--allow-partial-history"),
        ("expect_heads", "--expect-head"),
        ("expect_sequences", "--expect-seq"),
    ):
        for value in request.get(field, []):
            flags.extend((flag, value))
    for field, flag in (("expect_lineage", "--expect-lineage"), ("format", "--format")):
        if field in request:
            flags.extend((flag, request[field]))
    for field, flag in (("allow_unpinned", "--allow-unpinned"), ("allow_prefix", "--allow-prefix")):
        if request.get(field):
            flags.append(flag)
    return flags


def verify(command, args, expected_exit):
    proc = subprocess.run(
        [*command, "v3", *args], capture_output=True, check=False, timeout=60
    )
    if proc.returncode != expected_exit:
        raise ValueError(
            f"exit {proc.returncode}, expected {expected_exit}\n"
            f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
        )
    return proc.stdout


def compare(actual, expected, label):
    if actual == expected:
        return
    delta = b"".join(
        difflib.diff_bytes(
            difflib.unified_diff,
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=b"expected",
            tofile=b"actual",
        )
    )
    # Preserve a visible distinction even when only a terminal newline differs.
    raise ValueError(f"{label} bytes differ ({len(expected)} vs {len(actual)} bytes)\n"
                     f"{delta.decode('utf-8', errors='backslashreplace')}")


def check_vector(command, request_path):
    vector = request_path.parent
    request = json.loads(request_path.read_bytes())
    inputs = request["inputs"]
    for name in inputs:
        if "\\" in name or any(part in ("", ".", "..") for part in name.split("/")):
            raise ValueError(f"invalid corpus input path: {name!r}")
    if request.get("legacy"):
        for name in inputs:
            claims = verify(command, ["--claims", str(vector / name)], 0)
            compare(claims, b"false\n", "legacy claim")
        return False, False
    expected = (vector / "projection.json").read_bytes()
    expected_exit = json.loads(expected)["exit_code"]
    flags = request_flags(request)
    with tempfile.TemporaryDirectory(prefix="receipt-v3-gate-") as scratch:
        # Stage each vector so valid unknown files are visible in directory
        # scope, while the corpus metadata is never treated as input.
        if request.get("directory"):
            root = Path(scratch)
            for name in inputs:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(vector / name, target)
            paths = [str(root)]
        else:
            paths = [str(vector / name) for name in inputs]
        options = [*flags, "--output"]
        projection = verify(command, [*options, "projection", "--", *paths], expected_exit)
        compare(projection, expected, "projection")
        full = verify(command, [*options, "result", "--", *paths], expected_exit)
        if len(paths) >= 2:
            for label, order in (("reversed", paths[::-1]), ("rotated", paths[1:] + paths[:1])):
                reordered = verify(command, [*options, "result", "--", *order], expected_exit)
                compare(reordered, full, f"{label} full result")
    return True, full == (vector / "expect.json").read_bytes()


def run_lane(lane, command, vectors):
    projections = claims = ordered = equal = failures = 0
    # Each browser CLI invocation starts a new Node and WebAssembly runtime.
    # Bound concurrency and consume results in corpus order for stable reports.
    with ThreadPoolExecutor(max_workers=4 if lane == "WASM_V3" else 1) as pool:
        runs = [pool.submit(check_vector, command, vector) for vector in vectors]
        for vector, run in zip(vectors, runs, strict=True):
            try:
                verified, same_full = run.result()
                if verified:
                    projections += 1
                    equal += same_full
                    request = json.loads(vector.read_bytes())
                    ordered += not request.get("directory") and len(request["inputs"]) >= 2
                else:
                    claims += 1
            except (OSError, ValueError, subprocess.TimeoutExpired) as err:
                print(f"{lane} {vector.parent.name}: {err}", file=sys.stderr)
                failures += 1
    print(f"{lane}: {'FAIL' if failures else 'PASS'} "
          f"{projections + claims}/{len(vectors)} vectors "
          f"({projections} projections, {claims} legacy claim vectors), "
          f"{ordered} order checks, {equal}/{projections} full documents equal to Go, "
          f"{failures} failed", flush=True)
    return bool(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    vectors = sorted(args.corpus.resolve().glob("*/request.json"))
    if not vectors:
        parser.error("no receipt v3 vector requests found")
    require_all = os.environ.get("REQUIRE_ALL_LANES") == "1"
    failed = False
    for lane in LANES:
        setting = os.environ.get(lane, "").strip()
        if not setting:
            print(f"{lane}: SKIPPED (lane command unset)", flush=True)
            failed |= require_all
            continue
        failed |= run_lane(lane, shlex.split(setting), vectors)
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
