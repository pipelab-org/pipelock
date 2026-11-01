#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Run the same native Go fuzz targets as the pull-request workflow."""

import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fuzztime", default="30s", help="Go fuzz budget per target (default: 30s)")
    args = parser.parse_args()
    targets = json.loads((ROOT / ".github/fuzz-targets.json").read_text())["include"]
    for row in targets:
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
