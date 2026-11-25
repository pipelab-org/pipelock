# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Check the runtime registry shipped by each receipt v3 SDK."""

import argparse
from importlib.resources import files
import json
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
SECTIONS = (
    "conditions",
    "enums",
    "findings",
    "kinds",
    "layout",
    "limits",
    "normalization_profiles",
    "objects",
    "profile",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("typescript_registry", type=Path)
    args = parser.parse_args()

    source = json.loads((SDK / "receipt-v3/registry.json").read_bytes())
    expected = {section: source[section] for section in SECTIONS}
    python_expected = {
        **expected,
        "objects": {
            name: {
                field: [spec["type"], spec["required"]]
                for field, spec in shape.items()
            }
            for name, shape in expected["objects"].items()
        },
    }
    copies = {
        "Rust": (SDK / "verifiers/rust/src/v3/registry.json", expected),
        "TypeScript": (args.typescript_registry, expected),
        "Python": (
            files("pipelock_aarp_verify.v3").joinpath("registry.json"),
            python_expected,
        ),
    }
    for language, (path, want) in copies.items():
        actual = json.loads(path.read_bytes())
        changed = [
            key
            for key in sorted(actual.keys() | want.keys())
            if key not in actual or key not in want or actual[key] != want[key]
        ]
        if changed:
            raise SystemExit(f"{language} receipt v3 registry drift: {', '.join(changed)}")
        print(f"{language} receipt v3 registry matches")


if __name__ == "__main__":
    main()
