# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""The receipt v3 installed-package command."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from ..input_file import _open_regular_input
from .verify import Options, claims_input, verify_paths
from .wire import canonical


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def run(argv: list[str]) -> int:
    parser = _Parser(prog="pipelock_aarp_verify v3", allow_abbrev=False)
    parser.add_argument("--key", action="append", default=[])
    parser.add_argument("--allow-unpinned", action="store_true")
    parser.add_argument("--allow-prefix", action="store_true")
    parser.add_argument("--accept-discontinuity", action="append", default=[])
    parser.add_argument("--allow-partial-history", action="append", default=[])
    parser.add_argument("--expect-lineage", default="")
    parser.add_argument("--expect-head", action="append", default=[])
    parser.add_argument("--expect-seq", action="append", default=[])
    parser.add_argument("--format", choices=("v3",))
    parser.add_argument("--output", choices=("result", "projection"))
    parser.add_argument("--claims", action="store_true")
    parser.add_argument("paths", nargs="*", type=Path)
    try:
        args = parser.parse_intermixed_args(argv)
        if args.claims:
            if len(args.paths) != 1 or any(
                (
                    args.key,
                    args.allow_unpinned,
                    args.allow_prefix,
                    args.accept_discontinuity,
                    args.allow_partial_history,
                    args.expect_lineage,
                    args.expect_head,
                    args.expect_seq,
                    args.format,
                    args.output,
                )
            ):
                raise ValueError(
                    "--claims requires exactly one file and no other options"
                )
            with _open_regular_input(args.paths[0]):
                pass
            sys.stdout.write("true\n" if claims_input(args.paths[0]) else "false\n")
            return 0
        directory = len(args.paths) == 1 and args.paths[0].is_dir()
        options = Options(
            keys=tuple(args.key),
            allow_unpinned=args.allow_unpinned,
            allow_prefix=args.allow_prefix,
            accept_discontinuities=tuple(args.accept_discontinuity),
            allow_partial_histories=tuple(args.allow_partial_history),
            expect_lineage=args.expect_lineage,
            expect_heads=tuple(args.expect_head),
            expect_sequences=tuple(args.expect_seq),
            directory=directory,
            explicit_v3=args.format == "v3",
        )
        result, projection = verify_paths(args.paths, options)
        sys.stdout.write(
            canonical(projection if args.output == "projection" else result).decode(
                "utf-8"
            )
            + "\n"
        )
        return result["exit_code"]
    except (OSError, ValueError, sqlite3.Error) as exc:
        sys.stderr.write(" ".join(str(exc).splitlines()) + "\n")
        return 2
    except SystemExit as exc:
        return int(exc.code or 0)
