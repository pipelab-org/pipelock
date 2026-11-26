# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

from receipt_v3_gate import LANES, request_flags

GATE = Path(__file__).with_name("receipt-v3-gate.sh").resolve()
FAKE = """\
import sys

assert sys.argv[2] == "v3"
mode, _, *args = sys.argv[1:]
if args[0] == "--claims":
    print("false")
elif args[1] == "projection":
    print('{"exit_code":3}', end="" if mode == "projection" else "\\n")
    sys.exit(3)
elif mode == "order":
    print('{"first":"' + args[3].rsplit("/", 1)[1] + '"}')
    sys.exit(3)
else:
    print('{"exit_code":3}')
    sys.exit(2 if mode == "status" else 3)
"""


class ReceiptV3GateTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.command = self.root / "fake verifier.py"
        self.command.write_text(FAKE, encoding="utf-8")
        for name, legacy in (("scope", False), ("legacy", True)):
            vector = self.root / name
            vector.mkdir()
            inputs = ["a.jsonl"] if legacy else ["a.jsonl", "b.jsonl", "c.jsonl"]
            for input_name in inputs:
                (vector / input_name).touch()
            (vector / "request.json").write_text(
                json.dumps({"inputs": inputs, "legacy": legacy}), encoding="utf-8"
            )
            for filename in ("projection.json", "expect.json"):
                (vector / filename).write_bytes(b'{"exit_code":3}\n')

    def run_gate(self, mode, all_required=False, lane="GO_V3"):
        env = {key: value for key, value in os.environ.items() if key not in LANES}
        env[lane] = shlex.join((sys.executable, str(self.command), mode))
        env["REQUIRE_ALL_LANES"] = str(int(all_required))
        return subprocess.run(
            ["bash", GATE, "--corpus", self.root],
            env=env, capture_output=True, check=False, text=True, timeout=30,
        )

    def test_mutated_projection_and_file_order_fail(self):
        for mode, status, output in (
            ("valid", 0, "GO_V3: PASS 2/2 vectors"),
            ("projection", 1, "projection bytes differ"),
            ("order", 1, "reversed full result bytes differ"),
            ("status", 1, "exit 2, expected 3"),
        ):
            with self.subTest(mode=mode):
                proc = self.run_gate(mode)
                self.assertEqual(proc.returncode, status, proc.stderr)
                self.assertIn(output, proc.stdout + proc.stderr)

    def test_core_lane_uses_core_projection(self):
        (self.root / "scope/projection.core.json").write_bytes(b'{"exit_code":3,"core":true}\n')
        full = self.run_gate("valid", lane="GO_V3")
        self.assertEqual(full.returncode, 0, full.stderr)
        core = self.run_gate("valid", lane="TS_V3")
        self.assertEqual(core.returncode, 1)
        self.assertIn("projection bytes differ", core.stderr)
    def test_core_projection_cannot_turn_a_rejection_into_success(self):
        (self.root / "scope/projection.core.json").write_bytes(b'{"exit_code":0}\n')
        proc = self.run_gate("valid", lane="TS_V3")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("core projection turns a rejection into success", proc.stderr)
    def test_browser_lane_checks_document_order(self):
        matching = self.run_gate("valid", lane="WASM_V3")
        self.assertEqual(matching.returncode, 0, matching.stderr)
        self.assertIn("WASM_V3: PASS 2/2", matching.stdout)
        reordered = self.run_gate("order", lane="WASM_V3")
        self.assertEqual(reordered.returncode, 1)
        self.assertIn("WASM_V3 scope: reversed full result bytes differ", reordered.stderr)

    def test_path_cannot_escape_vector(self):
        (self.root / "scope/request.json").write_text(
            json.dumps({"inputs": ["../outside"], "directory": True}), encoding="utf-8"
        )
        proc = self.run_gate("valid")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("invalid corpus input path", proc.stderr)
        self.assertFalse((self.root / "outside").exists())

    def test_required_lane(self):
        proc = self.run_gate("valid", all_required=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("WASM_V3: SKIPPED", proc.stdout)

    def test_request_options(self):
        self.assertEqual(
            request_flags({
                "keys": ["a", "b"],
                "accept_discontinuities": ["record"],
                "allow_partial_histories": ["stream"],
                "expect_heads": ["head"],
                "expect_sequences": ["seq"],
                "expect_lineage": "lineage",
                "format": "v3",
                "allow_unpinned": True,
                "allow_prefix": True,
            }),
            ["--key", "a", "--key", "b", "--accept-discontinuity", "record",
             "--allow-partial-history", "stream", "--expect-head", "head",
             "--expect-seq", "seq", "--expect-lineage", "lineage", "--format", "v3",
             "--allow-unpinned", "--allow-prefix"],
        )


if __name__ == "__main__":
    unittest.main()
