# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-config-examples.sh"


class ConfigExampleFixtureContractTests(unittest.TestCase):
    def run_fixture_gate(self, keygen_mode: str) -> subprocess.CompletedProcess[str]:
        temp = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        fake = temp / "pipelock"
        fake.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = tls ] && [ "${2:-}" = init ]; then
    mkdir -p "$4"
    exit 0
fi
if [ "${1:-}" = signing ] && [ "${2:-}" = key ] && [ "${3:-}" = generate ]; then
    [ "$FAKE_KEYGEN_MODE" != fail ] || exit 9
    exit 0
fi
exit 97
""",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        env = os.environ.copy()
        env["HOME"] = str(temp / "home")
        env["FAKE_KEYGEN_MODE"] = keygen_mode
        return subprocess.run(
            ["bash", str(SCRIPT), str(fake)],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_recorder_key_uses_dedicated_lifecycle_command(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("signing key generate", source)
        self.assertIn("--purpose receipt-signing", source)
        self.assertNotIn('"$BIN" init --output "$WORK/keygen/', source)

    def test_missing_recorder_key_fails_the_gate(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        failure = 'echo "config-examples: could not fixture a recorder signing key" >&2'
        start = source.index(failure)
        self.assertIn("exit 1", source[start : start + 160])

    def test_key_generation_failure_fails_the_gate(self) -> None:
        result = self.run_fixture_gate("fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not fixture a recorder signing key", result.stderr)

    def test_empty_generated_key_fails_the_gate(self) -> None:
        result = self.run_fixture_gate("empty")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not fixture a recorder signing key", result.stderr)


class DoorRuntimeSkipTests(unittest.TestCase):
    REFUSAL = "mcp_door requires pipelock mcp proxy --listen; run does not support door mode"
    DOOR = "mcp_door:\n  enabled: true\n  mode: jwt\n"

    def reason(self, cfg: str, out: str, phase: str = "run") -> str:
        temp = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        (temp / "cfg.yaml").write_text(cfg, encoding="utf-8")
        (temp / "out.txt").write_text(out, encoding="utf-8")
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("environment_failure_reason() {")
        end = source.index("\n}\n", start) + 3
        program = (
            "enterprise_skip_allowed() { return 1; }\n"
            + source[start:end]
            + 'environment_failure_reason "$1" "$2" "$3"\n'
        )
        result = subprocess.run(
            ["bash", "-c", program, "probe", str(temp / "cfg.yaml"), str(temp / "out.txt"), phase],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_door_refusal_alone_is_skipped(self) -> None:
        self.assertEqual(
            self.reason(self.DOOR, self.REFUSAL + "\n"),
            "door configuration runs only under mcp proxy --listen",
        )

    def test_extra_startup_error_is_not_skipped(self) -> None:
        self.assertEqual(self.reason(self.DOOR, self.REFUSAL + "\nerror: listener bind failed\n"), "")

    def test_refusal_without_door_block_is_not_skipped(self) -> None:
        self.assertEqual(self.reason("mode: balanced\n", self.REFUSAL + "\n"), "")

    def test_check_phase_is_not_skipped(self) -> None:
        self.assertEqual(self.reason(self.DOOR, self.REFUSAL + "\n", phase="check"), "")

if __name__ == "__main__":
    unittest.main()
