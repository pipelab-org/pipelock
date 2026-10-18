#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Finite verification requests must finish even when their peer stays silent."""

from pathlib import Path
import re
import shlex
import socket
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ShellHTTPDeadlineTests(unittest.TestCase):
    def test_unavailable_webhook_is_not_reported_as_no_blocked_events(self):
        source = (ROOT / "examples/siem-events/verify.sh").read_text()
        check = source.split("sleep 0.3\n", 1)[1].split("# -- Test 4", 1)[0]
        for result in ("return 28", "printf invalid-json", "printf '[]'",
                       "printf '[{\"type\":\"blocked\"}]'"):
            with self.subTest(result=result):
                script = ("set -euo pipefail\nWEBHOOK_ADDR=unused\n"
                          f"curl() {{ {result}; }}\n"
                          "pass() { echo PASS; }\nfail() { echo FAIL; }\n" + check)
                run = subprocess.run(
                    ["bash", "-c", script], capture_output=True, text=True,
                    timeout=4, check=False,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout.strip(),
                                 "PASS" if result == "printf '[]'" else "FAIL")

    def test_example_health_polls_bound_each_attempt(self):
        for example in ("websocket-proxy", "kill-switch", "siem-events",
                        "fetch-proxy-ssrf", "docker-compose-proxy"):
            with self.subTest(example=example), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                port = listener.getsockname()[1]
                source = (ROOT / "examples" / example / "verify.sh").read_text()
                function = re.search(
                    r"^wait_for_health\(\) \{.*?^\}$", source, re.M | re.S
                ).group()
                # Run one real attempt rather than repeating the same dead peer
                # for every iteration in the example's startup budget.
                script = ('seq() { printf "1\\n"; }\n'
                          f'PIPELOCK_PROXY_URL=http://127.0.0.1:{port}\n'
                          + function + f"\nwait_for_health {port}")
                result = subprocess.run(
                    ["bash", "-c", script], capture_output=True, text=True,
                    timeout=4, check=False,
                )
                self.assertEqual(result.returncode, 1, result.stderr)

    def test_release_registry_requests_bound_a_silent_peer(self):
        source = (ROOT / "scripts/release-verifier-install-gate.sh").read_text()
        commands = re.findall(
            r'"\$CI_RETRY" (curl [^\n]*?)\)"', source.replace("\\\n", "")
        )
        self.assertEqual(len(commands), 3)
        for command in commands:
            with self.subTest(command=command), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                args = shlex.split(command)
                self.assertTrue(args[-1].startswith("https://"))
                # Keep the shipped curl options, but use a local silent peer
                # instead of depending on the availability of a public registry.
                args[-1] = f"http://127.0.0.1:{listener.getsockname()[1]}/"
                result = subprocess.run(
                    args, capture_output=True, text=True, timeout=14, check=False,
                )
                self.assertEqual(result.returncode, 28, result.stderr)


if __name__ == "__main__":
    unittest.main()
