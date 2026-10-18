#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Exercise the config-example gate's probes without booting every example."""

import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")


class ConfigExampleProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "scripts/check-config-examples.sh").read_text()
        cls.initialization = source.split("PROBE_CONNECT_TIMEOUT=", 1)[1]
        cls.initialization = "PROBE_CONNECT_TIMEOUT=" + cls.initialization.split(
            "REPO_ROOT=", 1
        )[0]
        cls.functions = "\n".join(
            re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.M | re.S).group()
            for name in ("probe_exchange", "choose_port", "http_ready")
        )

    def run_probe(self, command, value=None, path=None):
        env = os.environ.copy()
        env.pop("CONFIG_EXAMPLES_CONNECT_TIMEOUT", None)
        if value is not None:
            env["CONFIG_EXAMPLES_CONNECT_TIMEOUT"] = value
        if path is not None:
            env["PATH"] = path
        return subprocess.run(
            [BASH, "-c", "set -euo pipefail\n" + self.initialization
             + self.functions + "\n" + command],
            env=env, capture_output=True, text=True, timeout=6, check=False,
        )

    def test_timeout_validation(self):
        for value in (None, "", "1", "2"):
            with self.subTest(value=value):
                result = self.run_probe('printf "%s" "$PROBE_CONNECT_TIMEOUT"', value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, value or "1")
        for value in ("0", "-1", "1.5", "01", "1s", "1+1",
                      "9223372036854775807", "18446744073709551615", "9" * 100):
            with self.subTest(value=value):
                result = self.run_probe("echo reached-probe", value)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("CONFIG_EXAMPLES_CONNECT_TIMEOUT", result.stderr)
                self.assertNotIn("reached-probe", result.stdout)

    def test_missing_timeout_fails_before_binary_or_fixture_setup(self):
        with tempfile.TemporaryDirectory() as empty_path:
            result = subprocess.run(
                [BASH, str(ROOT / "scripts/check-config-examples.sh"), "/absent"],
                env={**os.environ, "PATH": empty_path}, capture_output=True,
                text=True, timeout=6, check=False,
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("timeout command", result.stderr)
        self.assertNotIn("mktemp", result.stderr)

    def test_health_requires_a_response_and_accepts_a_live_peer(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            # A peer accepting TCP but never replying must fail readiness.
            result = self.run_probe(f"http_ready {port}")
            self.assertEqual(result.returncode, 1, result.stderr)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(5)
            port = listener.getsockname()[1]

            def respond():
                with listener.accept()[0] as connection:
                    connection.settimeout(5)
                    connection.recv(4096)
                    connection.sendall(b"HTTP/1.0 200 OK\r\n\r\n")

            server = threading.Thread(target=respond)
            server.start()
            try:
                result = self.run_probe(f"http_ready {port}")
                self.assertEqual(result.returncode, 0, result.stderr)
            finally:
                server.join(timeout=6)
            self.assertFalse(server.is_alive())


if __name__ == "__main__":
    unittest.main()
