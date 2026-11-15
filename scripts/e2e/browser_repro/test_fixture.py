# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.parse
import urllib.request

import math
import shutil
import ssl

from fixture import CANARY, HOST, Fixture, generated_bundle, write_fixtures
from run import Cancellation, Process, browser_flags, config_for, isolated_environment, write_json
import tls_resource


class FixtureTests(unittest.TestCase):
    def test_bundle_is_deterministic_generated_and_marker_is_opt_in(self):
        body = generated_bundle(4096)
        self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(generated_bundle(4096)).digest())
        self.assertGreaterEqual(len(body), 4096)
        self.assertLess(len(body), 4200)
        self.assertIn(b"function fixtureRow", body)
        self.assertIn(b"window.fixture", body)
        self.assertNotIn(b"BROWSER_REPRO_RESPONSE_MARKER", body)
        self.assertEqual(generated_bundle(4096, marker=True), body+b"\n/* BROWSER_REPRO_RESPONSE_MARKER */\n")
        for size in (0, 4095, 8_000_001):
            with self.assertRaises(ValueError):
                generated_bundle(size)

    def test_frozen_fixtures_match_manifest_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixtures"
            manifest = write_fixtures(output, 4096)
            for name, expected in manifest.items():
                path = output / name
                body = path.read_bytes()
                self.assertEqual(expected, {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((output / "generated-fixtures.json").read_text()), manifest)
            with self.assertRaises(FileExistsError):
                write_fixtures(output, 4096)

    def test_real_fixture_routes_and_auth(self):
        with Fixture(4096, delay=0) as fixture:
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            connection.request("GET", "/account")
            response = connection.getresponse()
            self.assertEqual(response.status, 303)
            self.assertEqual(response.headers["Location"], "/login")
            response.read()
            connection.request("GET", "/account", headers={"Cookie": "fixture_session=synthetic-extra"})
            response = connection.getresponse()
            self.assertEqual(response.status, 303)
            response.read()
            connection.request("POST", "/session", "user=fixture&code=wrong")
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            connection.request("POST", "/session", "user=fixture&code=fixture-only")
            response = connection.getresponse()
            self.assertEqual(response.status, 303)
            cookie = response.headers["Set-Cookie"]
            self.assertIn("HttpOnly", cookie)
            self.assertIn("Max-Age=3600", cookie)
            response.read()
            connection.request("GET", "/account", headers={"Cookie": cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn(b"Synthetic browser fixture", response.read())
            connection.request("GET", "/bundle.js")
            response = connection.getresponse()
            self.assertEqual(response.headers.get_all("Cache-Control"), ["public, max-age=3600"])
            self.assertEqual(response.read(), generated_bundle(4096))
            connection.request("GET", "/api/data?scenario=error")
            response = connection.getresponse()
            self.assertEqual(response.status, 503)
            self.assertIn("error", json.loads(response.read()))
            connection.request("GET", "/api/data?scenario=incomplete")
            response = connection.getresponse()
            with self.assertRaises(http.client.IncompleteRead):
                response.read()
            connection.close()
            self.assertEqual(fixture.evidence()["auth_counts"], {
                "session_submissions": 2, "session_rejections": 1,
                "session_acceptances": 1, "account_authenticated": 1,
                "account_login_required": 2,
            })

    def test_route_evidence_does_not_store_queries_and_is_bounded(self):
        with Fixture(4096, delay=0) as fixture:
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            for index in range(40):
                connection.request("GET", f"/unknown-{index}?private=do-not-record")
                connection.getresponse().read()
            connection.close()
            evidence = fixture.evidence()
            self.assertEqual(evidence["counts"], {"other": 40})
            self.assertEqual(len(evidence["routes"]["other"]), 32)
            self.assertNotIn("private", json.dumps(evidence))

    def test_session_rejects_invalid_framing_and_closes_connection(self):
        cases = [([], 411), ([("Content-Length", "1025")], 413),
                 ([("Content-Length", "9" * 5000)], 413),
                 ([("Content-Length", "0"), ("Content-Length", "0")], 400),
                 ([("Transfer-Encoding", "chunked")], 400),
                 ([("Transfer-Encoding", "identity"), ("Content-Length", "0")], 400)]
        cases.extend(([("Content-Length", value)], 400)
                     for value in ("-1", "+1", "", "1.5", "1,1", "invalid", "\xb2", "\xa01"))
        with Fixture(4096, delay=0) as fixture:
            for headers, expected in cases:
                with self.subTest(headers=headers):
                    connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
                    try:
                        connection.putrequest("POST", "/session")
                        for name, value in headers:
                            connection.putheader(name, value)
                        connection.endheaders()
                        response = connection.getresponse()
                        self.assertEqual(response.status, expected)
                        self.assertEqual(response.headers["Connection"], "close")
                        self.assertEqual(response.read(), b"")
                    finally:
                        connection.close()
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            try:
                connection.request("GET", "/health")
                self.assertEqual(connection.getresponse().read(), b"fixture-ready")
            finally:
                connection.close()
            self.assertEqual(fixture.evidence()["auth_counts"], {"session_submissions": len(cases)})

    def test_session_body_bounds_and_encoding_use_real_http(self):
        with Fixture(4096, delay=0) as fixture:
            for body, length, expected in ((b"", "0", 401), (b"x" * 1024, "1024", 401),
                                          (b"\xff", "1", 400), (b"user=%FF", "8", 400),
                                          (b"user=fixture&code=fixture-only", "00030", 303)):
                with self.subTest(length=length, expected=expected):
                    connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
                    try:
                        connection.request("POST", "/session", body, {"Content-Length": length})
                        response = connection.getresponse()
                        self.assertEqual(response.status, expected)
                        response.read()
                    finally:
                        connection.close()
            with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as connection:
                connection.sendall(b"POST /session HTTP/1.1\r\nHost: fixture\r\nContent-Length: 2\r\n\r\nx")
                connection.shutdown(socket.SHUT_WR)
                response = http.client.HTTPResponse(connection)
                response.begin()
                self.assertEqual(response.status, 400)
                self.assertEqual(response.headers["Connection"], "close")
                response.read()
                response.close()

    def test_unknown_post_closes_connection_with_unread_body(self):
        with Fixture(4096, delay=0) as fixture:
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            try:
                connection.request("POST", "/missing", b"generated-body")
                response = connection.getresponse()
                self.assertEqual(response.status, 404)
                self.assertEqual(response.headers["Connection"], "close")
                response.read()
            finally:
                connection.close()
            self.assertEqual(fixture.evidence()["auth_counts"], {})

    def test_handler_launch_failure_releases_its_slot_and_shutdown_tolerates_closed_socket(self):
        with patch("fixture.MAX_HANDLERS", 1):
            fixture = Fixture(4096, delay=0)
        connection = socket.socket()
        try:
            with patch("fixture.ThreadingHTTPServer.process_request", side_effect=RuntimeError("synthetic launch failure")), \
                    self.assertRaisesRegex(RuntimeError, "synthetic launch failure"):
                fixture.server.process_request(connection, ("127.0.0.1", 0))
            self.assertFalse(fixture.server.connections)
            self.assertTrue(fixture.server.slots.acquire(blocking=False))
            self.assertFalse(fixture.server.slots.acquire(blocking=False))
            fixture.server.slots.release()
            connection.close()
            # Model the race where an admitted handler closes its own socket
            # after server_close takes its connection snapshot.
            fixture.server.connections.add(connection)
        finally:
            connection.close()
            fixture.server.server_close()
            fixture.server.connections.discard(connection)

    def test_request_disconnect_is_quiet_and_retires_handler(self):
        with Fixture(4096, delay=0) as fixture:
            with patch("fixture.BaseHTTPRequestHandler.handle", side_effect=ConnectionResetError("synthetic disconnect")):
                with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as connection:
                    self.assertEqual(connection.recv(1), b"")
        self.assertFalse(fixture.server.connections)

    def test_idle_and_incomplete_requests_timeout_without_holding_handlers(self):
        with patch("fixture.REQUEST_TIMEOUT_SECONDS", 0.1), Fixture(4096, delay=0) as fixture:
            with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as connection:
                connection.sendall(b"GET /health HTTP/1.1\r\n")
                self.assertEqual(connection.recv(1), b"")
            with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as connection:
                connection.sendall(b"POST /session HTTP/1.1\r\nHost: fixture\r\nContent-Length: 1\r\n\r\n")
                response = http.client.HTTPResponse(connection)
                response.begin()
                self.assertEqual(response.status, 408)
                self.assertEqual(response.headers["Connection"], "close")
                response.read()
                response.close()
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            try:
                connection.request("GET", "/health")
                self.assertEqual(connection.getresponse().read(), b"fixture-ready")
            finally:
                connection.close()

    def test_handler_admission_is_bounded_and_recovers_after_release(self):
        connections = []
        with patch("fixture.MAX_HANDLERS", 2), Fixture(4096, delay=0) as fixture:
            try:
                for _ in range(2):
                    connection = socket.create_connection(("127.0.0.1", fixture.port), timeout=2)
                    connections.append(connection)
                    connection.sendall(b"GET /api/data?scenario=pending HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
                deadline = time.monotonic() + 2
                while fixture.evidence()["scenario_counts"].get("pending") != 2:
                    self.assertLess(time.monotonic(), deadline, "owned pending handlers did not start")
                    threading.Event().wait(0.01)
                with fixture.server.connection_lock:
                    self.assertEqual(len(fixture.server.connections), 2)
                with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as rejected:
                    self.assertEqual(rejected.recv(1), b"")
                fixture.stop.set()
                for connection in connections:
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read()), {"message": "generated data complete"})
                    response.close()
                deadline = time.monotonic() + 2
                while True:
                    with fixture.server.connection_lock:
                        if not fixture.server.connections:
                            break
                    self.assertLess(time.monotonic(), deadline, "owned handlers did not retire")
                    threading.Event().wait(0.01)
                connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
                try:
                    connection.request("GET", "/health")
                    self.assertEqual(connection.getresponse().read(), b"fixture-ready")
                finally:
                    connection.close()
            finally:
                fixture.stop.set()
                for connection in connections:
                    connection.close()
        self.assertFalse(fixture.thread.is_alive())
        self.assertFalse(fixture.server.connections)

    def test_shutdown_closes_an_idle_keepalive_connection(self):
        with Fixture(4096, delay=0) as fixture:
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            try:
                connection.request("GET", "/health")
                self.assertEqual(connection.getresponse().read(), b"fixture-ready")
                owned_socket = connection.sock
            except BaseException:
                connection.close()
                raise
        try:
            self.assertEqual(owned_socket.recv(1), b"")
            self.assertFalse(fixture.server.connections)
            self.assertFalse(fixture.thread.is_alive())
        finally:
            connection.close()

    def test_configuration_preserves_defaults_and_limits_fixture_trust(self):
        config = config_for()
        self.assertEqual(config["mode"], "strict")
        self.assertEqual(config["api_allowlist"], [HOST])
        self.assertEqual(config["trusted_domains"], [HOST])
        self.assertEqual(config["response_scanning"], {"enabled": True, "action": "block"})
        self.assertNotIn("patterns", config["response_scanning"])
        self.assertNotIn("dlp", config)
        self.assertNotIn("ssrf", config)
        self.assertNotIn("sandbox", config)
        self.assertEqual(config["canary_tokens"]["tokens"][0]["value"], CANARY)

    @unittest.skipUnless(Path(f"/proc/self/task/{os.getpid()}/children").is_file(), "procfs children enumeration unavailable; cannot verify process cleanup")
    def test_both_output_pipes_are_drained_beyond_retention_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = isolated_environment(root)
            command = [sys.executable, "-c", "import os; os.write(1,b'o'*200000); os.write(2,b'e'*200000)"]
            process = Process(command, root / "flood", env, root)
            try:
                self.assertEqual(process.wait(10), 0)
            finally:
                result = process.stop()
            for name in ("stdout", "stderr"):
                self.assertEqual(result["streams"][name]["total_bytes"], 200000)
                self.assertEqual(result["streams"][name]["retained_bytes"], 65536)
                self.assertTrue(result["streams"][name]["truncated"])
            self.assertTrue(result["cleanup"]["cleanup_complete"])

    def test_drain_distinguishes_read_error_from_eof(self):
        process = Process.__new__(Process)
        process.output_lock = threading.Lock()
        process.buffers = {"stdout": bytearray()}
        process.counts = {"stdout": 0}
        process.eof = {"stdout": False}
        process.read_errors = {}
        stream = Mock()
        stream.read1.side_effect = [b"kept", OSError("synthetic read failure")]
        process.process = Mock(stdout=stream)
        process.drain("stdout")
        self.assertFalse(process.eof["stdout"])
        self.assertIn("synthetic read failure", process.read_errors["stdout"])
        self.assertEqual(process.buffers["stdout"], b"kept")

    def test_cleanup_witness_and_explicit_eof_are_required(self):
        for complete, unexpected, eof in ((False, False, True), (True, True, True), (True, False, False), (True, False, True)):
            with self.subTest(complete=complete, unexpected=unexpected, eof=eof), tempfile.TemporaryDirectory() as temporary:
                process = Process.__new__(Process)
                process.output = Path(temporary) / "child"
                process.output_lock = threading.Lock()
                process.process = Mock(returncode=0)
                process.process.poll.return_value = 0
                process.threads = []
                process.buffers = {"stdout": bytearray(b"synthetic"), "stderr": bytearray()}
                process.counts = {"stdout": 9, "stderr": 0}
                process.eof = {"stdout": eof, "stderr": eof}
                process.read_errors = {}
                write_json(process.output.with_suffix(".cleanup.json"), {"cleanup_complete": complete, "unexpected_live_descendants": unexpected})
                if complete and not unexpected and eof:
                    self.assertTrue(process.stop()["streams_drained"])
                else:
                    with self.assertRaises(RuntimeError):
                        process.stop()

    def test_process_refuses_missing_cleanup_facility(self):
        with patch("run.Path.is_file", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "procfs children file is absent"):
                Process(["unused"], Path("unused"), {}, Path("."))

    def test_cancellation_waits_for_safe_checkpoint_and_restores_handlers(self):
        cancellation = Cancellation()
        previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        cancellation.install()
        try:
            cancellation.interrupted(signal.SIGTERM, None)
            cancellation.interrupted(signal.SIGINT, None)
            self.assertEqual(cancellation.signum, signal.SIGTERM)
            process = Process.__new__(Process)
            process.cancellation = cancellation
            process.command = ["synthetic"]
            process.process = Mock()
            with self.assertRaisesRegex(RuntimeError, "runner interrupted"):
                process.wait(10)
            process.process.wait.assert_not_called()
            with patch("run.subprocess.Popen") as launch:
                with self.assertRaisesRegex(RuntimeError, "runner interrupted"):
                    Process(["unused"], Path("unused"), {}, Path("."), cancellation)
                launch.assert_not_called()
        finally:
            cancellation.restore()
        self.assertEqual(previous, {signum: signal.getsignal(signum) for signum in previous})

    def test_wait_retains_deadline_and_normal_exit(self):
        process = Process.__new__(Process)
        process.cancellation = Cancellation()
        process.command = ["synthetic"]
        process.process = Mock()
        process.process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 0.1), 7]
        self.assertEqual(process.wait(10), 7)
        with self.assertRaises(subprocess.TimeoutExpired):
            process.wait(0)

    @unittest.skipUnless(Path(f"/proc/self/task/{os.getpid()}/children").is_file(), "procfs children enumeration unavailable; cannot verify cancellation cleanup")
    def test_external_cancellation_reaps_supervised_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = """
import signal, sys, threading, time
from pathlib import Path
from run import Cancellation, Process, isolated_environment, write_json
root = Path(sys.argv[1])
cancellation = Cancellation()
cancellation.install()
process = None
try:
    process = Process([sys.executable, '-c', "import os, signal; os.write(1, b'r'*8192); signal.pause()"], root / 'child', isolated_environment(root), root, cancellation)
    deadline = time.monotonic() + 5
    while process.counts['stdout'] < 8192:
        cancellation.check()
        if process.process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError('synthetic child readiness absent')
        threading.Event().wait(0.01)
    print('ready', flush=True)
    process.wait(30)
except RuntimeError:
    pass
finally:
    if process:
        write_json(root / 'result.json', process.stop())
    cancellation.restore()
"""
            runner = subprocess.Popen([sys.executable, "-c", script, str(root)], cwd=Path(__file__).parent,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                import selectors
                with selectors.DefaultSelector() as selector:
                    selector.register(runner.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), "synthetic runner did not become ready")
                self.assertEqual(runner.stdout.readline().strip(), "ready")
                runner.send_signal(signal.SIGTERM)
                _out, errors = runner.communicate(timeout=12)
                self.assertEqual(runner.returncode, 0, errors)
                result = json.loads((root / "result.json").read_text())
                self.assertTrue(result["cleanup"]["cleanup_complete"])
                self.assertFalse(result["cleanup"]["unexpected_live_descendants"])
                self.assertTrue(result["streams_drained"])
            finally:
                if runner.poll() is None:
                    runner.send_signal(signal.SIGTERM)
                    runner.communicate(timeout=12)

    def test_environment_is_not_copied_and_outputs_are_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = isolated_environment(root)
            self.assertEqual(set(env), {"PATH", "LANG", "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "TMPDIR", "PIPELOCK_POSTURE_PROOF"})
            self.assertTrue(Path(env["HOME"]).is_dir())
            path = root / "result.json"
            write_json(path, {"status": "pending"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), {"status": "pending"})


def shannon(text):
    return -sum(text.count(char) / len(text) * math.log2(text.count(char) / len(text)) for char in set(text))


def receipt_line(extension="declared_resource_path", target=None, verdict="allow", actor=tls_resource.AGENT,
                 method="GET", layer="entropy_issuer_query_allow", key="a" * 64):
    return json.dumps({"v": 2, "type": "action_receipt", "detail": {
        "action_record": {"target": target, "verdict": verdict, "actor": actor, "method": method, "layer": layer},
        "signer_key": key, "ext": {"entropy_issuer_query_allow": extension}}})


class TLSConfigTests(unittest.TestCase):
    def config(self):
        return tls_resource.tls_config(1, "/w/ca.pem", "/w/ca-key.pem", "/w/rec", "/w/key")

    def test_only_exact_destinations_and_enforcing_actions_are_configured(self):
        config = self.config()
        self.assertEqual(config["mode"], "strict")
        self.assertEqual(config["api_allowlist"], list(tls_resource.HOSTS))
        self.assertEqual(config["trusted_domains"], list(tls_resource.HOSTS))
        self.assertEqual(config["dns"]["host_overrides"], {host: ["127.0.0.1"] for host in tls_resource.HOSTS})
        self.assertEqual(config["default_agent_identity"], tls_resource.AGENT)
        self.assertNotIn("bind_default_agent_identity", config)
        self.assertEqual(config["request_body_scanning"], {"enabled": True, "action": "block", "scan_headers": True,
                                                           "issuer_bound_session_cookies": True})
        self.assertEqual(config["response_scanning"], {"enabled": True, "action": "block"})
        self.assertTrue(config["tls_interception"]["enabled"])
        self.assertTrue(config["flight_recorder"]["enabled"])

    def test_no_entropy_exemption_rate_budget_ip_or_scanner_relaxation_is_manufactured(self):
        config = self.config()
        self.assertEqual(set(config), {"mode", "api_allowlist", "trusted_domains", "default_agent_identity", "dns",
                                       "forward_proxy", "tls_interception", "request_body_scanning", "response_scanning",
                                       "canary_tokens", "flight_recorder", "logging"})
        rendered = json.dumps(config).lower()
        for forbidden in ("exclusion", "exempt", "allowlist_ip", "ip_allowlist", "internal", "rate", "budget", "threshold",
                          "disable", "passthrough", "warn"):
            self.assertNotIn(forbidden, rendered.replace("api_allowlist", ""), forbidden)
        self.assertEqual(config["forward_proxy"], {"enabled": True})
        self.assertEqual(config["tls_interception"].keys(), {"enabled", "ca_cert", "ca_key"})

    def test_browser_flags_never_weaken_tls_and_http2_is_only_dropped_by_explicit_diagnostic(self):
        default = browser_flags()
        self.assertEqual(default, ("--disable-quic",))
        self.assertEqual(browser_flags(http1=True), ("--disable-quic", "--disable-http2"))
        for flags in (default, browser_flags(True)):
            for flag in flags:
                self.assertNotIn("certificate", flag)
                self.assertNotIn("insecure", flag)
                self.assertNotIn("spki", flag)

    def test_declared_paths_are_stable_distinct_high_entropy_and_not_trimmed_hashes(self):
        paths = tls_resource.resource_paths()
        self.assertEqual(paths, tls_resource.resource_paths())
        self.assertEqual(len(set(paths.values())), 5)
        for path in paths.values():
            segment = path.rsplit("/", 1)[1]
            stem = segment.rsplit(".", 1)[0]
            self.assertEqual(len(stem), 86)
            self.assertGreater(shannon(stem), 4.5)
        self.assertEqual(tls_resource.token("script"), tls_resource.token("script"))
        self.assertNotEqual(tls_resource.token("script"), tls_resource.token("style"))


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for generated upstream certificates")
class TLSFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pki = tls_resource.generate_upstream_pki(self.root / "upstream")

    def get(self, fixture, host, path, method="GET", body=None, cafile=None, hostname=None):
        context = ssl.create_default_context(cafile=str(cafile or self.pki["ca"]))
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=hostname or host) as secured:
                headers = f"{method} {path} HTTP/1.1\r\nHost: {host}:{fixture.port}\r\nConnection: close\r\n"
                if body is not None:
                    headers += f"Content-Length: {len(body)}\r\n"
                secured.sendall(headers.encode() + b"\r\n" + (body or b""))
                data = b""
                while chunk := secured.recv(65536):
                    data += chunk
        head, _, payload = data.partition(b"\r\n\r\n")
        return int(head.split(b" ", 2)[1]), payload

    def test_pki_is_private_workspace_local_and_never_overwritten(self):
        for path in self.pki.values():
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(path.resolve().is_relative_to(self.root.resolve()))
        with self.assertRaises(FileExistsError):
            tls_resource.generate_upstream_pki(self.root / "upstream")

    def test_origins_serve_exact_declared_resources_and_label_only_evidence(self):
        paths = tls_resource.resource_paths()
        with tls_resource.TLSResourceFixture(self.pki) as fixture:
            status, page = self.get(fixture, tls_resource.A_HOST, "/")
            self.assertEqual(status, 200)
            cdn = f"https://{tls_resource.B_HOST}:{fixture.port}".encode()
            for kind in ("script", "style", "image"):
                self.assertIn(cdn + paths[kind].encode(), page)
            # The page itself declares the third origin's independent root, never the onward path.
            self.assertIn(f"https://{tls_resource.C_HOST}:{fixture.port}{paths['root']}".encode(), page)
            self.assertNotIn(paths["third"].encode(), page)
            status, script = self.get(fixture, tls_resource.B_HOST, paths["script"])
            self.assertEqual((status, b"scriptRan" in script), (200, True))
            status, style = self.get(fixture, tls_resource.B_HOST, paths["style"])
            self.assertEqual(status, 200)
            self.assertIn(f"https://{tls_resource.C_HOST}:{fixture.port}{paths['third']}".encode(), style)
            status, image = self.get(fixture, tls_resource.B_HOST, paths["image"])
            self.assertEqual((status, image[:8]), (200, b"\x89PNG\r\n\x1a\n"))
            self.assertEqual(self.get(fixture, tls_resource.C_HOST, paths["third"])[0], 200)
            self.assertEqual(self.get(fixture, tls_resource.C_HOST, paths["root"])[0], 200)
            self.assertEqual(self.get(fixture, tls_resource.A_HOST, "/favicon.ico")[0], 404)
            evidence = fixture.evidence()
        self.assertEqual(evidence["counts"], {"a:/": 1, "b:script": 1, "b:style": 1, "b:image": 1, "c:third": 1, "c:root": 1, "a:favicon": 1})
        rendered = json.dumps(evidence)
        self.assertNotIn("assets", rendered)
        for kind in paths.values():
            self.assertNotIn(kind, rendered)

    def test_altered_wrong_host_query_and_post_arrivals_are_counted_as_other_or_post(self):
        paths = tls_resource.resource_paths()
        altered = paths["script"][:-4] + "Z.js"
        with tls_resource.TLSResourceFixture(self.pki) as fixture:
            self.assertEqual(self.get(fixture, tls_resource.B_HOST, altered)[0], 404)
            self.assertEqual(self.get(fixture, tls_resource.A_HOST, paths["script"])[0], 404)
            self.assertEqual(self.get(fixture, tls_resource.C_HOST, paths["script"])[0], 404)
            # A query still reaches the same exact route; the proxy, not the fixture, refuses it.
            self.assertEqual(self.get(fixture, tls_resource.B_HOST, paths["script"] + "?v=1")[0], 200)
            self.assertEqual(self.get(fixture, tls_resource.B_HOST, paths["script"], "POST", b"x=1")[0], 200)
            counts = fixture.evidence()["counts"]
        self.assertEqual(counts, {"other": 3, "b:script": 1, "post": 1})

    def test_certificate_verification_is_real_for_name_and_authority(self):
        with tls_resource.TLSResourceFixture(self.pki) as fixture:
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.get(fixture, tls_resource.A_HOST, "/", hostname="unlisted.fixture.example")
            other = tls_resource.generate_upstream_pki(self.root / "other")
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.get(fixture, tls_resource.A_HOST, "/", cafile=other["ca"])
            self.assertEqual(tls_resource.tls_witness(fixture.port, self.pki["ca"]), "TLSv1.3")
            with self.assertRaises(ssl.SSLCertVerificationError):
                tls_resource.tls_witness(fixture.port, other["ca"])
            self.assertEqual(fixture.evidence()["counts"], {})

    def test_shutdown_releases_the_listener_and_retires_handlers(self):
        with tls_resource.TLSResourceFixture(self.pki) as fixture:
            port = fixture.port
            self.assertEqual(self.get(fixture, tls_resource.A_HOST, "/")[0], 200)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        self.assertFalse(fixture.thread.is_alive())
        self.assertEqual(fixture.server.connections, set())

    def test_failed_handshake_leaves_no_raw_log_or_arrival(self):
        with tls_resource.TLSResourceFixture(self.pki) as fixture:
            with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as raw:
                raw.sendall(b"GET / HTTP/1.1\r\nHost: page.fixture.example\r\n\r\n")
                raw.settimeout(3)
                try:
                    raw.recv(16)
                except OSError:
                    pass
            deadline = time.monotonic() + 3
            while fixture.server.connections and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(fixture.evidence()["counts"], {})
            self.assertEqual(fixture.server.connections, set())


class TLSAcceptanceTests(unittest.TestCase):
    PORT = 4443

    def good(self):
        origin = f"https://{tls_resource.B_HOST}:{self.PORT}"
        receipts = [{"target": origin, "verdict": "allow", "actor": tls_resource.AGENT, "method": "GET",
                     "layer": "entropy_issuer_query_allow"}] * 6
        receipts += [{**receipts[0], "target": f"https://{tls_resource.C_HOST}:{self.PORT}"}] * 2
        events = ([{"event": "entropy_issuer_query_allow", "agent": tls_resource.AGENT, "agent_auth": "config-default"}] * 8
                  + [{"event": "blocked", "url": f"{origin}/[redacted]", "agent": tls_resource.AGENT}] * 11
                  + [{"event": "blocked", "target": "www.google.com:443", "agent": tls_resource.AGENT}])
        return dict(port=self.PORT,
                    fixture={"counts": {"a:/": 1, "a:favicon": 1, "b:script": 2, "b:style": 2, "b:image": 2, "c:root": 2}},
                    receipts=receipts, other_kinds=["declared_resource_path"] * 8, events=events,
                    browser={"tls": {"denials": [{"name": str(index)} for index in range(11)]}})

    def failures(self, **changes):
        arguments = self.good()
        arguments.update(changes)
        return tls_resource.evaluate_acceptance(**arguments)

    def test_complete_join_passes_and_background_host_blocks_are_not_fixture_blocks(self):
        self.assertEqual(self.failures(), [])

    def test_blank_page_or_fewer_blocks_cannot_pass(self):
        # No declared resource ever arrived, no receipt, no allowance, fewer blocks.
        failures = self.failures(fixture={"counts": {"a:/": 1}}, receipts=[], other_kinds=[],
                                 events=[], browser={"tls": {"denials": [{}]}})
        joined = " ".join(failures)
        for name in ("b:script", "b:style", "b:image", "c:root"):
            self.assertIn(name, joined)
        # Fewer proxy blocks than the browser/probes observed is its own failure.
        arguments = self.good()
        arguments["events"] = [event for event in arguments["events"] if event.get("event") != "blocked"]
        self.assertTrue(any("blocked events" in failure for failure in tls_resource.evaluate_acceptance(**arguments)))

    def test_denied_traffic_reaching_the_origin_fails(self):
        for label in ("c:third", "other", "post"):
            counts = {**self.good()["fixture"]["counts"], label: 1}
            self.assertTrue(any(label in failure for failure in self.failures(fixture={"counts": counts})), label)

    def test_receipts_must_equal_arrivals_and_name_the_exact_origin_identity_and_rule(self):
        arguments = self.good()
        self.assertTrue(any("differ from CDN arrivals" in f for f in self.failures(receipts=arguments["receipts"][:-1])))
        for field, value in (("target", "https://cdn.fixture.example:1"), ("verdict", "block"),
                             ("actor", "someone"), ("method", "POST"), ("layer", "other")):
            changed = [{**arguments["receipts"][0], field: value}] + arguments["receipts"][1:]
            self.assertTrue(any("unexpected target" in f for f in self.failures(receipts=changed)), field)
        self.assertTrue(any("other than declared_resource_path" in f for f in
                            self.failures(other_kinds=["declared_resource_path"] * 7 + ["observed_issuer"])))

    def test_audit_allowances_and_identity_grade_must_match(self):
        arguments = self.good()
        short = [event for event in arguments["events"] if event.get("event") != "entropy_issuer_query_allow"][:]
        self.assertTrue(any("audit allowances" in f for f in self.failures(events=short)))
        weak = [{**event, "agent_auth": "self-declared"} if event.get("event") == "entropy_issuer_query_allow" else event
                for event in arguments["events"]]
        self.assertTrue(any("default identity" in f for f in self.failures(events=weak)))
        stranger = [{**event, "agent": "anonymous"} if event.get("event") == "blocked" else event for event in arguments["events"]]
        self.assertTrue(any("block was not attributed" in f for f in self.failures(events=stranger)))

    def test_missing_browser_observations_fail(self):
        self.assertTrue(any("no TLS scenario observations" in f for f in self.failures(browser={})))
        self.assertTrue(any("no TLS scenario observations" in f for f in self.failures(browser=None)))
        self.assertTrue(any("blocked events" in f for f in self.failures(browser={"tls": {"denials": "ten"}})))

    def test_receipt_and_event_parsers_read_structure_and_ignore_malformed_input(self):
        target = f"https://{tls_resource.B_HOST}:9"
        lines = [receipt_line(target=target), receipt_line(extension="observed_issuer", target=target), "not json", "{}",
                 json.dumps({"detail": []}), json.dumps({"detail": {"action_record": {}, "ext": {"x": 1}}}),
                 json.dumps({"note": "declared_resource_path"})]
        found = tls_resource.declared_resource_receipts(lines)
        self.assertEqual(found, [{"target": target, "verdict": "allow", "actor": tls_resource.AGENT, "method": "GET",
                                  "layer": "entropy_issuer_query_allow"}])
        self.assertEqual(tls_resource.all_issuer_allow_kinds(lines), ["declared_resource_path", "observed_issuer"])
        self.assertEqual(tls_resource.receipt_signers(lines + [receipt_line(key="b" * 64), receipt_line(key="nothex")]),
                         ["a" * 64, "b" * 64])
        stdout = '{"event":"blocked"}\nplain text\n[1]\n{"event":"startup"}\n'
        self.assertEqual([event["event"] for event in tls_resource.proxy_events(stdout)], ["blocked", "startup"])
        self.assertEqual(tls_resource.event_host({"url": "https://cdn.fixture.example:443/[redacted]"}), "cdn.fixture.example")
        self.assertEqual(tls_resource.event_host({"target": "www.google.com:443"}), "www.google.com")
        self.assertEqual(tls_resource.event_host({"url": 7}), "")


if __name__ == "__main__":
    unittest.main()
