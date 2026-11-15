# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Opt-in generated TLS/CDN scenario for the existing browser reproduction runner.

Three synthetic HTTPS origins share one loopback listener and are told apart by
host name only: a page origin (A), a CDN origin (B) that serves a hashed script,
stylesheet and image, and a third origin (C) that B's stylesheet names. The names
are mapped to loopback by Pipelock's own ``dns.host_overrides``. Nothing here
reaches the public Internet, loads a credential or edits a trust store: the
upstream certificates and the Pipelock CA live in the runner workspace.
"""

import hashlib
import base64
import json
from pathlib import Path
import shutil
import ssl
import struct
import subprocess
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit
import zlib

from fixture import CANARY, MAX_HANDLERS, REQUEST_TIMEOUT_SECONDS, BoundedHTTPServer

A_HOST = "page.fixture.example"
B_HOST = "cdn.fixture.example"
C_HOST = "third.fixture.example"
HOSTS = (A_HOST, B_HOST, C_HOST)
AGENT = "browser-repro-agent"
FIXTURE_CA_NAME = "pipelock-browser-repro-fixture-ca"
NSS_NICKNAME = "pipelock-browser-repro-ca"
IMAGE_SIDE = 64
# One short line per route label keeps evidence memory and rate use bounded.
ROUTES = ("a:/", "a:favicon", "b:script", "b:style", "b:image", "c:root", "c:third", "other", "post")


def token(label):
    """Two chained digests: a deterministic path segment no entropy score passes."""
    first = hashlib.sha256(f"browser-repro-tls:{label}".encode()).digest()
    second = hashlib.sha256(first).digest()
    return base64.urlsafe_b64encode(first + second).decode().rstrip("=")


def resource_paths():
    return {
        "script": f"/assets/{token('script')}.js",
        "style": f"/assets/{token('style')}.css",
        "image": f"/assets/{token('image')}.png",
        "third": f"/assets/{token('third')}.png",  # named only by B's stylesheet: onward, stays denied
        "root": f"/assets/{token('root')}.png",  # declared by the page itself: independent positive control
    }


def solid_png(side=IMAGE_SIDE, rgb=(0, 128, 0)):
    """A valid, visibly green PNG built with the standard library."""
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
    row = b"\x00" + bytes(rgb) * side
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(row * side)) + chunk(b"IEND", b""))


def filler(size):
    """Readable deterministic HTML comments, never a captured page."""
    parts, length, index = [], 0, 0
    while length < size:
        item = f"<!-- fixture filler row {index} -->\n"
        parts.append(item)
        length += len(item)
        index += 1
    return "".join(parts)


def page_html(port, padding=0):
    paths = resource_paths()
    cdn = f"https://{B_HOST}:{port}"
    return f"""<!doctype html><meta charset="utf-8"><title>TLS CDN fixture</title>
<link rel="stylesheet" href="{cdn}{paths['style']}">
<h1>Synthetic CDN page</h1><p id="state">loading</p>
<p id="styled">styled by the CDN stylesheet</p><div id="third"></div>
<img id="third-root" width="{IMAGE_SIDE}" height="{IMAGE_SIDE}" alt="Third-origin image" src="https://{C_HOST}:{port}{paths['root']}">
<img id="cdn-image" width="{IMAGE_SIDE}" height="{IMAGE_SIDE}" alt="CDN image" src="{cdn}{paths['image']}">
<label>Input <input id="input" autocomplete="off"></label><button id="count">Count</button>
<output id="counted">0</output><script src="{cdn}{paths['script']}"></script>
{filler(padding)}"""


def stylesheet(port):
    paths = resource_paths()
    return ("#styled{color:rgb(0,128,0);font-weight:700}"
            f"#third{{width:{IMAGE_SIDE}px;height:{IMAGE_SIDE}px;"
            f"background:url(https://{C_HOST}:{port}{paths['third']})}}\n")


# The script is served by the CDN origin. It reports what the browser actually
# rendered: stylesheet applied, image decoded, script executed, control wired.
CDN_SCRIPT = """
window.fixture={state:'loading',count:0,scriptRan:true};
const f=window.fixture;
document.getElementById('count').onclick=()=>{f.count++;document.getElementById('counted').textContent=f.count};
function settle(){
  const image=document.getElementById('cdn-image');
  f.styleApplied=getComputedStyle(document.getElementById('styled')).color==='rgb(0, 128, 0)';
  f.imageWidth=image.naturalWidth;
  const root=document.getElementById('third-root');
  f.rootWidth=root.naturalWidth;
  const failed=[];
  if(!f.styleApplied)failed.push('stylesheet');
  if(f.imageWidth!==%d)failed.push('image');
  if(f.rootWidth!==%d)failed.push('third-origin root image');
  if(failed.length){f.state='error';f.error='not rendered: '+failed.join(',')}
  else{f.state='ready';document.getElementById('state').textContent='ready'}
  if(failed.length)document.getElementById('state').textContent='error: '+f.error;
}
if(document.readyState==='complete')settle();else window.addEventListener('load',settle);
""" % (IMAGE_SIDE, IMAGE_SIDE)


def run_openssl(openssl, arguments, cwd):
    subprocess.run([openssl, *arguments], cwd=cwd, check=True, timeout=30,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def generate_upstream_pki(directory, hosts=HOSTS, openssl=None):
    """Create a throwaway CA and one leaf for the synthetic hosts, inside ``directory``.

    Only the leaf is served; the CA exists so the proxy process (and only that
    process, through SSL_CERT_FILE) can verify the synthetic upstream. No key
    leaves ``directory``.
    """
    openssl = openssl or shutil.which("openssl")
    if not openssl:
        raise RuntimeError("openssl is required to create the synthetic upstream certificates")
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    san = ",".join(f"DNS:{host}" for host in hosts)
    (directory / "leaf.ext").write_text(f"subjectAltName={san}\nbasicConstraints=critical,CA:FALSE\n"
                                        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
    run_openssl(openssl, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key"], directory)
    run_openssl(openssl, ["req", "-x509", "-new", "-key", "ca.key", "-days", "2", "-subj", f"/CN={FIXTURE_CA_NAME}",
                          "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
                          "-out", "ca.pem"], directory)
    run_openssl(openssl, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "leaf.key"], directory)
    run_openssl(openssl, ["req", "-new", "-key", "leaf.key", "-subj", f"/CN={hosts[0]}", "-out", "leaf.csr"], directory)
    run_openssl(openssl, ["x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
                          "-days", "2", "-extfile", "leaf.ext", "-out", "leaf.pem"], directory)
    for path in directory.iterdir():
        path.chmod(0o600)
    return {"ca": directory / "ca.pem", "cert": directory / "leaf.pem", "key": directory / "leaf.key"}


class TLSBoundedServer(BoundedHTTPServer):
    """The bounded server, with TLS negotiated in the handler thread."""

    def __init__(self, address, handler, context):
        self.context = context
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        try:
            return self.context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False), address
        except BaseException:
            connection.close()
            raise


class TLSResourceFixture:
    """Serves the A/B/C origins on one loopback port; records only route labels."""

    def __init__(self, pki, padding=0):
        self.padding = padding
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = defaultdict(int)
        self.events = defaultdict(lambda: deque(maxlen=32))
        self.png = solid_png()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(pki["cert"]), str(pki["key"]))
        fixture = self
        self.port = None

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle(self):
                try:
                    super().handle()
                except (TimeoutError, ConnectionError, ssl.SSLError):
                    pass  # A refused handshake or reset must not produce raw logs.

            def log_message(self, *_args):
                pass  # Never log raw URLs or headers.

            def reply(self, code, body=b"", mime="text/plain"):
                self.send_response(code)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def label(self):
                host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
                path = urlsplit(self.path).path
                paths = resource_paths()
                if self.command in ("GET", "HEAD"):
                    if host == A_HOST and path == "/":
                        return "a:/"
                    if host == A_HOST and path == "/favicon.ico":
                        return "a:favicon"  # Browsers ask on their own; always a 404.
                    if host == B_HOST:
                        for name in ("script", "style", "image"):
                            if path == paths[name]:
                                return f"b:{name}"
                    if host == C_HOST and path == paths["third"]:
                        return "c:third"
                    if host == C_HOST and path == paths["root"]:
                        return "c:root"
                return "other"

            def serve(self):
                start = time.monotonic()
                label = self.label()
                if self.command == "POST":
                    label = "post"
                with fixture.lock:
                    fixture.counts[label] += 1
                try:
                    if self.command == "POST":
                        self.close_connection = True
                        self.reply(200, b"synthetic post arrived")
                    elif label == "a:/":
                        self.reply(200, page_html(fixture.port, fixture.padding).encode(), "text/html")
                    elif label == "b:script":
                        self.reply(200, CDN_SCRIPT.encode(), "application/javascript")
                    elif label == "b:style":
                        self.reply(200, stylesheet(fixture.port).encode(), "text/css")
                    elif label in ("b:image", "c:third", "c:root"):
                        self.reply(200, fixture.png, "image/png")
                    else:
                        self.reply(404, b"missing synthetic route")
                except (TimeoutError, ConnectionError, ssl.SSLError):
                    pass
                finally:
                    with fixture.lock:
                        fixture.events[label].append({"elapsed_ms": round((time.monotonic() - start) * 1000, 3)})

            do_GET = do_POST = do_HEAD = serve

        self.server = TLSBoundedServer(("127.0.0.1", 0), Handler, context)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def evidence(self):
        with self.lock:
            return {"counts": dict(self.counts), "routes": {key: list(value) for key, value in self.events.items()},
                    "scenario": "tls-resource"}


def tls_config(port, ca_cert, ca_key, recorder_dir, signing_key):
    """Strict exact-destination policy for the TLS scenario.

    No entropy exclusion, relaxed action, raised rate or budget, disabled scanner
    or IP exemption: the destination allowlist and exact-name loopback trust are
    the only fixture accommodations. The configured default identity is the
    operator-assigned trusted caller the issuer-bound evidence needs, and the
    request/response actions are the enforcing ones the evidence requires.
    """
    del port  # Origins are told apart by name; the port needs no policy entry.
    return {
        "mode": "strict", "api_allowlist": list(HOSTS), "trusted_domains": list(HOSTS),
        "default_agent_identity": AGENT,
        "dns": {"host_overrides": {host: ["127.0.0.1"] for host in HOSTS}},
        "forward_proxy": {"enabled": True},
        "tls_interception": {"enabled": True, "ca_cert": str(ca_cert), "ca_key": str(ca_key)},
        "request_body_scanning": {"enabled": True, "action": "block", "scan_headers": True,
                                  "issuer_bound_session_cookies": True},
        "response_scanning": {"enabled": True, "action": "block"},
        "canary_tokens": {"enabled": True, "tokens": [{"name": "browser-repro", "value": CANARY}]},
        "flight_recorder": {"enabled": True, "dir": str(recorder_dir), "signing_key_path": str(signing_key)},
        "logging": {"format": "json", "output": "stdout", "include_allowed": True, "include_blocked": True},
    }


def declared_resource_receipts(lines, extension="declared_resource_path"):
    """Receipts whose own extension names ``extension`` (default: the CDN rule).

    ``lines`` are flight-recorder JSONL lines. Matching reads the receipt's
    ``ext`` and action record, never a log substring, and skips anything that
    is malformed. A receipt target carries no query.
    """
    found = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        detail = entry.get("detail") if isinstance(entry, dict) else None
        if not isinstance(detail, dict):
            continue
        record, ext = detail.get("action_record"), detail.get("ext")
        if (isinstance(record, dict) and isinstance(ext, dict)
                and ext.get("entropy_issuer_query_allow") == extension):
            found.append({key: record.get(key) for key in ("target", "verdict", "actor", "method", "layer")})
    return found


def all_issuer_allow_kinds(lines):
    """Every ``entropy_issuer_query_allow`` kind seen, to prove no other rule fired."""
    kinds = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        detail = entry.get("detail") if isinstance(entry, dict) else None
        ext = detail.get("ext") if isinstance(detail, dict) else None
        if isinstance(ext, dict) and "entropy_issuer_query_allow" in ext:
            kinds.append(ext["entropy_issuer_query_allow"])
    return kinds


def receipt_signers(lines):
    """Distinct receipt signer public keys (hex) named by the recorder lines."""
    keys = set()
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        detail = entry.get("detail") if isinstance(entry, dict) else None
        if not isinstance(detail, dict):
            continue
        signature = detail.get("signature")
        for candidate in (detail.get("signer_key"), signature.get("signer_key_id") if isinstance(signature, dict) else None):
            if isinstance(candidate, str) and len(candidate) == 64 and all(c in "0123456789abcdef" for c in candidate):
                keys.add(candidate)
    return sorted(keys)


def event_host(event):
    """Destination host named by a proxy log event (``url`` or CONNECT ``target``)."""
    raw = event.get("url") or event.get("target") or ""
    if not isinstance(raw, str):
        return ""
    raw = raw.split("://", 1)[-1].split("/", 1)[0]
    return raw.rsplit(":", 1)[0].lower() if ":" in raw else raw.lower()


def proxy_events(stdout):
    """JSON log events from the proxy's captured stdout; non-JSON lines are skipped."""
    events = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def evaluate_acceptance(*, port, fixture, receipts, other_kinds, events, browser):
    """Return every reason this run does not establish the CDN-resource rule.

    A blank page, fewer blocks or a missing receipt can each look like success
    on its own, so the decision joins independent witnesses: the fixture's own
    arrival counts, the proxy's signed receipts and audit events, and the
    browser's rendered DOM and observed network outcomes.
    """
    failures = []
    counts = fixture.get("counts", {})
    cdn_arrivals = sum(counts.get(name, 0) for name in ("b:script", "b:style", "b:image", "c:root"))
    for name in ("b:script", "b:style", "b:image", "c:root"):
        if counts.get(name, 0) < 1:
            failures.append(f"declared CDN resource {name} never reached the origin")
    if counts.get("a:/", 0) < 1:
        failures.append("page origin never served the document")
    for name in ("c:third", "other", "post"):
        if counts.get(name, 0):
            failures.append(f"denied traffic ({name}) reached the origin {counts[name]} time(s)")
    origins = {f"https://{B_HOST}:{port}", f"https://{C_HOST}:{port}"}
    if len(receipts) != cdn_arrivals:
        failures.append(f"declared_resource_path receipts ({len(receipts)}) differ from CDN arrivals ({cdn_arrivals})")
    for receipt in receipts:
        if (receipt.get("target") not in origins or receipt.get("verdict") != "allow"
                or receipt.get("actor") != AGENT or receipt.get("method") != "GET"
                or receipt.get("layer") != "entropy_issuer_query_allow"):
            failures.append("a declared_resource_path receipt has an unexpected target, verdict, actor or method")
            break
    if other_kinds != ["declared_resource_path"] * len(other_kinds):
        failures.append("an issuer allowance other than declared_resource_path was recorded")
    allows = [event for event in events if event.get("event") == "entropy_issuer_query_allow"]
    if len(allows) != len(receipts):
        failures.append(f"audit allowances ({len(allows)}) differ from receipts ({len(receipts)})")
    if any(event.get("agent") != AGENT or event.get("agent_auth") != "config-default" for event in allows):
        failures.append("an allowance was not attributed to the configured default identity")
    # Chromium also tries its own Google service hosts; the strict allowlist refuses
    # them before any DNS or dial. They are reported, never counted as fixture blocks.
    blocked = [event for event in events if event.get("event") == "blocked" and event_host(event) in HOSTS]
    tls = browser.get("tls") if isinstance(browser, dict) else None
    if not isinstance(tls, dict):
        failures.append("browser report carries no TLS scenario observations")
    else:
        denied = tls.get("denials")
        if not isinstance(denied, list) or len(blocked) != len(denied):
            failures.append(f"proxy blocked events ({len(blocked)}) differ from observed denials "
                            f"({len(denied) if isinstance(denied, list) else 'unknown'})")
        if any(event.get("agent") != AGENT for event in blocked):
            failures.append("a block was not attributed to the configured default identity")
    return failures


def tls_witness(port, ca_path, host=B_HOST):
    """Verified TLS handshake to the fixture listener, from the runner process."""
    import socket
    context = ssl.create_default_context(cafile=str(ca_path))
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secured:
            return secured.version()
