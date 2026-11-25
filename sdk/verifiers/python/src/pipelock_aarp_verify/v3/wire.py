# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""Receipt v3 storage grammar and signature verification."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from importlib.resources import files
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

Document = dict[str, Any]
REGISTRY = json.loads(files(__package__).joinpath("registry.json").read_bytes())
LIMITS = REGISTRY["limits"]
MAX_INTEGER = LIMITS["integer"]
LINE_BYTES = LIMITS["line_bytes"]
LAYOUT = REGISTRY["layout"]
PROFILE = REGISTRY["profile"].encode("ascii")
PROFILE_PREFIX = b'{"payloadType":"application/vnd.pipelock.receipt.'
FINDINGS = REGISTRY["findings"]
KINDS = REGISTRY["kinds"]
MEMBER = re.compile(r"[a-z][a-z0-9_]{0," + str(LIMITS["member_bytes"] - 1) + "}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ID128 = re.compile(r"[0-9a-f]{32}")
KEY_HEX = re.compile(r"[0-9a-f]{64}")
ACTION_ID = re.compile(r"[a-zA-Z0-9._:-]{1,128}")
UTC_MILLIS = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"
)

PREFIX = LAYOUT["prefix"].encode("ascii")
SUFFIX = LAYOUT["suffix"].encode("ascii")
PAYLOAD_PREFIX = LAYOUT["payload_prefix"].encode("ascii")
ENTRY = re.compile(
    re.escape(LAYOUT["entry_prefix"].encode("ascii"))
    + rb"(sha256:[0-9a-f]{64})"
    + re.escape(LAYOUT["signature_prefix"].encode("ascii"))
    + rb"([A-Za-z0-9+/]{86}==)"
    + re.escape(LAYOUT["entry_suffix"].encode("ascii"))
)


class WireError(ValueError):
    """A rejected record's registry finding code."""


def canonical(value: Any) -> bytes:
    """Encode the v3 restricted JSON model (all member names are ASCII)."""
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def genesis(stream: str) -> str:
    return digest((LAYOUT["genesis_domain"] + "\0" + stream).encode("ascii"))


def pae(payload: bytes) -> bytes:
    return b" ".join(
        (
            b"DSSEv1",
            str(len(PROFILE)).encode(),
            PROFILE,
            str(len(payload)).encode(),
            payload,
        )
    )


def decode_base64(text: bytes, size: int) -> bytes | None:
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    return raw if len(raw) == size and base64.b64encode(raw) == text else None


class PayloadParser:
    """Parse one canonical JSON object without recursing past the wire limit."""

    _token = re.compile(r'"(?:[^"\\\x00-\x1f]|\\["\\bfnrt]|\\u00[01][0-9a-f])*"')
    _integer = re.compile(r"0|-?[1-9][0-9]*")

    def __init__(self, data: bytes) -> None:
        self.text = data.decode("utf-8")
        self.pos = 0

    def _eat(self, token: str) -> bool:
        if self.text.startswith(token, self.pos):
            self.pos += len(token)
            return True
        return False

    def _need(self, token: str) -> None:
        if not self._eat(token):
            raise WireError("PAYLOAD_LAYOUT")

    def _string(self) -> str:
        match = self._token.match(self.text, self.pos)
        if match is None:
            raise WireError("PAYLOAD_LAYOUT")
        raw = match[0]
        value = json.loads(raw)
        if json.dumps(value, ensure_ascii=False) != raw:
            raise WireError("PAYLOAD_LAYOUT")
        self.pos = match.end()
        return value

    def _value(self, depth: int) -> Any:
        if self.text.startswith('"', self.pos):
            return self._string()
        if self.text.startswith("{", self.pos):
            return self.object(depth + 1)
        if self._eat("["):
            if depth >= LIMITS["depth"]:
                raise WireError("PAYLOAD_LAYOUT")
            values = []
            if not self._eat("]"):
                values.append(self._value(depth + 1))
                while self._eat(","):
                    values.append(self._value(depth + 1))
                self._need("]")
            return values
        if self._eat("true"):
            return True
        if self._eat("false"):
            return False
        match = self._integer.match(self.text, self.pos)
        if match is None or match.end() - self.pos > 17:
            raise WireError("PAYLOAD_LAYOUT")
        self.pos = match.end()
        integer = int(match[0])
        if abs(integer) > MAX_INTEGER:
            raise WireError("PAYLOAD_LAYOUT")
        return integer

    def object(self, depth: int = 1) -> Document:
        if depth > LIMITS["depth"]:
            raise WireError("PAYLOAD_LAYOUT")
        self._need("{")
        fields: Document = {}
        if self._eat("}"):
            return fields
        last = ""
        while True:
            name = self._string()
            if name <= last or not MEMBER.fullmatch(name):
                raise WireError("PAYLOAD_LAYOUT")
            self._need(":")
            fields[name] = self._value(depth)
            last = name
            if not self._eat(","):
                self._need("}")
                return fields


def parse_payload(raw: bytes, trailing_code: str = "PAYLOAD_LAYOUT") -> Document:
    try:
        parser = PayloadParser(raw)
    except UnicodeDecodeError as exc:
        # An invalid byte can be outside the payload object.
        PayloadParser(raw[: exc.start]).object()
        raise WireError(trailing_code) from exc
    value = parser.object()
    if parser.pos != len(parser.text):
        raise WireError(trailing_code)
    return value


def _time(text: str) -> bool:
    if not UTC_MILLIS.fullmatch(text):
        return False
    # Go's proleptic Gregorian time parser admits year zero, a leap year.
    if text.startswith("0000"):
        text = "2000" + text[4:]
    try:
        datetime.fromisoformat(text)
    except ValueError:
        return False
    return True


def _match_string(value: str, kind: str) -> bool:
    if not value:
        return False
    match kind:
        case "string":
            return True
        case "name":
            return bool(MEMBER.fullmatch(value))
        case "id128":
            return bool(ID128.fullmatch(value))
        case "digest":
            return bool(DIGEST.fullmatch(value))
        case "action_id":
            return bool(ACTION_ID.fullmatch(value))
        case "target":
            return len(value.encode()) <= LIMITS["target_bytes"]
        case "instance":
            return len(value.encode()) <= LIMITS["writer_instance_bytes"]
        case "key":
            return decode_base64(value.encode(), LAYOUT["public_key_bytes"]) is not None
        case "time":
            return _time(value)
        case _:
            return False


def match_field(value: Any, kind: str, required: bool) -> tuple[bool, bool]:
    """Return (unknown enumeration, structurally valid)."""
    if kind.startswith("[]"):
        if not isinstance(value, list) or not (required or value):
            return False, False
        unknown = False
        for item in value:
            new, valid = match_field(item, kind[2:], True)
            if not valid:
                return False, False
            unknown |= new
        return unknown, True
    if kind.startswith("@"):
        return value not in REGISTRY["enums"][kind[1:]], isinstance(
            value, str
        ) and bool(value)
    if isinstance(value, dict) and (required or value):
        if kind == "object":
            return False, True
        if kind in REGISTRY["objects"]:
            return match_object(value, kind)
    elif isinstance(value, str):
        return False, _match_string(value, kind)
    elif type(value) is int:
        return False, (
            kind == "uint"
            and value >= 0
            or kind == "positive"
            and value > 0
            or kind == "version"
            and value == 3
        )
    elif isinstance(value, bool):
        return False, kind == "bool"
    return False, False


def match_object(value: Document, shape: str) -> tuple[bool, bool]:
    fields = REGISTRY["objects"][shape]
    if value.keys() - fields.keys():
        return False, False
    unknown = False
    for name, (kind, required) in fields.items():
        if name in value:
            new, valid = match_field(value[name], kind, required)
            if not valid:
                return False, False
            unknown |= new
        elif required:
            return False, False
    for condition in REGISTRY["conditions"].get(shape, ()):
        if value.get(condition["field"]) != condition["value"]:
            continue
        if any(key not in value for key in condition.get("require", ())):
            return unknown, False
        if any(key in value for key in condition.get("forbid", ())):
            return unknown, False
        if any(
            value.get(key) != want for key, want in condition.get("equals", {}).items()
        ):
            return unknown, False
    return unknown, True


@dataclass(slots=True)
class Record:
    fields: Document
    id: str
    unknown: bool = False
    body_code: str = ""
    after_damage: bool = False

    @property
    def stream(self) -> str:
        return self.fields["stream"]

    @property
    def seq(self) -> int:
        return self.fields["seq"]

    @property
    def kind(self) -> str:
        return self.fields["kind"]

    @property
    def signer(self) -> str:
        return self.fields["signer"]

    @property
    def body(self) -> Document:
        return self.fields["body"]

    def position(self) -> Document:
        return {"record": self.id, "seq": self.seq}


def parse_line(line: bytes) -> tuple[Record, bytes, bytes]:
    if len(line) > LINE_BYTES:
        raise WireError("LINE_SIZE")
    if not line.startswith(PREFIX):
        if line.startswith(PROFILE_PREFIX):
            profile, sep, _ = line[len(PROFILE_PREFIX) :].partition(b'"')
            if sep and profile != b"v3+json":
                raise WireError("UNKNOWN_PROFILE")
        raise WireError("LINE_LAYOUT")
    cursor = len(PREFIX)
    signatures: dict[str, bytes] = {}
    last = ""
    for _ in range(LIMITS["signatures"]):
        match = ENTRY.match(line, cursor)
        if match is None:
            raise WireError("LINE_LAYOUT")
        key = match[1].decode("ascii")
        raw = decode_base64(match[2], LAYOUT["signature_bytes"])
        if key <= last or raw is None:
            raise WireError("LINE_LAYOUT")
        signatures[key], last = raw, key
        cursor = match.end()
        if not line.startswith(b",", cursor):
            break
        if len(signatures) == LIMITS["signatures"]:
            raise WireError("LINE_LAYOUT")
        cursor += 1
    if not line.startswith(PAYLOAD_PREFIX, cursor) or not line.endswith(SUFFIX):
        raise WireError("LINE_LAYOUT")
    payload = line[cursor + len(PAYLOAD_PREFIX) : -len(SUFFIX)]
    if not payload.startswith(b"{"):
        raise WireError("LINE_LAYOUT")
    values = parse_payload(payload, "LINE_LAYOUT")
    _, valid = match_object(values, "Common")
    crit = values.get("crit", ())
    if not valid or list(crit) != sorted(set(crit)):
        raise WireError("COMMON_SCHEMA")
    sig = signatures.get(values["signer"])
    if sig is None:
        raise WireError("SIGNER_MISSING")
    message = pae(payload)
    return Record(values, digest(message)), payload, sig


def check_body(record: Record) -> tuple[bool, str]:
    if record.fields.get("crit"):
        return True, "UNKNOWN_CRIT"
    kind = KINDS.get(record.kind)
    if kind is None or record.fields["body_v"] != kind["body_v"]:
        return True, "UNKNOWN_CONTROL" if kind and kind["class"] == "control" else ""
    body = record.body
    unknown, valid = match_object(body, kind["body"])
    if not valid:
        return False, "BODY_SCHEMA"
    if unknown and kind["class"] == "control":
        return True, "UNKNOWN_CONTROL"
    if record.kind == "stream_open":
        surfaces = body["coverage"]["surfaces"]
        key = base64.b64decode(body["signer_key"]["public"])
        if (
            ("previous" in body) == ("legacy_cutover" in body)
            or surfaces != sorted(surfaces)
            or digest(key) != record.signer
        ):
            return False, "BODY_SCHEMA"
    elif record.kind == "stream_close" and body["records"] != record.seq + 1:
        return False, "BODY_SCHEMA"
    elif record.kind == "action" and not _action_fields(body):
        return False, "BODY_SCHEMA"
    return unknown, ""


def _action_fields(body: Document) -> bool:
    if body["policy"]["source"] == "writer_config":
        return False
    hold = body.get("hold")
    if hold is not None:
        resolution = ("resolution_policy", "resolution_source")
        if body["phase"] == "hold" and (
            "policy" not in hold or any(k in hold for k in (*resolution, "correction"))
        ):
            return False
        if body["phase"] == "resolution" and (
            "policy" in hold
            or "parent" in hold
            or any(k not in hold for k in resolution)
        ):
            return False
    classes = [entry["class"] for entry in body.get("redaction", {}).get("classes", ())]
    return classes == sorted(set(classes))


# RFC 8032 point decompression and unreduced subgroup membership. These
# operations handle public inputs only. Signature equations use OpenSSL.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_SQRT_MINUS_ONE = pow(2, (_P - 1) // 4, _P)
Point = tuple[int, int, int, int]
_IDENTITY: Point = (0, 1, 1, 0)


def _point(encoded: bytes) -> Point | None:
    raw = int.from_bytes(encoded, "little")
    sign, y = raw >> 255, raw % (2**255)
    if y >= _P:
        return None
    yy = y * y
    u, v = (yy - 1) % _P, (_D * yy + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    if (v * x * x - u) % _P:
        x = x * _SQRT_MINUS_ONE % _P
    if (v * x * x - u) % _P or (x == 0 and (sign or y == 1)):
        return None
    if x % 2 != sign:
        x = _P - x
    return x, y, 1, x * y % _P


def _add(p: Point, q: Point) -> Point:
    x, y, z, t = p
    xx, yy, zz, tt = q
    a = (y - x) * (yy - xx) % _P
    b = (y + x) * (yy + xx) % _P
    c = t * tt * (2 * _D) % _P
    d = z * zz * 2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _prime_order(point: Point) -> bool:
    total = _IDENTITY
    for bit in bin(_L)[2:]:
        total = _add(total, total)
        if bit == "1":
            total = _add(total, point)
    return total[0] == 0 and total[1] == total[2]


def validate_key(raw: bytes) -> Ed25519PublicKey | None:
    point = _point(raw)
    if point is None or not _prime_order(point):
        return None
    return Ed25519PublicKey.from_public_bytes(raw)


def check_signature(
    key: Ed25519PublicKey | None, payload: bytes, signature: bytes
) -> None:
    if key is None:
        raise WireError("SIGNATURE_KEY")
    if int.from_bytes(signature[32:], "little") >= _L:
        raise WireError("SIGNATURE_SCALAR")
    point = _point(signature[:32])
    if point is None:
        raise WireError("SIGNATURE_POINT")
    try:
        key.verify(signature, pae(payload))
    except InvalidSignature as exc:
        raise WireError("SIGNATURE_EQUATION") from exc
    # With both public points in the prime-order subgroup, cofactored and
    # cofactorless equations agree. Keep the equation finding for mixed R.
    if not _prime_order(point):
        raise WireError("SIGNATURE_EQUATION")
