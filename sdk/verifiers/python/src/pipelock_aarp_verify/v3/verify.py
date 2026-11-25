# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""Disk-backed verification and deterministic receipt v3 reports."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from collections.abc import Iterable, Iterator
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..group import _recorder_file_exclusions
from ..input_file import _open_regular_input
from .decision import appraise
from .legacy import legacy_candidate, verify_cutover
from .wire import (
    DIGEST,
    FINDINGS,
    ID128,
    KEY_HEX,
    LAYOUT,
    LINE_BYTES,
    MAX_INTEGER,
    PROFILE_PREFIX,
    Document,
    Record,
    WireError,
    check_body,
    check_signature,
    decode_base64,
    digest,
    genesis,
    parse_line,
    validate_key,
)

_PROFILE_NAME = re.compile(r"\.receipt-v([0-9]+)\.jsonl$")
_STREAM_NAME = re.compile(r"([0-9a-f]{32})-([0-9]{16})\.receipt-v3\.jsonl")
_INVENTORY_NAME = re.compile(r"receipt-v3-cutover-([0-9a-f]{64})\.json")
_PREFIX = "VALID PREFIX, END UNPROVEN"


@dataclass(frozen=True, slots=True)
class Options:
    """Pins and scope for verify_paths. Keys and expectations use CLI syntax."""

    keys: tuple[str, ...] = ()
    allow_unpinned: bool = False
    allow_prefix: bool = False
    accept_discontinuities: tuple[str, ...] = ()
    allow_partial_histories: tuple[str, ...] = ()
    expect_lineage: str = ""
    expect_heads: tuple[str, ...] = ()
    expect_sequences: tuple[str, ...] = ()
    directory: bool = False
    explicit_v3: bool = False

    def validate(self, paths: list[Path]) -> None:
        if self.explicit_v3 and (self.directory or len(paths) != 1):
            raise ValueError("explicit v3 format applies only to a single file")
        if self.directory and len(paths) != 1:
            raise ValueError("directory scope requires exactly one directory")
        if any(not KEY_HEX.fullmatch(key) for key in self.keys):
            raise ValueError("key must be 64 lowercase hexadecimal characters")
        if self.expect_lineage and not ID128.fullmatch(self.expect_lineage):
            raise ValueError(
                "expected lineage must be 32 lowercase hexadecimal characters"
            )
        if any(not ID128.fullmatch(item) for item in self.allow_partial_histories):
            raise ValueError("partial history must name a 32-character stream ID")
        if any(not DIGEST.fullmatch(item) for item in self.accept_discontinuities):
            raise ValueError("accepted discontinuity must be a record ID")
        for head in self.expect_heads:
            head_expectation(head)
        for sequence in self.expect_sequences:
            sequence_expectation(sequence)


def sequence_expectation(value: str) -> tuple[str, int]:
    stream, _, seq = value.partition(":")
    if (
        not ID128.fullmatch(stream)
        or not re.fullmatch(r"0|[1-9][0-9]{0,15}", seq)
        or int(seq) > MAX_INTEGER
    ):
        raise ValueError("expected sequence must be stream:seq")
    return stream, int(seq)


def head_expectation(value: str) -> tuple[str, int, str]:
    stream, seq, record = (value.split(":", 2) + ["", ""])[:3]
    try:
        _, position = sequence_expectation(f"{stream}:{seq}")
        if DIGEST.fullmatch(record):
            return stream, position, record
    except ValueError:
        pass
    raise ValueError("expected head must be stream:seq:sha256:digest")


@dataclass(frozen=True, slots=True)
class _Input:
    path: Path
    stream: str = ""
    start: int = -1
    code: str = ""


def _identify(path: Path) -> _Input | None:
    profile = _PROFILE_NAME.search(path.name)
    if not profile:
        return None
    if profile[1] != "3":
        return _Input(path, code="UNKNOWN_PROFILE")
    match = _STREAM_NAME.fullmatch(path.name)
    if match is None:
        return _Input(path, code="FILE_LAYOUT")
    return _Input(path, match[1], int(match[2]))


def _starts_with_profile(path: Path) -> bool:
    with _open_regular_input(path) as source:
        return source.read(len(PROFILE_PREFIX)) == PROFILE_PREFIX


def claims_input(path: str | Path) -> bool:
    """Return whether the v3-or-later detector claims this file."""
    path = Path(path)
    return _identify(path) is not None or _starts_with_profile(path)


def _discover(
    paths: list[Path], options: Options
) -> tuple[list[_Input], list[Path], dict[str, list[Path]], int]:
    ignored = 0
    if options.directory:
        directory = paths[0].resolve(strict=True)
        paths = []
        for child in directory.iterdir():
            if not (
                _identify(child)
                or _INVENTORY_NAME.fullmatch(child.name)
                or legacy_candidate(child.name)
            ):
                ignored += 1
                continue
            if child.is_symlink() or not child.is_file():
                raise ValueError(f"evidence path is not a regular file: {child}")
            paths.append(child)
    v3 = []
    legacy = []
    inventories = defaultdict(list)
    for path in sorted(set(paths)):
        match = _INVENTORY_NAME.fullmatch(path.name)
        if match:
            inventories["sha256:" + match[1]].append(path)
        elif identified := _identify(path):
            v3.append(identified)
        elif options.explicit_v3:
            v3.append(_Input(path))
        elif _starts_with_profile(path):
            v3.append(_Input(path, code="V3_CONTENT_UNCLAIMED"))
        else:
            legacy.append(path)
    return v3, legacy, inventories, ignored


def _read_line(source: BinaryIO) -> tuple[bytes, bool]:
    line = source.readline(LINE_BYTES + 1)
    tail = line
    while len(tail) == LINE_BYTES + 1 and not tail.endswith(b"\n"):
        tail = source.readline(LINE_BYTES + 1)
    return line, tail.endswith(b"\n")


@dataclass(eq=False, slots=True)
class _Stream:
    opening: Record | None = None
    body: Document = field(default_factory=dict)
    last: Record | None = None
    limit: int = MAX_INTEGER
    fork: list[Record] = field(default_factory=list)
    children: list[_Stream] = field(default_factory=list)
    missing: bool = False
    broken: bool = False
    summary: Document = field(default_factory=lambda: {"records": 0})

    def summarize(self) -> None:
        row = self.summary
        row["stream"] = self.opening.stream if self.opening else ""
        row["signer"] = self.opening.signer if self.opening else ""
        pin = self.body.get("previous")
        if pin:
            row["previous"] = pin["stream"]
        if self.last:
            row["last"] = row["tip"] = self.last.position()
        row["end"] = "open"
        if self.fork:
            row["end"] = "forked"
        elif self.last and self.last.kind == "stream_close":
            row["end"] = "closed"
        if len(self.children) > 1:
            row.pop("tip", None)
        elif self.children and not self.fork:
            child = self.children[0]
            pin = child.body["previous"]
            if (
                pin["ended"] == "unsealed"
                and self.last
                and self.last.position() == {"record": pin["record"], "seq": pin["seq"]}
                and self.last.kind != "stream_close"
                and self.body.get("lineage") == child.body["lineage"]
            ):
                row["end"] = "superseded_unsealed"
            elif pin["ended"] == "write_error" and self.limit == pin["seq"]:
                row.update(
                    end="superseded_write_error",
                    tip={"record": pin["record"], "seq": pin["seq"]},
                    records=pin["seq"] + 1,
                    unconfirmed_from=pin["seq"] + 1,
                )


def _position_order(current: Record, last: Record | None, stream: str) -> str:
    if last is None:
        if (
            current.seq != 0
            or current.kind != "stream_open"
            or current.fields["prev"] != genesis(stream)
        ):
            return "STREAM_ORDER"
    elif last.kind == "stream_close":
        return "DATA_AFTER_CLOSE"
    elif (
        current.seq != last.seq + 1
        or current.fields["prev"] != last.id
        or current.signer != last.signer
        or current.kind == "stream_open"
    ):
        return "STREAM_ORDER"
    return ""


class Verification:
    def __init__(self, db: sqlite3.Connection, opts: Options, ignored: int) -> None:
        self.db = db
        db.execute("""
            CREATE TABLE records (
                stream TEXT, seq INTEGER, id TEXT, payload BLOB,
                unknown INTEGER, body_code TEXT, damaged INTEGER,
                PRIMARY KEY (stream, seq, id)
            ) WITHOUT ROWID
        """)
        self.opts = opts
        self.trusted = {
            digest(bytes.fromhex(k)): validate_key(bytes.fromhex(k)) for k in opts.keys
        }
        self.keys = dict(self.trusted)
        self.used: set[str] = set()
        self.streams: dict[str, _Stream] = {}
        self.histories: dict[str, list[_Stream]] = defaultdict(list)
        self.result: Document = {
            "kind": "verify_result",
            "v": 1,
            "accepted": [],
            "contested_streams": [],
            "findings": [],
            "histories": [],
            "legacy": [],
            "ignored_files": ignored,
            "limits": ["L-FSYNC-ERROR-REOPEN", "L-FSYNC-HONESTY"],
            "trust": {"mode": "pinned_keys" if opts.keys else "unpinned", "keys": []},
            "trust_state": "pinned" if opts.keys else "unpinned",
        }

    def add(self, code: str, stream: str = "", record: Record | None = None) -> None:
        finding = {"class": FINDINGS[code], "code": code}
        if record:
            finding.update(
                {"record": record.id, "seq": record.seq, "stream": record.stream}
            )
        elif stream:
            finding["stream"] = stream
        self.result["findings"].append(finding)

    def discover_key(self, evidence: _Input) -> None:
        if evidence.code or evidence.start > 0:
            return
        with _open_regular_input(evidence.path) as source:
            line, complete = _read_line(source)
        if not complete:
            return
        try:
            record, _, _ = parse_line(line)
        except WireError:
            return
        if (
            record.seq != 0
            or record.kind != "stream_open"
            or record.signer in self.keys
        ):
            return
        key = record.body.get("signer_key")
        public = key.get("public") if isinstance(key, dict) else None
        if isinstance(public, str):
            raw = decode_base64(public.encode(), LAYOUT["public_key_bytes"])
            if raw is not None and digest(raw) == record.signer:
                self.keys[record.signer] = validate_key(raw)

    def stage_files(self, files: list[_Input]) -> None:
        max_starts: dict[str, int] = defaultdict(lambda: -1)
        tails = []
        for evidence in files:
            if evidence.code:
                self.add(evidence.code, evidence.stream)
                continue
            stream, start, last, torn = self._stage_file(evidence)
            if last is not None:
                max_starts[stream] = max(max_starts[stream], start)
                if torn:
                    tails.append((start, last))
        for start, last in tails:
            if last.kind == "stream_close":
                self.add("DATA_AFTER_CLOSE", record=last)
            elif start < max_starts[last.stream]:
                self.add("FILE_LAYOUT", last.stream)
            else:
                self.add("TORN_TAIL", record=last)

    def _stage_file(self, evidence: _Input) -> tuple[str, int, Record | None, bool]:
        stream, start = evidence.stream, evidence.start
        last = None
        complete = broken = after_damage = False
        with _open_regular_input(evidence.path) as source:
            offset = 0
            while True:
                line, terminated = _read_line(source)
                if not terminated:
                    if not complete and not broken:
                        self.add("FILE_LAYOUT", stream)
                    return stream, start, last, bool(line) and complete
                try:
                    record, payload, signature = parse_line(line)
                    key: Ed25519PublicKey | None = self.keys.get(record.signer)
                    check_signature(key, payload, signature)
                except WireError as exc:
                    self.add(str(exc), stream)
                    broken = after_damage = True
                    offset += 1
                    continue
                self.used.add(record.signer)
                code = ""
                if not complete:
                    if (
                        offset == 0
                        and start >= 0
                        and (stream, start) != (record.stream, record.seq)
                    ):
                        code = "FILE_LAYOUT"
                    else:
                        if start < 0:
                            stream, start = record.stream, record.seq - offset
                        complete = True
                if not code:
                    code = self._local_order(
                        record, stream, start + offset, last, broken
                    )
                offset += 1
                if code:
                    self.add(code, record=record)
                    broken = after_damage = True
                    continue
                unknown, body_code = check_body(record)
                self.streams.setdefault(stream, _Stream())
                self.db.execute(
                    """
                    INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (stream, seq, id) DO UPDATE
                    SET damaged = min(damaged, excluded.damaged)
                """,
                    (
                        record.stream,
                        record.seq,
                        record.id,
                        payload,
                        unknown,
                        body_code,
                        after_damage,
                    ),
                )
                last, after_damage = record, False

    @staticmethod
    def _local_order(
        record: Record, stream: str, seq: int, last: Record | None, broken: bool
    ) -> str:
        if not broken and (record.stream != stream or record.seq != seq):
            return "STREAM_ORDER"
        if last and last.kind == "stream_close":
            return "DATA_AFTER_CLOSE"
        if (
            not broken
            and record.seq != 0
            and (
                record.kind == "stream_open"
                or last
                and (last.id != record.fields["prev"] or last.signer != record.signer)
            )
        ):
            return "STREAM_ORDER"
        return ""

    def walk(self, stream: str, limit: int = MAX_INTEGER) -> Iterator[Record]:
        rows = self.db.execute(
            "SELECT id,payload,unknown,body_code,damaged FROM records "
            "WHERE stream=? AND seq<=? ORDER BY seq,id",
            (stream, limit),
        )
        for record_id, payload, unknown, code, damaged in rows:
            yield Record(
                json.loads(payload), record_id, bool(unknown), code, bool(damaged)
            )

    def _staged_body(self, record: Record) -> bool:
        if record.body_code:
            self.add(record.body_code, record=record)
            return FINDINGS[record.body_code] != "invalid"
        if self.trusted and record.signer not in self.trusted:
            self.add("TRUST", record=record)
        return True

    def _publish(self, stream: str, state: _Stream, record: Record, beat: int) -> int:
        last, state.last = state.last, record
        code = _position_order(record, last, stream)
        if code:
            if (
                code == "STREAM_ORDER"
                and record.after_damage
                and record.seq > (last.seq + 1 if last else 0)
            ):
                state.broken = True
                self._staged_body(record)
            else:
                self.add(code, record=record)
            return beat
        if not self._staged_body(record):
            state.broken = True
            return beat
        if record.seq == 0 and record.kind == "stream_open":
            state.opening = record
            if not record.unknown:
                state.body = record.body
        if last and record.fields["ts"] < last.fields["ts"]:
            self.add("CLOCK_REGRESSION", record=record)
        if record.kind == "heartbeat" and not record.unknown:
            beat += 1
            if record.body["beat"] != beat:
                self.add("HEARTBEAT_GAP", record=record)
        state.summary["records"] += 1
        return beat

    def verify_streams(self) -> None:
        for stream, state in sorted(self.streams.items()):
            previous = None
            beat = 0
            for current in self.walk(stream):
                if state.fork:
                    if current.seq == state.fork[0].seq:
                        state.fork.append(current)
                    else:
                        break
                elif previous is not None and previous.seq == current.seq:
                    state.fork.extend((previous, current))
                else:
                    if previous is not None:
                        beat = self._publish(stream, state, previous, beat)
                    previous = current
            if state.fork:
                state.limit = state.fork[0].seq - 1
                for candidate in state.fork:
                    self.add("FORK", record=candidate)
                if state.limit < 0:
                    self.result["contested_streams"].append(
                        {"stream": stream, "records": [r.id for r in state.fork]}
                    )
            elif previous is not None:
                self._publish(stream, state, previous, beat)
            if state.broken:
                state.opening = state.last = None
                state.body = {}
            elif state.opening and not state.opening.unknown:
                self.histories[state.body["lineage"]].append(state)

    def verify_succession(self) -> None:
        for _, stream in sorted(self.streams.items()):
            pin = stream.body.get("previous")
            if pin and stream.opening:
                parent = self.streams.get(pin["stream"])
                if parent is None or (not parent.opening and not parent.fork):
                    stream.missing = True
                    self.add("PREDECESSOR_NOT_PRESENTED", record=stream.opening)
                else:
                    parent.children.append(stream)
        for _, parent in sorted(self.streams.items()):
            for child in parent.children:
                if len(parent.children) > 1:
                    self.add("SUCCESSION_FORK", record=child.opening)
                if parent.opening:
                    self._check_pin(parent, child)
            parent.summarize()

    def _check_pin(self, parent: _Stream, child: _Stream) -> None:
        pin = child.body["previous"]
        same_lineage = parent.body.get("lineage") == child.body["lineage"]
        if not same_lineage and parent.body.get("lineage"):
            self.add("LINEAGE_MISMATCH", record=child.opening)
        found = self.db.execute(
            "SELECT id,json_extract(payload, '$.kind') FROM records "
            "WHERE stream=? AND seq=? AND seq<=?",
            (pin["stream"], pin["seq"], parent.limit),
        ).fetchone()
        if found is None:
            self.add("PREDECESSOR_TRUNCATED", record=child.opening)
            return
        record_id, kind = found
        ended = pin["ended"]
        if (
            record_id != pin["record"]
            or ended == "closed"
            and kind != "stream_close"
            or ended == "unsealed"
            and kind == "stream_close"
        ):
            self.add("PIN_MISMATCH", record=child.opening)
        elif ended != "write_error":
            if parent.last and parent.last.seq > pin["seq"]:
                self.add("TAIL_AFTER_SUCCESSION", record=child.opening)
        elif len(parent.children) == 1 and same_lineage and not parent.fork:
            parent.limit = pin["seq"]
            if parent.last and parent.last.seq > parent.limit:
                for record in self.walk(pin["stream"], parent.last.seq):
                    if record.seq > parent.limit:
                        self.add("UNCONFIRMED", record=record)

    def segments(self, members: list[_Stream]) -> list[tuple[bool, list[_Stream]]]:
        following = {}
        children = set()
        roots = []
        for member in members:
            if "previous" not in member.body:
                roots.append(member)
            if not member.fork and len(member.children) == 1:
                child = member.children[0]
                if child.body["lineage"] == member.body["lineage"]:
                    following[member] = child
                    children.add(child)
        if len(roots) > 1:
            for root in roots:
                self.add("ROOT_FORK", record=root.opening)
        visited = set()
        pieces = []
        forked = any(member.fork or len(member.children) > 1 for member in members)
        for member in sorted(members, key=lambda item: item in children):
            if member in visited:
                continue
            forked |= member in children
            connected = []
            current = member
            while current is not None and current not in visited:
                visited.add(current)
                connected.append(current)
                current = following.get(current)
            pieces.append(("previous" not in member.body, connected))
        if (len(pieces) != 1 or forked) and members[0].opening:
            self.add("HISTORY_DISCONNECTED", members[0].opening.stream)
        return pieces

    def _accept(self, kind: str, value: str, satisfied: bool = True) -> None:
        if satisfied:
            self.result["accepted"].append({"kind": kind, "value": value})
        else:
            self.add("EXPECTATION_NOT_MET")

    def expectations(self, cutover_ends: dict[str, Record]) -> None:
        opts = self.opts
        acceptable = cutover_ends.keys() | {
            s.opening.id
            for s in self.streams.values()
            if s.opening
            and s.body.get("previous", {}).get("ended") in ("write_error", "unsealed")
        }
        for wanted in opts.accept_discontinuities:
            self._accept("accept-discontinuity", wanted, wanted in acceptable)
        for wanted in opts.allow_partial_histories:
            stream = self.streams.get(wanted)
            self._accept(
                "allow-partial-history", wanted, stream is not None and stream.missing
            )
        proved = set()
        for flag, expectations in (
            ("expect-head", opts.expect_heads),
            ("expect-seq", opts.expect_sequences),
        ):
            for value in expectations:
                if flag == "expect-head":
                    stream, seq, record = head_expectation(value)
                else:
                    stream, seq = sequence_expectation(value)
                    record = ""
                state = self.streams.get(stream)
                tip = state.summary.get("tip") if state else None
                found = (
                    tip is not None
                    and tip["seq"] == seq
                    and (not record or record == tip["record"])
                )
                self._accept(flag, value, found)
                if found:
                    proved.add(stream)
        if opts.expect_lineage:
            self._accept(
                "expect-lineage",
                opts.expect_lineage,
                opts.expect_lineage in self.histories,
            )
        if opts.allow_prefix:
            self._accept("allow-prefix", "true")
        if opts.allow_unpinned:
            self._accept("allow-unpinned", "true")
        for item in cutover_ends.values():
            self.add("LEGACY_END_UNPROVEN", record=item)
        for stream, state in self.streams.items():
            if not state.opening or stream in proved:
                continue
            if state.summary["end"] == "open":
                self.add("END_UNPROVEN", record=state.last)
            elif state.summary["end"] in (
                "superseded_unsealed",
                "superseded_write_error",
            ):
                successor = state.children[0].opening
                if successor and successor.id not in opts.accept_discontinuities:
                    self.add("END_UNPROVEN", record=successor)
        self.result["histories"] = [
            {"lineage": lineage, "streams": [state.summary for state in members]}
            for lineage, members in sorted(self.histories.items())
        ]


def _finding_key(row: Document) -> tuple[str, str, int, str]:
    return row["code"], row.get("stream", ""), row.get("seq", -1), row.get("record", "")


def _accepted(finding: Document, accepted: set[tuple[str, str]]) -> bool:
    match finding["code"]:
        case "PREDECESSOR_NOT_PRESENTED":
            return ("allow-partial-history", finding["stream"]) in accepted
        case "LEGACY_END_UNPROVEN":
            return ("accept-discontinuity", finding["record"]) in accepted
        case _:
            return False


_DECIDING = {
    "INVALID": "invalid",
    "UNSUPPORTED": "unsupported",
    "INCOMPLETE": "incomplete",
    _PREFIX: "end_unproven",
}


def _finish(result: Document, opts: Options) -> None:
    result["findings"] = [
        item
        for _, item in sorted(
            {_finding_key(row): row for row in result["findings"]}.items()
        )
    ]
    accepted = {(a["kind"], a["value"]) for a in result["accepted"]}
    result["accepted"] = [{"kind": k, "value": v} for k, v in sorted(accepted)]
    classes = {f["class"] for f in result["findings"] if not _accepted(f, accepted)}
    result["integrity"] = "failed" if "invalid" in classes else "ok"
    result["completeness"] = next(
        (item for item in ("incomplete", "end_unproven") if item in classes), "complete"
    )
    if result["counts"]["scope"] == "full_history":
        result["counts"]["complete"] = not bool(
            classes & {"invalid", "unsupported", "incomplete"}
        )
    verdict = next((name for name, kind in _DECIDING.items() if kind in classes), "")
    if not verdict:
        if not opts.keys:
            verdict = "SELF-CONSISTENT ONLY"
        elif any(
            kind in ("allow-partial-history", "accept-discontinuity")
            for kind, _ in accepted
        ):
            verdict = "VALID, GAPS ACCEPTED"
        else:
            verdict = "VALID"
    if verdict == "INVALID":
        exit_code = 1
    elif verdict in ("UNSUPPORTED", "INCOMPLETE") or (
        verdict == _PREFIX and not opts.allow_prefix
    ):
        exit_code = 3
    else:
        exit_code = int(not opts.keys and not opts.allow_unpinned)
    result.update(verdict=verdict, exit_code=exit_code)
    result["limits"].sort()


def projection(result: Document) -> Document:
    """Extract the normative projection from a receipt v3 verify_result."""
    accepted = {(item["kind"], item["value"]) for item in result["accepted"]}
    deciding = _DECIDING.get(result["verdict"])
    projected = {
        key: result[key]
        for key in (
            "accepted",
            "completeness",
            "exit_code",
            "integrity",
            "trust",
            "trust_state",
            "verdict",
        )
    }
    projected["finding_codes"] = sorted(
        {
            f["code"]
            for f in result["findings"]
            if f["class"] == deciding and not _accepted(f, accepted)
        }
    )
    if result["verdict"] not in ("INVALID", "UNSUPPORTED", "INCOMPLETE"):
        projected["counts"] = result["counts"]
        projected["histories"] = [
            {
                "lineage": history["lineage"],
                "streams": [
                    {
                        key: s[key]
                        for key in ("end", "records", "stream", "previous", "tip")
                        if key in s
                    }
                    for s in history["streams"]
                ],
            }
            for history in result["histories"]
        ]
    return projected


def verify_paths(
    paths: Iterable[str | Path], options: Options | None = None
) -> tuple[Document, Document]:
    """Verify paths and return (full document, normative projection).

    Input and usage errors raise OSError or ValueError. Evidence failures are
    represented by findings and a verification exit code in the documents.
    """
    options = options or Options()
    inputs = [Path(path) for path in paths]
    options.validate(inputs)
    files, old, inventories, ignored = _discover(inputs, options)
    with closing(sqlite3.connect("")) as db:
        v = Verification(db, options, ignored)
        for item in files:
            v.discover_key(item)
        v.stage_files(files)
        v.verify_streams()
        v.verify_succession()
        excluded = (
            frozenset(file.path.name for file in files)
            if v.opts.directory
            else frozenset()
        )
        token = _recorder_file_exclusions.set(excluded)
        try:
            unproven = verify_cutover(v, old, inventories, bool(files))
        finally:
            _recorder_file_exclusions.reset(token)
        v.result["counts"] = appraise(v)
        v.expectations(unproven)
        v.result["trust"]["keys"] = sorted(v.used)
        if not files and v.result["legacy"]:
            raise ValueError(
                "legacy-only evidence requires the legacy verification path"
            )
        if not files and not v.result["findings"]:
            v.add("NO_EVIDENCE")
    _finish(v.result, options)
    return v.result, projection(v.result)
