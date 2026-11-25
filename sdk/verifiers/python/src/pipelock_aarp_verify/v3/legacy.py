# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""Legacy evidence and content-addressed cutover inventories."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from ..chain_set import verify_base
from ..cli import _close_ends_chain
from ..group import (
    GROUP_INCOMPLETE,
    GROUP_INVALID,
    GROUP_VALID,
    _parse_evidence_filename,
)
from ..input_file import _open_regular_input
from ..legacy_directory import (
    RecorderRun,
    evidence_chain_valid,
    read_legacy_file,
    read_run,
    recorder_index,
    run_base,
    verify_receipt_groups,
)
from ..receipt import (
    ReceiptError,
    _canonicalize_action_record,
    receipt_hash,
    verify_evidence_chain,
)
from ..secret_egress import SecretEgressError
from .wire import (
    DIGEST,
    ID128,
    KEY_HEX,
    MAX_INTEGER,
    Document,
    Record,
    WireError,
    digest,
    parse_payload,
)

if TYPE_CHECKING:
    from .verify import Verification

_ACTION = "action_v1"
_EVIDENCE = "evidence_v2"
_GROUP = "receipt_group"
_PREFIX = "VALID PREFIX, END UNPROVEN"
_EMPTY = digest(b'{"chains":[],"v":1}')
# Even a row with two digests and the largest wire integer fits in this bound.
_INVENTORY_ITEM_LIMIT = 256
_INVENTORY_TAIL = re.compile(rb'(?:,"journal":"sha256:[0-9a-f]{64}")?,"v":1}')
_ERRORS = (OSError, ValueError, ReceiptError, SecretEgressError, RecursionError)

Identity = tuple[str, str]


def _is_group(name: str) -> bool:
    return name.startswith("receipt-group-") and name.endswith(".json")


def legacy_candidate(name: str) -> bool:
    return bool(
        _parse_evidence_filename(name)
        or _is_group(name)
        or name
        in (
            "activation-receipts.jsonl",
            "redaction-receipts.jsonl",
            "ratification-receipts.jsonl",
        )
    )


@dataclass(slots=True)
class _Legacy:
    seq: int
    record: str
    verdict: str
    position: int = 0
    forked: bool = False
    seen: dict[int, str] | None = None

    def compare_cutover_position(self, row: Document) -> int:
        if self.record != row["record"] and not self.forked:
            for position, record in (self.seen or {}).items():
                if 0 <= position < self.position and record == row["record"]:
                    return 1
            # An absent sequence-zero pin can start a later signing epoch.
            if row["format"] == _ACTION and row["seq"] == 0 and self.seq > 0:
                return -1
        return self.seq - row["seq"]


def _legacy_row(key: Identity, status: str, passed: bool) -> Document:
    return {
        "format": key[0],
        "chain": key[1],
        "class": "pass" if passed else "failure",
        "verdict": status,
    }


def _result_label(v: Verification, key: Identity, item: _Legacy) -> Document:
    fmt = key[0]
    if fmt == _GROUP:
        return _legacy_row(key, item.verdict, item.verdict == GROUP_VALID)
    label = "EVIDENCE CHAIN" if fmt == _EVIDENCE else "CHAIN"
    if item.verdict == "INVALID" or item.forked:
        return _legacy_row(key, label + " BROKEN", False)
    if item.verdict == _PREFIX:
        return _legacy_row(
            key,
            _PREFIX,
            v.opts.allow_prefix and bool(v.opts.keys or v.opts.allow_unpinned),
        )
    if not v.opts.keys:
        return _legacy_row(key, label + " UNPINNED", v.opts.allow_unpinned)
    return _legacy_row(key, label + " VALID", True)


def _chains(
    rows: list[Document], recorder: bool, action: bool
) -> Iterator[list[Document]]:
    start = 0
    if not recorder:
        for pos, row in enumerate(rows[1:], start=1):
            rec = row["action_record"] if action else row
            if rec["chain_seq"] == 0 and (not action or not rec.get("key_transition")):
                yield rows[start:pos]
                start = pos
    if rows:
        yield rows[start:]


class _LegacyVerifier:
    def __init__(self, verifier: Verification) -> None:
        self.v = verifier
        self.rows: dict[Identity, _Legacy] = {}
        self.positions: dict[Identity, dict[int, str]] = defaultdict(dict)
        self.keys = set(verifier.opts.keys)

    def _fail(self, session: str, exc: BaseException) -> None:
        self.v.add("LEGACY_INVALID")
        label = (
            "CHAIN UNAVAILABLE"
            if isinstance(exc, OSError) and not isinstance(exc, FileNotFoundError)
            else "CHAIN BROKEN"
        )
        self.v.result["legacy"].append(_legacy_row((_ACTION, session), label, False))

    def add_batch(self, batch: RecorderRun, recorder: bool) -> None:
        for action, receipts in ((True, batch.action), (False, batch.evidence)):
            for chain in _chains(receipts, recorder, action):
                self._add_chain(chain, action)

    def _add_chain(self, chain: list[Document], action: bool) -> None:
        fmt = _ACTION if action else _EVIDENCE
        if action:
            records = [row["action_record"] for row in chain]
            hashes = [digest(_canonicalize_action_record(record)) for record in records]
            identity = records[0].get("run_nonce") or hashes[0]
            seqs = range(len(chain))
            signers = [row["signer_key"] for row in chain]
            final_seq = records[-1]["chain_seq"]
            verdict = "VALID" if _close_ends_chain(chain) else _PREFIX
            try:
                valid = verify_evidence_chain(chain, ",".join(sorted(self.keys)), True)[
                    "valid"
                ]
            except _ERRORS:
                valid = False
        else:
            hashes = ["sha256:" + receipt_hash(row) for row in chain]
            identity = hashes[0]
            seqs = [row["chain_seq"] for row in chain]
            signers = [row["signature"]["signer_key_id"] for row in chain]
            final_seq = seqs[-1]
            verdict = _PREFIX
            try:
                valid = evidence_chain_valid(chain, self.keys)
            except _ERRORS:
                valid = False
        key = fmt, identity
        seen = self.positions[key]
        for seq, value, signer in zip(seqs, hashes, signers, strict=True):
            if seq > MAX_INTEGER:
                seen[-1] = "out_of_range"
            else:
                if seq in seen and seen[seq] != value:
                    seen[-1] = "fork"
                seen[seq] = value
            if isinstance(signer, str) and KEY_HEX.fullmatch(signer.lower()):
                self.v.used.add(digest(bytes.fromhex(signer)))
        position = seq
        if position > MAX_INTEGER or final_seq > MAX_INTEGER:
            self.v.add("LEGACY_INVALID")
            return
        previous = self.rows.get(key)
        was_invalid = previous is not None and previous.verdict == "INVALID"
        if previous is None or position > previous.position:
            previous = _Legacy(final_seq, hashes[-1], verdict, position, seen=seen)
        if not valid:
            self.v.add("LEGACY_INVALID")
        if not valid or was_invalid:
            previous.verdict = "INVALID"
        previous.forked = -1 in seen
        self.rows[key] = previous

    def verify(self, paths: list[Path]) -> dict[Identity, _Legacy]:
        sessions: dict[Path, set[str]] = defaultdict(set)
        for path in paths:
            if self.v.opts.directory:
                selected = sessions[path.parent]
                if _is_group(path.name):
                    continue
                if parsed := _parse_evidence_filename(path.name):
                    selected.add(parsed[0])
                    continue
            try:
                batch, recorder = read_legacy_file(path)
                if batch.action or batch.evidence:
                    self.add_batch(batch, recorder)
                else:
                    self.v.add("UNRECOGNIZED_FILE")
            except _ERRORS as exc:
                self._fail("", exc)
        for root, selected in sessions.items():
            grouped = self._groups(root)
            index = recorder_index(root, exclude_groups=grouped)
            bases = set()
            for session in sorted(selected & index.keys()):
                if base := run_base(session):
                    bases.add(base)
                try:
                    batch = read_run(session, index[session])
                    if batch.outer_error:
                        raise ReceiptError(batch.outer_error)
                    if batch.action or batch.evidence:
                        self.add_batch(batch, True)
                    else:
                        self.v.result["ignored_files"] += 1
                except _ERRORS as exc:
                    self._fail(session, exc)
            for base in sorted(bases):
                self._continuity(root, base, grouped)
        result = self.v.result["legacy"]
        result.extend(
            _result_label(self.v, key, item) for key, item in self.rows.items()
        )
        result.sort(key=lambda r: (r["format"], r["chain"], r["verdict"], r["class"]))
        return self.rows

    def _groups(self, root: Path) -> bool:
        try:
            reports = verify_receipt_groups(root, sorted(self.keys))
        except (OSError, ValueError) as exc:
            verdict, code = (
                (GROUP_INCOMPLETE, "LEGACY_GROUP_INCOMPLETE")
                if isinstance(exc, OSError)
                else (GROUP_INVALID, "LEGACY_INVALID")
            )
            self.v.add(code)
            self.v.result["legacy"].append(_legacy_row((_GROUP, ""), verdict, False))
            return True
        for report in reports:
            verdict = report["verdict"]
            if verdict != GROUP_VALID:
                self.v.add(
                    "LEGACY_GROUP_INCOMPLETE"
                    if verdict == GROUP_INCOMPLETE
                    else "LEGACY_INVALID"
                )
            head = (
                report.get("close_manifest_sha256")
                or report.get("open_manifest_sha256")
                or ""
            )
            if head and not head.startswith("sha256:"):
                head = "sha256:" + head
            self.rows[(_GROUP, report["group_id"])] = _Legacy(
                report["shard_count"], head, verdict
            )
        return bool(reports)

    def _continuity(self, root: Path, base: str, grouped: bool) -> None:
        try:
            if verify_base(
                root, base, tuple(sorted(self.keys)), exclude_groups=grouped
            )["healthy"]:
                return
            label = "RESTART CONTINUITY FAILED"
        except _ERRORS:
            label = "RESTART CONTINUITY INCOMPLETE"
        self.v.add("LEGACY_INVALID")
        self.v.result["legacy"].append(_legacy_row((_ACTION, base), label, False))


def _identity(row: Document) -> Identity:
    return row["format"], row["chain"]


def _valid_row(row: Document) -> bool:
    if not isinstance(row, dict) or set(row) != {"chain", "format", "record", "seq"}:
        return False
    if (
        not isinstance(row["record"], str)
        or not DIGEST.fullmatch(row["record"])
        or type(row["seq"]) is not int
        or not 0 <= row["seq"] <= MAX_INTEGER
        or not isinstance(row["chain"], str)
    ):
        return False
    fmt, chain = _identity(row)
    return bool(
        fmt == _ACTION
        and (ID128.fullmatch(chain) or DIGEST.fullmatch(chain))
        or fmt == _EVIDENCE
        and DIGEST.fullmatch(chain)
        or fmt == _GROUP
        and ID128.fullmatch(chain)
    )


def _read_inventory_row(source: BinaryIO) -> bytes | None:
    raw = bytearray(b"{")
    for _ in range(_INVENTORY_ITEM_LIMIT - 1):
        token = source.read(1)
        if not token:
            return None
        raw.extend(token)
        if token == b"}":
            return bytes(raw)
    return None


def _read_inventory(path: Path, pin: str, chains: int) -> list[Document] | None:
    prefix = b'{"chains":['
    with _open_regular_input(path) as source:
        if source.read(len(prefix)) != prefix:
            return None
        hashed = hashlib.sha256(prefix)
        rows: list[Document] = []
        token = source.read(1)
        while token == b"{":
            if 0 <= chains <= len(rows):
                return None
            raw = _read_inventory_row(source)
            if raw is None:
                return None
            try:
                row = parse_payload(raw)
            except WireError:
                return None
            if not _valid_row(row) or (rows and _identity(rows[-1]) >= _identity(row)):
                return None
            rows.append(row)
            hashed.update(raw)
            token = source.read(1)
            if token != b",":
                break
            hashed.update(token)
            token = source.read(1)
            if token != b"{":
                return None
        if token != b"]" or (chains >= 0 and len(rows) != chains):
            return None
        tail = source.read(_INVENTORY_ITEM_LIMIT)
        if not _INVENTORY_TAIL.fullmatch(tail) or source.read(1):
            return None
        hashed.update(token)
        hashed.update(tail)
    return rows if "sha256:" + hashed.hexdigest() == pin else None


def _membership_known(v: Verification) -> bool:
    if not v.histories or any(
        not any(
            "legacy_cutover" in stream.body and "previous" not in stream.body
            for stream in members
        )
        for members in v.histories.values()
    ):
        return False
    return not any(
        item.kind == "stream_open"
        and (
            item.unknown
            or "previous" not in item.body
            or item.body.get("lineage") not in v.histories
        )
        for stream in v.streams.values()
        if stream.limit < 0
        for item in stream.fork
    )


def verify_cutover(
    v: Verification,
    legacy: list[Path],
    inventories: dict[str, list[Path]],
    claimed: bool,
) -> dict[str, Record]:
    old = _LegacyVerifier(v).verify(legacy)
    if old and claimed and not v.opts.directory:
        raise ValueError(
            "old-format and v3 evidence require directory scope; verify the directory"
        )
    if not claimed:
        return {}
    known = _membership_known(v)
    listed: set[Identity] = set()
    checked = set()
    unproven = {}
    for _, stream in sorted(v.streams.items()):
        cutover = stream.body.get("legacy_cutover")
        opener = stream.opening
        if cutover is None or opener is None:
            continue
        pin, count = cutover["inventory"], cutover["chains"]
        checked.add(pin)
        rows = None
        paths = inventories.get(pin, ())
        if paths:
            for path in paths:
                loaded = _read_inventory(path, pin, count)
                if loaded is None:
                    v.add("CUTOVER_INVENTORY_MISMATCH", record=opener)
                else:
                    rows = loaded
        elif pin != _EMPTY:
            v.add("CUTOVER_INVENTORY_NOT_PRESENTED", record=opener)
        elif count > 0:
            v.add("CUTOVER_INVENTORY_MISMATCH", record=opener)
        else:
            rows = []
        if rows is None:
            known = False
            continue
        for row in rows:
            key = _identity(row)
            listed.add(key)
            actual = old.get(key)
            if actual is None:
                v.add("LEGACY_CHAIN_NOT_PRESENTED", record=opener)
                continue
            position = actual.compare_cutover_position(row)
            if position > 0:
                v.add("LEGACY_EXTENDED_AFTER_CUTOVER", record=opener)
            elif position < 0:
                v.add("LEGACY_CHAIN_TRUNCATED", record=opener)
            elif actual.forked or actual.record != row["record"]:
                v.add("LEGACY_CHAIN_HEAD_MISMATCH", record=opener)
            elif actual.verdict == _PREFIX:
                unproven[opener.id] = opener
    for pin in sorted(inventories.keys() - checked):
        for path in inventories[pin]:
            if _read_inventory(path, pin, -1) is None:
                v.add("CUTOVER_INVENTORY_MISMATCH")
    if old.keys() - listed:
        v.add("LEGACY_CHAIN_UNLISTED" if known else "LEGACY_MEMBERSHIP_UNKNOWN")
    return unproven
