# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""Recorder directory discovery shared by cutover and restart verification."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .group import (
    _GATE_ENTRY_TYPE,
    _GROUP_ARTIFACT,
    _HEX32,
    GROUP_INVALID,
    _check_recorder_entry,
    _inventory,
    _open_evidence_file,
    _parse_evidence_filename,
    _record_hash,
    verify_receipt_group,
)
from .input_file import MAX_RECORDER_LINE_BYTES, iter_verifier_jsonl_lines
from .line_space import trim_go_space
from .rawjson import SourcedReceipt, go_raw_message_bytes, object_member_span
from .receipt import (
    ACTION_ENTRY_TYPE,
    EVIDENCE_ENTRY_TYPE,
    V2_RECORD_TYPE,
    ReceiptError,
    _reject_duplicate_pairs,
    normalize_evidence_receipt,
    validate_action_record,
    verify_evidence_chain,
)
from .secret_egress import validate_source as validate_secret_egress_source

Document = dict[str, Any]
Index = dict[str, list[tuple[int, Path]]]


def run_base(session: str) -> str | None:
    base, sep, _ = session.partition(".run.")
    return base if base and sep else None


def _json(text: str) -> Document:
    value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    if not isinstance(value, dict):
        raise ReceiptError("expected a JSON object")
    return value


def _first_entry(path: Path) -> Document | None:
    try:
        with _open_evidence_file(path) as source:
            while raw := source.readline(MAX_RECORDER_LINE_BYTES + 3):
                if (
                    not raw.endswith(b"\n")
                    or len(raw.rstrip(b"\r\n")) > MAX_RECORDER_LINE_BYTES
                ):
                    return None
                text = trim_go_space(raw.decode("utf-8"))
                if text:
                    entry = _json(text)
                    if (
                        type(entry.get("v")) is int
                        and type(entry.get("seq")) is int
                        and isinstance(entry.get("type"), str)
                        and isinstance(entry.get("session_id"), str)
                    ):
                        return entry
                    return None
    except (ValueError, OSError, ReceiptError, RecursionError):
        return None
    return None


def recorder_index(directory: Path, *, exclude_groups: bool = False) -> Index:
    index: Index = defaultdict(list)
    for path in sorted(directory.iterdir()):
        parsed = _parse_evidence_filename(path.name)
        if parsed is not None:
            session, seq = parsed
            index[session].append((seq, path))
    ordinary: Index = {}
    for session, shards in sorted(index.items()):
        shards.sort()
        if exclude_groups:
            genesis = next((path for seq, path in shards if seq == 0), None)
            if (
                genesis is not None
                and (_first_entry(genesis) or {}).get("type") == _GATE_ENTRY_TYPE
            ):
                continue
        ordinary[session] = shards
    return ordinary


def _missing(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def verify_receipt_groups(
    directory: str | Path, trusted_keys: list[str]
) -> list[Document]:
    """Verify all published groups, including orphan artifacts and first gates.

    Inventory errors raise instead of letting partial results imply a pass.
    """
    root = Path(directory)
    entries = sorted(root.iterdir())
    artifacts = [p for p in entries if p.name.startswith("receipt-group-")]
    gates = []
    for path in entries:
        parsed = _parse_evidence_filename(path.name)
        if parsed is None or parsed[1] != 0:
            continue
        first = _first_entry(path)
        if first and first["type"] == _GATE_ENTRY_TYPE:
            gates.append(first.get("detail"))
    if not artifacts and not gates:
        return []
    identity = root.lstat()
    before = _inventory(root)

    def orphan(group: str, detail: str) -> Document:
        return {
            "group_id": group,
            "verdict": GROUP_INVALID,
            "error": detail,
            "shard_count": 0,
        }

    reports = []
    try:
        openings = []
        for artifact in artifacts:
            name = artifact.name
            if not _GROUP_ARTIFACT.fullmatch(name):
                raise ValueError(f"unknown receipt group artifact {name!r}")
            group = name[len("receipt-group-") :][:32]
            if name.endswith("-open.json"):
                openings.append(group)
            elif _missing(root / f"receipt-group-{group}-open.json"):
                reports.append(
                    orphan(group, "receipt group artifact has no opening manifest")
                )
        for gate in gates:
            group = gate.get("group_id") if isinstance(gate, dict) else ""
            if not isinstance(group, str) or not _HEX32.fullmatch(group):
                group = ""
            if not group or _missing(root / f"receipt-group-{group}-open.json"):
                reports.append(orphan(group, "gated session has no opening manifest"))
        reports.extend(
            verify_receipt_group(root, group, trusted_keys) for group in openings
        )
        return reports
    finally:
        try:
            changed = not os.path.samestat(
                identity, root.lstat()
            ) or before != _inventory(root)
        except (OSError, ValueError):
            changed = True
        if changed:
            raise OSError("receipt group directory changed during verification")


@dataclass(slots=True)
class RecorderRun:
    action: list[Document] = field(default_factory=list)
    evidence: list[Document] = field(default_factory=list)
    last: Document | None = None
    outer_error: str = ""


def _wrapper(line: str, entry: Document) -> tuple[bytes, str]:
    span = object_member_span(line, 0, "detail")
    if span is None and entry.get("detail") is not None:
        raise ReceiptError("recorder detail is malformed")
    detail = line[slice(*span)].encode() if span else b""
    if entry["type"] in (ACTION_ENTRY_TYPE, EVIDENCE_ENTRY_TYPE) and not span:
        raise ReceiptError("recorder entry requires receipt detail")
    return detail, _record_hash(entry, detail)


def _append_receipt(
    run: RecorderRun, raw: str, receipt: Document, evidence: bool
) -> None:
    validate_secret_egress_source(receipt, raw)
    if evidence:
        normalize_evidence_receipt(receipt)
        run.evidence.append(receipt)
    else:
        record = receipt.get("action_record")
        if not isinstance(record, dict):
            raise ReceiptError("action_record must be an object")
        validate_action_record(record)
        if not isinstance(receipt.get("signer_key"), str):
            raise ReceiptError("signer_key must be a string")
        span = object_member_span(raw, 0, "ext")
        if span is not None:
            receipt = SourcedReceipt(receipt, go_raw_message_bytes(raw[slice(*span)]))
        run.action.append(receipt)


def _append_entry(run: RecorderRun, line: str, entry: Document, session: str) -> None:
    seq = entry.get("seq")
    if (
        entry.get("session_id") != session
        or type(seq) is not int
        or not 0 <= seq < 2**64
        or type(entry.get("v")) is not int
        or not isinstance(entry.get("type"), str)
    ):
        raise ReceiptError("invalid recorder entry or session binding")
    detail, computed = _wrapper(line, entry)
    last = run.last
    try:
        _check_recorder_entry(entry, seq)
        projection = (
            "session_id",
            "trace_id",
            "type",
            "transport",
            "summary",
            "raw_ref",
            "prev_hash",
        )
        if entry["v"] > 1:
            projection += ("event_kind",)
        if entry["v"] == 3:
            projection += ("chain_kind", "writer_instance_id")
            if entry.get("chain_kind") != "native_live" or not entry.get(
                "writer_instance_id"
            ):
                raise ValueError("recorder namespace is invalid")
        elif entry.get("chain_kind") or entry.get("writer_instance_id"):
            raise ValueError("unbound recorder namespace")
        if any(
            not isinstance((value := entry.get(name, "")), str) or "\0" in value
            for name in projection
        ):
            raise ValueError("unbound recorder field")
        if (
            computed != entry.get("hash")
            or (
                last is not None
                and (
                    seq != last["seq"] + 1
                    or last["hash"] != entry.get("prev_hash")
                    or (entry["v"] == 3) != (last["v"] == 3)
                    or entry.get("chain_kind") != last.get("chain_kind")
                    or entry.get("writer_instance_id") != last.get("writer_instance_id")
                )
            )
            or (last is None and seq == 0 and entry.get("prev_hash") != "genesis")
        ):
            raise ValueError("recorder sequence or hash mismatch")
    except ValueError as exc:
        run.outer_error = run.outer_error or str(exc)
    run.last = entry
    if entry["type"] in (ACTION_ENTRY_TYPE, EVIDENCE_ENTRY_TYPE):
        raw = detail.decode("utf-8")
        _append_receipt(run, raw, _json(raw), entry["type"] == EVIDENCE_ENTRY_TYPE)


def _lines(path: Path) -> Iterator[bytes]:
    # The legacy line reader bounds each shard and checks its file identity.
    # The additional check keeps symlinks out of the directory inventory.
    if path.is_symlink():
        raise ReceiptError("recorder shard is a symlink")
    yield from iter_verifier_jsonl_lines(path)


def read_run(
    session: str,
    shards: list[tuple[int, Path]],
    *,
    recovery_offset: int | None = None,
    include_torn: bool = False,
) -> RecorderRun:
    """Decode the ordered shards and check their outer recorder chain."""
    run = RecorderRun()
    starts = set()
    mode = None
    for index, (start, path) in enumerate(shards):
        if start in starts:
            raise ReceiptError("ambiguous evidence shard sequence start")
        starts.add(start)
        recovering = recovery_offset is not None and index == len(shards) - 1
        consumed = 0
        first = True
        for raw in _lines(path):
            offset = consumed
            consumed += len(raw)
            if not raw.endswith(b"\n"):
                if not recovering or offset != recovery_offset:
                    raise ReceiptError("recorder shard has a torn tail")
                if not include_torn:
                    break
                try:
                    entry = _json(trim_go_space(raw.decode("utf-8")))
                except (ValueError, ReceiptError):
                    break  # An unreadable final fragment is the observed damage.
            else:
                text = trim_go_space(raw.decode("utf-8"))
                if not text:
                    continue
                entry = _json(text)
            text = trim_go_space(raw.decode("utf-8"))
            bare = entry.get("record_type") == V2_RECORD_TYPE
            if mode is not None and mode != bare:
                raise ReceiptError("mixed recorder and bare evidence")
            mode = bare
            if bare:
                _append_receipt(run, text, entry, True)
            else:
                if first and (
                    entry.get("seq") != start or run.last is None and start != 0
                ):
                    run.outer_error = (
                        run.outer_error or "recorder shard sequence mismatch"
                    )
                _append_entry(run, text, entry, session)
            first = False
    return run


def read_legacy_file(path: Path) -> tuple[RecorderRun, bool]:
    """Decode a single selected legacy input using its native discriminator."""
    run = RecorderRun()
    mode = ""
    for raw in iter_verifier_jsonl_lines(path):
        text = trim_go_space(raw.decode("utf-8"))
        if not text:
            continue
        entry = _json(text)
        if entry.get("record_type") == V2_RECORD_TYPE:
            kind = "evidence"
        elif (
            not entry.get("record_type")
            and type(entry.get("version")) is int
            and entry["version"] == 1
            and not entry.get("type")
        ):
            kind = "action"
        elif (
            entry.get("type")
            and isinstance(entry.get("session_id"), str)
            and entry["session_id"]
        ):
            kind = "recorder"
        else:
            return RecorderRun(), False
        if mode and kind != mode:
            raise ReceiptError("malformed or mixed legacy record")
        mode = kind
        if kind == "recorder":
            parsed = _parse_evidence_filename(path.name)
            if parsed and (
                parsed[0] != entry["session_id"]
                or run.last is None
                and parsed[1] != entry.get("seq")
            ):
                raise ReceiptError("recorder entry disagrees with evidence file name")
            if run.last and entry["session_id"] != run.last["session_id"]:
                raise ReceiptError("recorder session changed")
            _append_entry(run, text, entry, entry["session_id"])
            if run.outer_error:
                raise ReceiptError(run.outer_error)
        else:
            _append_receipt(run, text, entry, kind == "evidence")
    return run, mode == "recorder"


def evidence_chain_valid(evidence: list[Document], keys: set[str]) -> bool:
    # The v2 signer ID is its raw key. The existing unpinned API is
    # structural-only. Directory verification follows Go and checks the signer
    # embedded in the first evidence receipt even in the absence of pins.
    signer = evidence[0]["signature"]["signer_key_id"]
    return (not keys or signer in keys) and bool(
        verify_evidence_chain(evidence, signer)["valid"]
    )
