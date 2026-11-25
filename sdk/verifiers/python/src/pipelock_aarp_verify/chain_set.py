# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""Verify recorder restart continuity and signed recovery observations."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .group import _go_json, _open_evidence_file, _require_canonical_utc
from .legacy_directory import (
    Document,
    Index,
    RecorderRun,
    evidence_chain_valid,
    read_run,
    recorder_index,
    run_base,
)
from .receipt import (
    ReceiptError,
    _reject_duplicate_pairs,
    _session_open,
    _verify_action_chain,
    compute_session_open_genesis,
    receipt_hash,
    verify_evidence_chain,
)
from .recovery import _FIELDS, _read_regular, _validate, check_recovery_binding
from .secret_egress import SecretEgressError

_LINK_FILE = re.compile(r"chain-link-(.+)\.json")
_HEX = re.compile(r"[0-9a-f]{64}")
_SIGNATURE = re.compile(r"ed25519:[0-9a-fA-F]{128}")
_LINK_FIELDS = (
    "version",
    "predecessor_session",
    "predecessor_tail_seq",
    "predecessor_tail_hash",
    "predecessor_signer_key",
    "successor_session",
    "successor_signer_key",
    "linked_at",
)
_ROTATION_FIELDS = (
    "version",
    "session_id",
    "prior_signer_key",
    "prior_final_seq",
    "prior_tail_hash",
    "new_signer_key",
    "rotated_at",
)
_READ_FAILURES = (OSError, ValueError, ReceiptError, SecretEgressError, RecursionError)


def _in_base(session: str, base: str) -> bool:
    return session == base or run_base(session) == base


def _decode_signed(raw: bytes) -> Document:
    artifact = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    if (
        not isinstance(artifact, dict)
        or type(artifact.get("version")) is not int
        or artifact["version"] != 1
    ):
        raise ValueError("invalid signed restart artifact version")
    return artifact


def _verify_artifact(value: Document, *, rotation: bool) -> Document:
    if type(value.get("version")) is not int or value["version"] != 1:
        raise ValueError("invalid signed restart artifact version")
    if rotation:
        fields, signature = _ROTATION_FIELDS, "endorsement"
        keys = ("prior_signer_key", "new_signer_key", "prior_tail_hash")
        sequence, timestamp = "prior_final_seq", "rotated_at"
        sessions = ("session_id",)
        domain = b"pipelock-rotation-endorsement-v1\0"
    else:
        fields, signature = _LINK_FIELDS, "signature"
        keys = (
            "successor_signer_key",
            "predecessor_signer_key",
            "predecessor_tail_hash",
        )
        sequence, timestamp = "predecessor_tail_seq", "linked_at"
        sessions = ("predecessor_session", "successor_session")
        domain = b"pipelock-chain-link-v1\0"
    if (
        set(value) != {*fields, signature}
        or any(
            not isinstance(value[k], str) or not _HEX.fullmatch(value[k]) for k in keys
        )
        or any(not isinstance(value[k], str) or not value[k].strip() for k in sessions)
        or type(value[sequence]) is not int
        or not 0 <= value[sequence] < 2**64
        or not isinstance(value[signature], str)
        or not _SIGNATURE.fullmatch(value[signature])
        or (rotation and value[keys[0]] == value[keys[1]])
        or (not rotation and value[sessions[0]] == value[sessions[1]])
    ):
        raise ValueError("invalid signed restart artifact fields")
    ts = value[timestamp]
    _require_canonical_utc(ts, timestamp)
    datetime.fromisoformat("2000" + ts[4:] if ts.startswith("0000") else ts)
    if ts == "0001-01-01T00:00:00Z":
        raise ValueError("restart artifact time is zero")
    message = domain + _go_json({key: value[key] for key in fields})
    if rotation:
        message = hashlib.sha256(message).digest()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(value[keys[0]])).verify(
            bytes.fromhex(value[signature][8:]),
            message,
        )
    except InvalidSignature as exc:
        raise ValueError("invalid signed restart artifact signature") from exc
    return value


def load_rotation_endorsement(path: str | Path) -> Document:
    """Read and authenticate a rotation endorsement before applying it."""
    return _verify_artifact(
        _decode_signed(_read_regular(Path(path), 64 << 10)), rotation=True
    )


@dataclass(slots=True)
class _Chain:
    run: RecorderRun
    valid: bool = False
    link: Document | None = None
    seal: Document | None = None
    trust: str = ""


def _receipt_position(receipt: Document) -> tuple[int, str, str]:
    return (
        receipt["action_record"]["chain_seq"],
        receipt_hash(receipt),
        receipt["signer_key"],
    )


def _link_position(link: Document) -> tuple[int, str, str]:
    return (
        link["predecessor_tail_seq"],
        link["predecessor_tail_hash"],
        link["predecessor_signer_key"],
    )


def _tail_finding(predecessor: _Chain, link: Document) -> str:
    wanted = _link_position(link)
    actions = predecessor.run.action
    if _receipt_position(actions[-1]) == wanted:
        return ""
    if any(_receipt_position(item)[:2] == wanted[:2] for item in actions[:-1]):
        return "appended_after_link"
    return "link_tail_mismatch"


def _endorsement_matches(link: Document, endorsement: Document) -> bool:
    return (
        link["predecessor_session"] == endorsement["session_id"]
        and link["predecessor_signer_key"] == endorsement["prior_signer_key"]
        and link["predecessor_tail_hash"] == endorsement["prior_tail_hash"]
        and link["predecessor_tail_seq"] == endorsement["prior_final_seq"]
        and link["successor_signer_key"] == endorsement["new_signer_key"]
    )


def _verify_chains(
    chains: dict[str, _Chain],
    keys: set[str],
    endorsements: tuple[Document, ...],
    add,
) -> None:
    candidates = {
        session: next(
            (i for i, e in enumerate(endorsements) if _endorsement_matches(c.link, e)),
            None,
        )
        for session, c in chains.items()
        if c.link and c.link["successor_signer_key"] != c.link["predecessor_signer_key"]
    }
    consumed = set(candidates.values())
    resolved: set[str] = set()

    def verify(session: str, allow_endorsement: bool) -> None:
        chain = chains[session]
        actions = chain.run.action
        accepted = keys.copy()
        if (
            allow_endorsement
            and session in candidates
            and candidates[session] is not None
        ):
            link = chain.link
            pred = chains.get(link["predecessor_session"])
            if (
                pred
                and pred.valid
                and pred.run.action
                and not _tail_finding(pred, link)
            ):
                chain.trust = "endorsed"
                if accepted:
                    accepted.add(link["successor_signer_key"])
        transitions: dict[int, str] = {}
        try:
            for i, endorsement in enumerate(endorsements):
                if (
                    i not in consumed
                    and endorsement["session_id"] == session
                    and actions
                ):
                    expected = (
                        endorsement["prior_final_seq"],
                        endorsement["prior_tail_hash"],
                        endorsement["prior_signer_key"],
                    )
                    if expected == _receipt_position(actions[-1]):
                        continue  # A handoff may be missing its link file.
                    index = next(
                        (
                            j
                            for j, r in enumerate(actions[:-1])
                            if _receipt_position(r) == expected
                        ),
                        None,
                    )
                    if (
                        index is None
                        or not accepted
                        or actions[index + 1]["signer_key"]
                        != endorsement["new_signer_key"]
                        or not actions[index + 1]["action_record"].get("key_transition")
                    ):
                        raise ReceiptError(
                            "rotation endorsement does not bind a trusted transition"
                        )
                    if index + 1 in transitions:
                        raise ReceiptError("multiple endorsements for one rotation")
                    transitions[index + 1] = endorsement["new_signer_key"]
            valid = (
                not actions
                or _verify_action_chain(
                    actions,
                    ",".join(sorted(accepted)),
                    True,
                    endorsed_transitions=transitions,
                )["valid"]
            ) and (
                not chain.run.evidence
                or evidence_chain_valid(chain.run.evidence, accepted)
            )
            if not valid:
                add("corrupt_chain", session)
            chain.valid = bool(valid and not chain.run.outer_error)
        except _READ_FAILURES:
            add("corrupt_chain", session)
        resolved.add(session)

    pending = list(chains)
    while pending:
        waiting = []
        for session in pending:
            chain = chains[session]
            pred = chain.link["predecessor_session"] if chain.link else ""
            if (
                candidates.get(session) is not None
                and pred in chains
                and pred not in resolved
            ):
                waiting.append(session)
            else:
                verify(session, True)
        if len(waiting) == len(pending):
            for session in waiting:
                verify(session, False)
            break
        pending = waiting


def _recovery(
    index: Index,
    keys: set[str],
    seal: Document,
    successor: _Chain,
) -> None:
    predecessor, target = seal["predecessor_session"], seal["successor_session"]
    if (
        seal["predecessor_signer_key"] != seal["successor_signer_key"]
        and seal["successor_signer_key"] not in keys
    ):
        raise ValueError("recovery successor signer is untrusted")
    shards = index.get(predecessor, [])
    if not shards or shards[-1][1].name != seal["shard"]:
        raise ValueError("recovery must bind the final predecessor shard")
    # Hash the exact shard bytes and keep only the bounded recorder line being
    # examined. The signed offset must mark the start of a nonempty torn line.
    shard = shards[-1][1]
    with _open_evidence_file(shard) as source:
        hasher = hashlib.sha256()
        length = 0
        while chunk := source.read(1 << 20):
            hasher.update(chunk)
            length += len(chunk)
        offset = seal["damage_offset"]
        if offset >= length:
            raise ValueError("recovery shard has no damaged tail")
        if offset:
            source.seek(offset - 1)
            if source.read(1) != b"\n":
                raise ValueError("recovery damage offset is not a line boundary")
        source.seek(offset)
        while chunk := source.read(1 << 20):
            if b"\n" in chunk:
                raise ValueError("recovery tail contains a complete line")
    observed = read_run(predecessor, shards, recovery_offset=offset)
    checked = read_run(predecessor, shards, recovery_offset=offset, include_torn=True)
    actions = observed.action
    if (
        checked.outer_error
        or not successor.run.action
        or checked.action
        and not verify_evidence_chain(checked.action, ",".join(sorted(keys)), True)[
            "valid"
        ]
        or checked.evidence
        and not evidence_chain_valid(checked.evidence, keys)
    ):
        raise ValueError("recovery prefix did not verify")
    head = successor.run.action[0]
    opening = _session_open(head["action_record"].get("session_control"))
    if (
        not opening
        or opening.get("recorder_session") != target
        or head["action_record"]["chain_seq"] != 0
        or head["action_record"]["chain_prev_hash"]
        != compute_session_open_genesis(opening)
    ):
        raise ValueError("recovery successor opening is not bound")
    for session, receipts in (
        (predecessor, checked.action),
        (target, successor.run.action),
    ):
        for receipt in receipts:
            opened = _session_open(receipt["action_record"].get("session_control"))
            if opened and opened.get("recorder_session") != session:
                raise ValueError("recovery opening session differs")
    tail_seq, tail_hash, prior_key = (
        _receipt_position(actions[-1])
        if actions
        else (0, "genesis", head["signer_key"])
    )
    last_outer = observed.last or {"seq": 0, "hash": "genesis"}
    check_recovery_binding(
        seal,
        {
            "shard": shard.name,
            "shard_size": length,
            "shard_sha256": hasher.hexdigest(),
            "damage_offset": offset,
            "last_good_seq": last_outer["seq"],
            "last_good_hash": last_outer["hash"],
            "predecessor_tail_seq": tail_seq,
            "predecessor_tail_hash": tail_hash,
            "predecessor_signer_key": prior_key,
            "successor_signer_key": head["signer_key"],
            "successor_open_hash": receipt_hash(head),
        },
        predecessor_session=predecessor,
        successor_session=target,
    )


def _snapshot(
    directory: Path, base: str, exclude: bool
) -> tuple[Index, list[Path], tuple, set[str]]:
    groups: set[str] = set()
    index = {
        s: shards
        for s, shards in recorder_index(
            directory, exclude_groups=exclude, group_sessions=groups
        ).items()
        if _in_base(s, base)
    }
    links = sorted(p for p in directory.iterdir() if _LINK_FILE.fullmatch(p.name))
    paths = [
        directory,
        *links,
        *(path for shards in index.values() for _, path in shards),
    ]
    stamps = []
    for path in paths:
        info = path.lstat()
        stamps.append(
            (
                path.name,
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        )
    return index, links, (tuple(stamps), frozenset(groups)), groups


def verify_base(
    directory: str | Path,
    base: str,
    trusted_keys: tuple[str, ...] = (),
    *,
    endorsements: tuple[Document, ...] = (),
    exclude_groups: bool = False,
) -> Document:
    """Verify ordinary runs and claims for one recorder base.

    Unlinked runs are reported separately. An attested recovery discontinuity
    remains a finding, even when the seal binds the evidence it describes.
    """
    root = Path(directory).resolve(strict=True)
    keys = set(trusted_keys)
    if any(not _HEX.fullmatch(key) for key in keys):
        raise ValueError("invalid trusted key")
    if endorsements and not keys:
        raise ValueError("rotation endorsements require a pinned root key")
    for endorsement in endorsements:
        _verify_artifact(endorsement, rotation=True)
    index, links, stamps, groups = _snapshot(root, base, exclude_groups)
    findings: list[Document] = []

    def add(kind: str, session: str, detail: str = "") -> None:
        findings.append({"kind": kind, "session": session, "detail": detail})

    chains = {}
    for session, shards in index.items():
        try:
            run = read_run(session, shards)
        except _READ_FAILURES as exc:
            add("corrupt_chain", session, str(exc))
            run = RecorderRun(outer_error=str(exc))
        else:
            if run.outer_error:
                add("outer_chain_broken", session, run.outer_error)
        chains[session] = _Chain(run)

    successors: dict[str, list[str]] = defaultdict(list)
    recoveries = []
    for path in links:
        named = _LINK_FILE.fullmatch(path.name)[1]
        recovery = False
        try:
            raw = _read_regular(path, 64 << 10)
            value = _decode_signed(raw)
            recovery = "kind" in value
            if recovery:
                if set(value) != set(_FIELDS) or any(v is None for v in value.values()):
                    raise ValueError("recovery seal fields differ from schema")
                _validate(
                    value,
                    {str(value["successor_signer_key"])},
                    ordinary_restart=True,
                )
            else:
                _verify_artifact(value, rotation=False)
        except _READ_FAILURES as exc:
            if _in_base(named, base):
                add(
                    "invalid_recovery_seal" if recovery else "invalid_link",
                    named,
                    str(exc),
                )
            continue
        pred, succ = value["predecessor_session"], value["successor_session"]
        if not any(_in_base(s, base) for s in (succ, pred, named)):
            continue
        if recovery:
            if named == pred and pred in groups and succ in groups:
                continue
            recoveries.append((named, value))
            continue
        if named != pred:
            add("link_name_mismatch", named)
        successors[pred].append(succ)
        if not _in_base(pred, base) or run_base(succ) != base:
            add("invalid_link", succ)
        elif succ not in chains:
            add("dangling_link", succ)
        elif chains[succ].link:
            add("invalid_link", succ, "successor already has a predecessor link")
        else:
            chains[succ].link = value

    _verify_chains(chains, keys, endorsements, add)
    for session, chain in chains.items():
        link = chain.link
        if not link:
            continue
        skey = link["successor_signer_key"]
        action = chain.run.action
        if action and action[0]["signer_key"] != skey:
            add(
                "invalid_link", session, "link signer does not sign the successor chain"
            )
        pred = link["predecessor_session"]
        if pred not in chains:
            add("dangling_link", session)
            continue
        earlier = chains[pred]
        if not earlier.valid or not earlier.run.action:
            add("predecessor_unverified", session)
            continue
        tail = _tail_finding(earlier, link)
        if tail:
            add(tail, pred)
        if skey == link["predecessor_signer_key"]:
            chain.trust = "same_key"
        elif skey in keys:
            chain.trust = "trusted_key"
        elif chain.trust != "endorsed":
            add("untrusted_successor_key", session)
    for named, seal in recoveries:
        pred, succ = seal["predecessor_session"], seal["successor_session"]
        successors[pred].append(succ)
        chain = chains.get(succ)
        try:
            if named != pred or not _in_base(pred, base) or chain is None:
                raise ValueError("recovery seal filename or base mismatch")
            if not chain.valid or chain.link or chain.seal:
                raise ValueError(
                    "recovery successor unavailable, invalid, or already linked"
                )
            _recovery(index, keys, seal, chain)
        except _READ_FAILURES as exc:
            add("invalid_recovery_seal", succ, str(exc))
        else:
            chain.seal = seal
            add("attested_discontinuity", succ)
    for pred, claimants in sorted(successors.items()):
        if len(claimants) > 1:
            add("double_successor", pred)
    nonces: dict[str, str] = {}
    for session, chain in chains.items():
        for nonce in sorted(
            {r["action_record"].get("run_nonce") or "" for r in chain.run.action} - {""}
        ):
            if nonces.setdefault(nonce, session) != session:
                add("duplicate_run_nonce", session)
    try:
        changed = _snapshot(root, base, exclude_groups)[2] != stamps
    except _READ_FAILURES:
        changed = True
    if changed:
        findings.clear()
        add(
            "corrupt_chain",
            base,
            "evidence changed during verification; no verdict reached",
        )
        for chain in chains.values():
            chain.valid = False
    return {
        "base": base,
        "healthy": not findings,
        "findings": findings,
        "chains": [
            {
                "session": s,
                "valid": c.valid,
                "link": c.link,
                "link_trust": c.trust,
                "recovery_seal": c.seal,
            }
            for s, c in chains.items()
        ],
        "unlinked": [s for s, c in chains.items() if c.link is None and c.seal is None],
    }
