# Copyright 2026 Pipelab
# SPDX-License-Identifier: Apache-2.0

"""Receipt v3 action shapes and connected decision state."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .wire import KINDS, LIMITS, REGISTRY, Document

if TYPE_CHECKING:
    from .verify import Verification, _Stream

_RELEASES = {"allow", "warn", "strip", "forward", "redirect"}
_OUTCOME_RELATION = {
    "completed": "after",
    "failed_after_attempt": "after",
    "failed_before_attempt": "not_attempted",
    "attempt_unknown": "unknown",
}


def _boundary_releases(boundary: str) -> bool:
    return boundary not in ("none", "approval_prompt")


def _shape(action: Document, required: bool) -> bool:
    phase, verdict = action["phase"], action["verdict"]
    boundary, relation = action["effect_boundary"], action["effect_relation"]
    hold, ask = action.get("hold", {}), action.get("ask")
    if (
        (phase in ("intent", "outcome")) != ("attempt" in action)
        or (phase == "outcome") != ("outcome_class" in action)
        or (phase in ("hold", "resolution")) != ("hold" in action)
        or "correction" in hold
        and (
            hold["correction"] is not True
            or phase != "resolution"
            or verdict != "block"
        )
    ):
        return False
    if verdict == "ask":
        channel = (
            {"channel": "host_prompt", "observed": False}
            if phase == "decision"
            else {
                "channel": "approval_api",
                "observed": True,
            }
        )
        if ask != channel:
            return False
    elif ask is not None:
        return False
    releases = verdict in _RELEASES
    match phase:
        case "decision":
            if verdict == "block":
                return relation == "not_attempted"
            if verdict == "ask":
                return boundary == "hook_execution" and relation == "before"
            return (
                not required
                and releases
                and _boundary_releases(boundary)
                and relation in ("before", "after", "unknown")
            )
        case "intent":
            return releases and _boundary_releases(boundary) and relation == "before"
        case "outcome":
            outcome = action["outcome_class"]
            if outcome == "not_released":
                return verdict == "block" and relation == "not_attempted"
            return releases and _OUTCOME_RELATION.get(outcome) == relation
        case "hold":
            return (
                verdict in ("ask", "defer")
                and boundary == "approval_prompt"
                and relation == "before"
            )
        case "resolution":
            return boundary == "approval_prompt" and (
                verdict in ("allow", "ask")
                and relation == "after"
                or verdict == "block"
                and relation in ("after", "not_attempted", "unknown")
            )
    return False


def _effect(action: Document) -> tuple[str, ...]:
    return tuple(
        action.get(key, "")
        for key in ("action_type", "transport", "method", "target", "effect_boundary")
    )


@dataclass(slots=True)
class _Piece:
    state: str = ""
    hold: str = ""
    first_resolution: str = ""
    number: int = 0
    effect: tuple[str, ...] = ()
    intent: str = ""
    retryable: bool = False
    failed: bool = False

    def advance(self, action: Document, unknown_start: bool) -> bool:
        if not self.state and unknown_start and not self._infer_prefix(action):
            return False
        match action["phase"]:
            case "decision":
                if self.state:
                    return False
                self.state = {"block": "blocked", "ask": "asked_unobserved"}.get(
                    action["verdict"], "allowed_effect_unrecorded"
                )
            case "hold":
                if self.state:
                    return False
                self.state, self.hold = "pending", action["hold"]["id"]
            case "resolution":
                return self._resolve(action)
            case _:
                return self._attempt(action)
        return True

    def _infer_prefix(self, action: Document) -> bool:
        phase = action["phase"]
        if phase == "resolution":
            self.hold, self.state = action["hold"]["id"], "pending"
            if "correction" in action["hold"]:
                self.first_resolution, self.state = "allow", "outcome_unknown"
        elif phase in ("intent", "outcome"):
            # A prefix of standalone refusals is represented by its last
            # attempt, with constant work even at the wire integer limit.
            self.number = action["attempt"] - 1
            if self.number:
                self.effect, self.state, self.retryable = (
                    _effect(action),
                    "not_released",
                    True,
                )
            if phase == "outcome" and action["outcome_class"] != "not_released":
                if not _boundary_releases(action["effect_boundary"]):
                    return False
                self.number, self.effect = action["attempt"], _effect(action)
                self.intent, self.state, self.retryable = (
                    action["verdict"],
                    "outcome_unknown",
                    False,
                )
        return True

    def _resolve(self, action: Document) -> bool:
        verdict = action["verdict"]
        if self.number or not self.hold or action["hold"]["id"] != self.hold:
            return False
        prior = self.first_resolution
        if (
            prior == "ask"
            or prior
            and verdict != "block"
            or ("correction" in action["hold"])
            != (prior == "allow" and verdict == "block")
        ):
            return False
        self.first_resolution = prior or verdict
        self.state = {
            "allow": "outcome_unknown",
            "ask": "stepped_up",
            "block": "blocked",
        }[verdict]
        return True

    def _attempt(self, action: Document) -> bool:
        number, effect = action["attempt"], _effect(action)
        phase, outcome = action["phase"], action.get("outcome_class")
        if self.number and self.effect != effect:
            return False
        if self.intent:
            if (
                phase != "outcome"
                or number != self.number
                or outcome != "not_released"
                and action["verdict"] != self.intent
            ):
                return False
            self.intent = ""
        else:
            can_start = (
                not self.state
                or self.retryable
                or not self.number
                and self.first_resolution == "allow"
                and self.state == "outcome_unknown"
            )
            if (
                not can_start
                or number != self.number + 1
                or (phase != "intent" and outcome != "not_released")
            ):
                return False
            self.number, self.effect = number, effect
        self.retryable = outcome in ("failed_before_attempt", "not_released")
        if phase == "intent":
            self.intent, self.state = action["verdict"], "outcome_unknown"
        else:
            self.state = {
                "failed_before_attempt": "failed",
                "failed_after_attempt": "failed",
                "attempt_unknown": "outcome_unknown",
            }.get(outcome, outcome)
        return True


def _appraise_segment(
    verification: Verification,
    segment: int,
    rooted: bool,
    streams: list[_Stream],
    ids: dict[str, bool],
    decisions: Counter[str],
) -> None:
    pieces: dict[str, _Piece] = {}
    for stream in streams:
        for record in verification.walk(stream.opening.stream, stream.limit):
            if record.kind != "action" or record.body_code:
                continue
            action = record.body
            action_id = action["action_id"]
            piece = pieces.get(action_id)
            if piece is None:
                piece = _Piece()
                if ids[action_id]:
                    piece.state = "uninterpreted"
                else:
                    piece.failed = (
                        verification.db.execute(
                            "SELECT 1 FROM bad_shapes WHERE segment=? AND id=?",
                            (segment, action_id),
                        ).fetchone()
                        is not None
                    )
                pieces[action_id] = piece
            if (
                not piece.failed
                and piece.state != "uninterpreted"
                and not piece.advance(action, not rooted)
            ):
                piece.failed = True
                verification.add("DECISION_INCONSISTENT", record=record)
    if rooted:
        decisions.update(piece.state for piece in pieces.values() if not piece.failed)


def _inspect_history(
    verification: Verification,
    segments: list[tuple[bool, list[_Stream]]],
    uninterpreted: Counter[str],
) -> tuple[dict[str, bool], bool, bool]:
    db = verification.db
    db.execute("DELETE FROM hold_owners")
    db.execute("DELETE FROM bad_shapes")
    ids: dict[str, bool] = {}
    future = full = False
    for segment, (_, streams) in enumerate(segments):
        for stream in streams:
            for record in verification.walk(stream.opening.stream, stream.limit):
                if record.body_code:
                    continue
                if record.kind != "action":
                    if (
                        record.unknown
                        and KINDS.get(record.kind, {}).get("class") != "control"
                    ):
                        uninterpreted[record.kind] += 1
                        verification.add("EVENT_UNINTERPRETED", record=record)
                    continue
                if record.fields["body_v"] != KINDS["action"]["body_v"]:
                    future = True
                    uninterpreted["action"] += 1
                    continue
                action = record.body
                binding = action.get("normalization")
                if (
                    binding
                    and REGISTRY["normalization_profiles"].get(binding["digest"])
                    != binding["id"]
                ):
                    verification.add("NORMALIZATION_UNKNOWN", record=record)
                action_id = action["action_id"]
                if action_id in ids or len(ids) < LIMITS["decisions"]:
                    ids[action_id] = ids.get(action_id, False) or record.unknown
                else:
                    full = True
                if "hold" in action and action["phase"] in ("hold", "resolution"):
                    hold = action["hold"]["id"]
                    db.execute(
                        "INSERT OR IGNORE INTO hold_owners VALUES (?,?)",
                        (hold, action_id),
                    )
                    (owner,) = db.execute(
                        "SELECT action_id FROM hold_owners WHERE id=?", (hold,)
                    ).fetchone()
                    if owner != action_id:
                        verification.add("DECISION_INCONSISTENT", record=record)
                if record.unknown:
                    uninterpreted["action"] += 1
                    verification.add("ACTION_UNINTERPRETED", record=record)
                elif not _shape(action, stream.body["coverage"]["receipts_required"]):
                    verification.add("DECISION_INCONSISTENT", record=record)
                    db.execute(
                        "INSERT OR IGNORE INTO bad_shapes VALUES (?,?)",
                        (segment, action_id),
                    )
    return ids, future, full


def appraise(verification: Verification) -> Document:
    db = verification.db
    db.execute(
        "CREATE TABLE hold_owners (id TEXT PRIMARY KEY, action_id TEXT) WITHOUT ROWID"
    )
    db.execute(
        "CREATE TABLE bad_shapes (segment INTEGER, id TEXT,"
        " PRIMARY KEY (segment,id)) WITHOUT ROWID"
    )
    full_history = True
    decisions: Counter[str] = Counter()
    uninterpreted: Counter[str] = Counter()
    for _, members in sorted(verification.histories.items()):
        segments = verification.segments(members)
        ids, future, full = _inspect_history(verification, segments, uninterpreted)
        if future:
            verification.add("DECISIONS_NOT_APPRAISED", record=members[0].opening)
        if full:
            verification.add("DECISION_INDEX_FULL", record=members[0].opening)
            if "L-DECISION-INDEX" not in verification.result["limits"]:
                verification.result["limits"].append("L-DECISION-INDEX")
        if future or full:
            full_history = False
            continue
        full_history &= (
            len(segments) == 1 and segments[0][0] and not segments[0][1][-1].forked
        )
        for segment, (rooted, streams) in enumerate(segments):
            _appraise_segment(verification, segment, rooted, streams, ids, decisions)
    if not full_history:
        return {"scope": "not_appraised"}
    return {
        "scope": "full_history",
        "decisions": [{"state": k, "count": v} for k, v in sorted(decisions.items())],
        "effects_completed": decisions["completed"],
        "effects_unknown": sum(
            decisions[k]
            for k in (
                "outcome_unknown",
                "pending",
                "asked_unobserved",
                "allowed_effect_unrecorded",
                "uninterpreted",
            )
        ),
        "uninterpreted": [
            {"kind": k, "count": v} for k, v in sorted(uninterpreted.items())
        ],
    }
