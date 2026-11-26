// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { segments, type Segment } from "./history.js";
import type { Verification } from "./verify.js";
import { digest, limits, normalizationProfiles } from "./wire.js";

interface Action {
  action_id: string;
  action_type: string;
  phase: string;
  verdict: string;
  effect_boundary: string;
  effect_relation: string;
  transport: string;
  method: string;
  target: string;
  attempt?: number;
  outcome_class?: string;
  ask?: { channel: string; observed: boolean };
  hold?: { id: string; correction?: boolean };
  normalization?: { digest: string; id: string };
}

const releases = (verdict: string): boolean =>
  ["allow", "warn", "strip", "forward", "redirect"].includes(verdict);
const releasingBoundary = (boundary: string): boolean =>
  boundary !== "none" && boundary !== "approval_prompt";

function actionShape(a: Action, required: boolean): boolean {
  if (
    (a.phase === "intent" || a.phase === "outcome") !== (a.attempt !== undefined) ||
    (a.phase === "outcome") !== (a.outcome_class !== undefined) ||
    (a.phase === "hold" || a.phase === "resolution") !== (a.hold !== undefined)
  )
    return false;
  if (
    a.hold?.correction !== undefined &&
    (!a.hold.correction || a.phase !== "resolution" || a.verdict !== "block")
  )
    return false;
  if (!askShape(a)) return false;
  const { verdict, effect_boundary: boundary, effect_relation: relation } = a;
  switch (a.phase) {
    case "decision":
      if (verdict === "block") return relation === "not_attempted";
      if (verdict === "ask") return boundary === "hook_execution" && relation === "before";
      return (
        !required &&
        releases(verdict) &&
        releasingBoundary(boundary) &&
        ["before", "after", "unknown"].includes(relation)
      );
    case "intent":
      return releases(verdict) && releasingBoundary(boundary) && relation === "before";
    case "outcome":
      return outcomeShape(a);
    case "hold":
      return (
        ["ask", "defer"].includes(verdict) &&
        boundary === "approval_prompt" &&
        relation === "before"
      );
    case "resolution":
      if (boundary !== "approval_prompt") return false;
      if (["allow", "ask"].includes(verdict)) return relation === "after";
      return verdict === "block" && ["after", "not_attempted", "unknown"].includes(relation);
    default:
      return false;
  }
}

function askShape(a: Action): boolean {
  if (a.verdict !== "ask") return a.ask === undefined;
  if (!a.ask) return false;
  return a.phase === "decision"
    ? a.ask.channel === "host_prompt" && !a.ask.observed
    : a.ask.channel === "approval_api" && a.ask.observed;
}

function outcomeShape(a: Action): boolean {
  if (a.outcome_class === "not_released")
    return a.verdict === "block" && a.effect_relation === "not_attempted";
  if (!releases(a.verdict)) return false;
  switch (a.outcome_class) {
    case "completed":
    case "failed_after_attempt":
      return a.effect_relation === "after";
    case "failed_before_attempt":
      return a.effect_relation === "not_attempted";
    case "attempt_unknown":
      return a.effect_relation === "unknown";
    default:
      return false;
  }
}

function effect(a: Action): string {
  return JSON.stringify([a.action_type, a.transport, a.method, a.target, a.effect_boundary]);
}

class Decision {
  state = "";
  failed = false;
  private hold = "";
  private firstResolution = "";
  private attemptNumber = 0;
  private effect = "";
  private intentVerdict = "";
  private retryable = false;

  advance(a: Action, unknownStart: boolean): boolean {
    if (!this.state && unknownStart && !this.inferPrefix(a)) return false;
    switch (a.phase) {
      case "decision":
        if (this.state) return false;
        this.state =
          a.verdict === "block"
            ? "blocked"
            : a.verdict === "ask"
              ? "asked_unobserved"
              : "allowed_effect_unrecorded";
        return true;
      case "hold":
        if (this.state) return false;
        this.state = "pending";
        this.hold = a.hold!.id;
        return true;
      case "resolution":
        return this.resolve(a);
      default:
        return this.attempt(a);
    }
  }

  private inferPrefix(a: Action): boolean {
    if (a.phase === "resolution") {
      this.hold = a.hold!.id;
      this.state = "pending";
      if (a.hold!.correction !== undefined) {
        this.firstResolution = "allow";
        this.state = "outcome_unknown";
      }
    } else if (a.phase === "intent" || a.phase === "outcome") {
      this.attemptNumber = a.attempt! - 1;
      if (this.attemptNumber) {
        this.effect = effect(a);
        this.state = "not_released";
        this.retryable = true;
      }
      if (a.phase === "outcome" && a.outcome_class !== "not_released") {
        if (!releasingBoundary(a.effect_boundary)) return false;
        this.attemptNumber = a.attempt!;
        this.effect = effect(a);
        this.intentVerdict = a.verdict;
        this.state = "outcome_unknown";
        this.retryable = false;
      }
    }
    return true;
  }

  private resolve(a: Action): boolean {
    if (this.attemptNumber || !this.hold || a.hold!.id !== this.hold) return false;
    const prior = this.firstResolution;
    if (
      prior === "ask" ||
      (prior && a.verdict !== "block") ||
      (a.hold!.correction !== undefined) !== (prior === "allow" && a.verdict === "block")
    )
      return false;
    if (!prior) this.firstResolution = a.verdict;
    this.state =
      a.verdict === "allow" ? "outcome_unknown" : a.verdict === "ask" ? "stepped_up" : "blocked";
    return true;
  }

  private attempt(a: Action): boolean {
    const claim = effect(a);
    if (this.attemptNumber && this.effect !== claim) return false;
    const { phase, verdict, outcome_class: outcome, attempt } = a;
    if (this.intentVerdict) {
      if (
        phase !== "outcome" ||
        attempt !== this.attemptNumber ||
        (outcome !== "not_released" && verdict !== this.intentVerdict)
      )
        return false;
      this.intentVerdict = "";
    } else {
      const canStart =
        !this.state ||
        this.retryable ||
        (!this.attemptNumber &&
          this.firstResolution === "allow" &&
          this.state === "outcome_unknown");
      if (
        !canStart ||
        attempt !== this.attemptNumber + 1 ||
        (phase !== "intent" && outcome !== "not_released")
      )
        return false;
      this.attemptNumber = attempt;
      this.effect = claim;
    }
    this.retryable = false;
    if (phase === "intent") {
      this.intentVerdict = verdict;
      this.state = "outcome_unknown";
    } else {
      switch (outcome) {
        case "failed_before_attempt":
          this.retryable = true;
          this.state = "failed";
          break;
        case "failed_after_attempt":
          this.state = "failed";
          break;
        case "attempt_unknown":
          this.state = "outcome_unknown";
          break;
        case "not_released":
          this.retryable = true;
          this.state = outcome;
          break;
        default:
          this.state = outcome!;
      }
    }
    return true;
  }
}

function increment(counts: Map<string, number>, key: string): void {
  counts.set(key, (counts.get(key) ?? 0) + 1);
}

const unknownStates = [
  "outcome_unknown",
  "pending",
  "asked_unobserved",
  "allowed_effect_unrecorded",
  "uninterpreted",
];

export function appraiseDecisions(v: Verification): void {
  const decisions = new Map<string, number>();
  const uninterpreted = new Map<string, number>();
  let fullHistory = true;
  for (const lineage of [...v.histories.keys()].sort()) {
    const members = v.histories.get(lineage)!;
    const pieces = segments(v, members);
    const appraised = appraiseHistory(v, pieces, decisions, uninterpreted);
    fullHistory = fullHistory && appraised;
  }
  if (fullHistory) {
    v.result.counts = {
      scope: "full_history",
      complete: true,
      decisions: [...decisions.keys()]
        .sort()
        .map((state) => ({ state, count: decisions.get(state)! })),
      effects_completed: decisions.get("completed") ?? 0,
      effects_unknown: unknownStates.reduce((sum, state) => sum + (decisions.get(state) ?? 0), 0),
      uninterpreted: [...uninterpreted.keys()]
        .sort()
        .map((kind) => ({ kind, count: uninterpreted.get(kind)! })),
    };
  }
}

// The index keeps a fixed-size digest of each hold ID and shares the decision
// index budget: past it the history is reported as incomplete.
export function claimHold(
  holds: Map<string, string>,
  hold: string,
  action: string,
  max: number,
): "conflict" | "full" | undefined {
  const key = digest(Buffer.from(hold));
  const owner = holds.get(key);
  if (owner !== undefined) return owner === action ? undefined : "conflict";
  if (holds.size >= max) return "full";
  holds.set(key, action);
  return undefined;
}

function appraiseHistory(
  v: Verification,
  pieces: Segment[],
  decisions: Map<string, number>,
  uninterpreted: Map<string, number>,
): boolean {
  const ids = new Map<string, boolean>();
  const holds = new Map<string, string>();
  const bad = new Map<Segment, Set<string>>();
  let future = false;
  let full = false;
  for (const piece of pieces) {
    const badShape = new Set<string>();
    bad.set(piece, badShape);
    for (const stream of piece.streams) {
      for (const record of v.store.walk(stream.open!.stream, stream.limit)) {
        if (record.bodyCode) continue;
        if (record.kind !== "action") {
          if (record.unknown && record.kind !== "stream_open" && record.kind !== "stream_close") {
            v.add("EVENT_UNINTERPRETED", record);
            increment(uninterpreted, record.kind);
          }
          continue;
        }
        if (record.body_v !== 1) {
          future = true;
          increment(uninterpreted, "action");
          continue;
        }
        const a = record.body as unknown as Action;
        const id = a.action_id;
        const binding = a.normalization;
        if (binding && normalizationProfiles[binding.digest] !== binding.id)
          v.add("NORMALIZATION_UNKNOWN", record);
        if (ids.has(id) || ids.size < limits.decisions)
          ids.set(id, ids.get(id) === true || record.unknown);
        else full = true;

        if (a.hold && (a.phase === "hold" || a.phase === "resolution")) {
          const claim = claimHold(holds, a.hold.id, id, limits.decisions);
          if (claim === "conflict") v.add("DECISION_INCONSISTENT", record);
          else if (claim === "full") full = true;
        }
        if (record.unknown) {
          increment(uninterpreted, "action");
          v.add("ACTION_UNINTERPRETED", record);
        } else if (!actionShape(a, stream.body!.coverage.receipts_required)) {
          badShape.add(id);
          v.add("DECISION_INCONSISTENT", record);
        }
      }
    }
  }
  const first = pieces
    .flatMap((piece) => piece.streams)
    .reduce((a, b) => (a.open!.stream < b.open!.stream ? a : b)).open!;
  if (future) v.add("DECISIONS_NOT_APPRAISED", first);
  if (full) {
    v.add("DECISION_INDEX_FULL", first);
    if (!v.result.limits.includes("L-DECISION-INDEX")) v.result.limits.push("L-DECISION-INDEX");
  }
  if (future || full) return false;
  for (const piece of pieces) appraiseSegment(v, piece, ids, bad.get(piece)!, decisions);
  return pieces.length === 1 && pieces[0].rooted && !pieces[0].streams.at(-1)!.forked;
}

function appraiseSegment(
  v: Verification,
  piece: Segment,
  ids: Map<string, boolean>,
  bad: Set<string>,
  decisions: Map<string, number>,
): void {
  const states = new Map<string, Decision>();
  for (const stream of piece.streams) {
    for (const record of v.store.walk(stream.open!.stream, stream.limit)) {
      if (record.kind !== "action" || record.bodyCode) continue;
      const a = record.body as unknown as Action;
      let state = states.get(a.action_id);
      if (!state) {
        state = new Decision();
        if (ids.get(a.action_id)) state.state = "uninterpreted";
        else if (bad.has(a.action_id)) state.failed = true;
        states.set(a.action_id, state);
      }
      if (!state.failed && state.state !== "uninterpreted" && !state.advance(a, !piece.rooted)) {
        state.failed = true;
        v.add("DECISION_INCONSISTENT", record);
      }
    }
  }
  if (piece.rooted) {
    for (const state of states.values()) if (!state.failed) increment(decisions, state.state);
  }
}
