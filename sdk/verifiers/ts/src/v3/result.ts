// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import type { V3Position, VerifyV3Options } from "./input.js";
import { ascii, byteOrder, findings, type FindingClass, type RecordV3 } from "./wire.js";

export interface V3Finding {
  code: string;
  class: FindingClass;
  stream?: string;
  seq?: number;
  record?: string;
}

export interface V3StreamResult {
  stream: string;
  signer: string;
  records: number;
  end: string;
  previous?: string;
  last?: V3Position;
  tip?: V3Position;
  unconfirmed_from?: number;
}

interface V3History {
  lineage: string;
  streams: V3StreamResult[];
}

interface Acceptance {
  kind: string;
  value: string;
}

export type V3Counts =
  | { scope: "not_appraised" }
  | {
      scope: "full_history";
      complete: boolean;
      decisions: { state: string; count: number }[];
      effects_completed: number;
      effects_unknown: number;
      uninterpreted: { kind: string; count: number }[];
    };

export interface V3LegacyResult {
  chain: string;
  class: "pass" | "failure";
  format: string;
  verdict: string;
}

type V3Verdict =
  | "INVALID"
  | "UNSUPPORTED"
  | "INCOMPLETE"
  | "VALID PREFIX, END UNPROVEN"
  | "SELF-CONSISTENT ONLY"
  | "VALID, GAPS ACCEPTED"
  | "VALID";

interface V3VerdictFields {
  verdict: V3Verdict;
  exit_code: 0 | 1 | 3;
  integrity: "ok" | "failed";
  completeness: "complete" | "end_unproven" | "incomplete";
  trust_state: "pinned" | "unpinned";
  trust: { mode: "pinned_keys" | "unpinned"; keys: string[] };
  accepted: Acceptance[];
}

export interface V3Result extends V3VerdictFields {
  kind: "verify_result";
  v: 1;
  contested_streams: { stream: string; records: string[] }[];
  counts: V3Counts;
  findings: V3Finding[];
  histories: V3History[];
  ignored_files: number;
  legacy: V3LegacyResult[];
  limits: string[];
}

export interface V3Projection extends V3VerdictFields {
  finding_codes: string[];
  counts?: V3Counts;
  histories?: {
    lineage: string;
    streams: Omit<V3StreamResult, "signer" | "last" | "unconfirmed_from">[];
  }[];
}

export function canonicalV3(value: V3Result | V3Projection): string {
  return canonicalJSON(value);
}

// V3 uses RFC 8785, including UTF-16 member order and unmodified string bytes.
export function canonicalJSON(value: unknown): string {
  if (Array.isArray(value)) {
    const elements: string[] = [];
    for (let i = 0; i < value.length; i++) {
      if (!Object.hasOwn(value, i)) throw new TypeError("sparse canonical JSON array");
      if (value[i] === undefined) throw new TypeError("undefined canonical JSON array element");
      elements.push(canonicalJSON(value[i]));
    }
    return "[" + elements.join(",") + "]";
  }
  if (typeof value === "object" && value !== null) {
    const object = value as Record<string, unknown>;
    return (
      "{" +
      Object.keys(object)
        .filter((key) => object[key] !== undefined)
        .sort()
        .map((key) => quote(key) + ":" + canonicalJSON(object[key]))
        .join(",") +
      "}"
    );
  }
  if (typeof value === "string") return quote(value);
  if (typeof value === "number" && !Number.isFinite(value))
    throw new TypeError("canonicalJSON: non-finite numbers cannot be represented in JSON");
  return JSON.stringify(value);
}

// RFC 8785 forbids a lone surrogate, which JSON.stringify would escape.
function quote(text: string): string {
  if (/\p{Surrogate}/u.test(text))
    throw new TypeError("canonicalJSON: unpaired surrogate cannot be represented in UTF-8");
  return JSON.stringify(text);
}

export function newResult(opts: VerifyV3Options, ignoredFiles: number): V3Result {
  const pinned = Boolean(opts.keys?.length);
  return {
    kind: "verify_result",
    v: 1,
    verdict: "VALID",
    exit_code: 0,
    accepted: [],
    integrity: "ok",
    completeness: "complete",
    trust_state: pinned ? "pinned" : "unpinned",
    trust: { mode: pinned ? "pinned_keys" : "unpinned", keys: [] },
    contested_streams: [],
    counts: { scope: "not_appraised" },
    findings: [],
    histories: [],
    ignored_files: ignoredFiles,
    legacy: [],
    limits: ["L-FSYNC-ERROR-REOPEN", "L-FSYNC-HONESTY"],
  };
}

export type RecordPosition = Pick<RecordV3, "stream" | "seq" | "id">;

export function position(record: RecordPosition): V3Position {
  return { seq: record.seq, record: record.id };
}

export function finding(code: string, loc: RecordPosition | string): V3Finding {
  const result: V3Finding = { code, class: findings[code] };
  if (typeof loc !== "string") {
    result.seq = loc.seq;
    result.record = loc.id;
    result.stream = loc.stream;
  } else if (loc) {
    result.stream = loc;
  }
  return result;
}

function compareFindings(a: V3Finding, b: V3Finding): number {
  return (
    ascii(a.code, b.code) ||
    ascii(a.stream ?? "", b.stream ?? "") ||
    (a.seq ?? -1) - (b.seq ?? -1) ||
    ascii(a.record ?? "", b.record ?? "")
  );
}

function compareAccepted(a: Acceptance, b: Acceptance): number {
  return ascii(a.kind, b.kind) || ascii(a.value, b.value);
}

function acceptanceIndex(accepted: Acceptance[]): { partial: Set<string>; gaps: Set<string> } {
  const values = (wanted: string): Set<string> =>
    new Set(accepted.filter(({ kind }) => kind === wanted).map(({ value }) => value));
  return { partial: values("allow-partial-history"), gaps: values("accept-discontinuity") };
}

function acceptedFinding(f: V3Finding, index: ReturnType<typeof acceptanceIndex>): boolean {
  return (
    (f.code === "PREDECESSOR_NOT_PRESENTED" && index.partial.has(f.stream ?? "")) ||
    (f.code === "LEGACY_END_UNPROVEN" && index.gaps.has(f.record ?? ""))
  );
}

export const prefixVerdict = "VALID PREFIX, END UNPROVEN";

export function finish(result: V3Result, opts: VerifyV3Options): V3Projection {
  result.limits.sort();
  result.findings = result.findings
    .sort(compareFindings)
    .filter((f, i, arr) => !i || compareFindings(arr[i - 1], f) !== 0);
  result.accepted = result.accepted
    .sort(compareAccepted)
    .filter((a, i, arr) => !i || compareAccepted(arr[i - 1], a) !== 0);

  const acceptance = acceptanceIndex(result.accepted);
  const effective = result.findings.filter((f) => !acceptedFinding(f, acceptance));
  const classes = new Set(effective.map((f) => f.class));
  const invalid = classes.has("invalid");
  const unsupported = classes.has("unsupported");
  const incomplete = classes.has("incomplete");
  const endUnproven = classes.has("end_unproven");
  result.integrity = invalid ? "failed" : "ok";
  result.completeness = incomplete ? "incomplete" : endUnproven ? "end_unproven" : "complete";
  if (result.counts.scope === "full_history")
    result.counts.complete = !invalid && !unsupported && !incomplete;
  const pinned = result.trust_state === "pinned";
  const gaps = result.accepted.some(
    (a) => a.kind === "allow-partial-history" || a.kind === "accept-discontinuity",
  );
  let deciding: FindingClass | undefined;
  if (invalid) {
    result.verdict = "INVALID";
    result.exit_code = 1;
    deciding = "invalid";
  } else if (unsupported || incomplete) {
    result.verdict = unsupported ? "UNSUPPORTED" : "INCOMPLETE";
    result.exit_code = 3;
    deciding = unsupported ? "unsupported" : "incomplete";
  } else {
    result.verdict = endUnproven
      ? prefixVerdict
      : !pinned
        ? "SELF-CONSISTENT ONLY"
        : gaps
          ? "VALID, GAPS ACCEPTED"
          : "VALID";
    if (endUnproven) deciding = "end_unproven";
    if (endUnproven && !opts.allowPrefix) result.exit_code = 3;
    else if (!pinned && !opts.allowUnpinned) result.exit_code = 1;
  }

  const projection: V3Projection = {
    accepted: result.accepted,
    completeness: result.completeness,
    exit_code: result.exit_code,
    finding_codes: [...new Set(effective.filter((f) => f.class === deciding).map((f) => f.code))],
    integrity: result.integrity,
    trust: result.trust,
    trust_state: result.trust_state,
    verdict: result.verdict,
  };
  if (!invalid && !unsupported && !incomplete) {
    projection.counts = result.counts;
    projection.histories = result.histories.map(({ streams, lineage }) => ({
      lineage,
      streams: streams.map(({ stream, previous, end, records, tip }) => ({
        stream,
        ...(previous ? { previous } : {}),
        end,
        records,
        ...(tip ? { tip } : {}),
      })),
    }));
  }
  return projection;
}

export function sortLegacy(results: V3LegacyResult[]): void {
  results.sort(
    (a, b) =>
      ascii(a.format, b.format) ||
      byteOrder(a.chain, b.chain) ||
      ascii(a.verdict, b.verdict) ||
      ascii(a.class, b.class),
  );
}
