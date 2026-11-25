// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { headValue, sequenceValue, type V3Position } from "./input.js";
import { position, type V3StreamResult } from "./result.js";
import type { Staged } from "./store.js";
import type { Verification } from "./verify.js";
import { ascii, type Fields } from "./wire.js";

interface Previous extends V3Position {
  stream: string;
  ended: string;
}

export interface Cutover {
  inventory: string;
  chains: number;
}

export interface OpenBody {
  lineage: string;
  previous?: Previous;
  legacy_cutover?: Cutover;
  coverage: { receipts_required: boolean };
}

export interface VerifiedStream {
  open?: Staged;
  last?: Staged;
  body?: OpenBody;
  limit: number;
  contenders: Staged[];
  successors: VerifiedStream[];
  missing?: boolean;
  segment: number;
  broken?: boolean;
  summary: V3StreamResult;
}

function sorted<T>(map: Map<string, T>): T[] {
  return [...map.keys()].sort().map((key) => map.get(key)!);
}

export function verifySuccession(v: Verification): void {
  const streams = sorted(v.streams);
  for (const stream of streams) {
    const pin = stream.body?.previous;
    if (!pin) continue;
    const parent = v.streams.get(pin.stream);
    if (!parent || (!parent.open && !parent.contenders.length)) {
      stream.missing = true;
      v.add("PREDECESSOR_NOT_PRESENTED", stream.open!);
    } else {
      parent.successors.push(stream);
    }
  }
  for (const parent of streams) {
    for (const child of parent.successors) {
      if (parent.successors.length > 1) v.add("SUCCESSION_FORK", child.open!);
      if (parent.open) checkPin(v, parent, child);
    }
    setSummary(parent);
  }
}

function checkPin(v: Verification, parent: VerifiedStream, child: VerifiedStream): void {
  const pin = child.body!.previous!;
  const sameLineage = parent.body?.lineage === child.body!.lineage;
  if (!sameLineage && parent.body?.lineage) v.add("LINEAGE_MISMATCH", child.open!);
  const record = v.store.pin(pin.stream, pin.seq, parent.limit);
  if (!record) {
    v.add("PREDECESSOR_TRUNCATED", child.open!);
    return;
  }
  if (
    record.id !== pin.record ||
    (pin.ended === "closed" && record.kind !== "stream_close") ||
    (pin.ended === "unsealed" && record.kind === "stream_close")
  ) {
    v.add("PIN_MISMATCH", child.open!);
    return;
  }
  if (pin.ended !== "write_error") {
    if ((parent.last?.seq ?? 0) > pin.seq) v.add("TAIL_AFTER_SUCCESSION", child.open!);
  } else if (parent.successors.length === 1 && sameLineage && !parent.contenders.length) {
    parent.limit = pin.seq;
    for (const item of v.store.walk(pin.stream, parent.last?.seq ?? 0)) {
      if (item.seq > pin.seq) v.add("UNCONFIRMED", item);
    }
  }
}

function setSummary(stream: VerifiedStream): void {
  const { body, last, open, summary, contenders, successors } = stream;
  summary.stream = open?.stream ?? "";
  summary.signer = open?.signer ?? "";
  if (body?.previous) summary.previous = body.previous.stream;
  if (last) summary.last = summary.tip = position(last);
  summary.end = contenders.length ? "forked" : last?.kind === "stream_close" ? "closed" : "open";
  if (successors.length > 1) delete summary.tip;
  else if (successors.length === 1 && !contenders.length) {
    const child = successors[0];
    const pin = child.body!.previous!;
    if (
      pin.ended === "unsealed" &&
      last?.id === pin.record &&
      last.seq === pin.seq &&
      last.kind !== "stream_close" &&
      body?.lineage === child.body!.lineage
    )
      summary.end = "superseded_unsealed";
    else if (pin.ended === "write_error" && stream.limit === pin.seq) {
      summary.end = "superseded_write_error";
      summary.tip = { record: pin.record, seq: pin.seq };
      summary.records = pin.seq + 1;
      summary.unconfirmed_from = pin.seq + 1;
    }
  }
}

export interface Segment {
  rooted: boolean;
  streams: VerifiedStream[];
}

export function segments(v: Verification, members: VerifiedStream[]): Segment[] {
  const next = new Map<VerifiedStream, VerifiedStream>();
  const hasParent = new Set<VerifiedStream>();
  const roots = members.filter((member) => !member.body!.previous);
  for (const member of members) {
    if (!member.contenders.length && member.successors.length === 1) {
      const child = member.successors[0];
      if (child.body!.lineage === member.body!.lineage) {
        next.set(member, child);
        hasParent.add(child);
      }
    }
  }
  if (roots.length > 1) for (const root of roots) v.add("ROOT_FORK", root.open!);
  const pieces: Segment[] = [];
  const append = (start: VerifiedStream) => {
    const segment: Segment = { rooted: !start.body!.previous, streams: [] };
    for (let s: VerifiedStream | undefined = start; s && s.segment < 0; s = next.get(s)) {
      s.segment = pieces.length;
      segment.streams.push(s);
    }
    pieces.push(segment);
  };
  let forked = false;
  for (const member of members) {
    forked ||= member.contenders.length > 0 || member.successors.length > 1;
    if (!hasParent.has(member)) append(member);
  }
  for (const member of members) {
    if (member.segment < 0) {
      append(member);
      forked = true;
    }
  }
  if (pieces.length !== 1 || forked) v.add("HISTORY_DISCONNECTED", members[0].open!.stream);
  return pieces;
}

export function checkExpectations(v: Verification, cutoverEnds: Map<string, Staged>): void {
  const { opts, streams, histories } = v;
  const accept = (kind: string, value: string, satisfied: boolean) => {
    if (satisfied) v.result.accepted.push({ kind, value });
    else v.add("EXPECTATION_NOT_MET");
  };
  for (const id of opts.acceptDiscontinuities ?? []) {
    const found =
      cutoverEnds.has(id) ||
      [...streams.values()].some((stream) => {
        const end = stream.body?.previous?.ended;
        return stream.open?.id === id && (end === "write_error" || end === "unsealed");
      });
    accept("accept-discontinuity", id, found);
  }
  for (const id of opts.allowPartialHistories ?? [])
    accept("allow-partial-history", id, streams.get(id)?.missing === true);

  const proved = new Set<string>();
  for (const expected of opts.expectHeads ?? []) {
    const tip = streams.get(expected.stream)?.summary.tip;
    const found = tip?.seq === expected.seq && tip.record === expected.record;
    accept("expect-head", headValue(expected), found);
    if (found) proved.add(expected.stream);
  }
  for (const expected of opts.expectSequences ?? []) {
    const tip = streams.get(expected.stream)?.summary.tip;
    const found = tip?.seq === expected.seq;
    accept("expect-seq", sequenceValue(expected), found);
    if (found) proved.add(expected.stream);
  }
  if (opts.expectLineage)
    accept("expect-lineage", opts.expectLineage, histories.has(opts.expectLineage));
  if (opts.allowPrefix) accept("allow-prefix", "true", true);
  if (opts.allowUnpinned) accept("allow-unpinned", "true", true);

  for (const record of cutoverEnds.values()) v.add("LEGACY_END_UNPROVEN", record);
  for (const [id, stream] of streams) {
    if (!stream.open || proved.has(id)) continue;
    if (stream.summary.end === "open") v.add("END_UNPROVEN", stream.last!);
    else if (["superseded_unsealed", "superseded_write_error"].includes(stream.summary.end)) {
      const successor = stream.successors[0].open!;
      if (!opts.acceptDiscontinuities?.includes(successor.id)) v.add("END_UNPROVEN", successor);
    }
  }
  for (const lineage of [...histories.keys()].sort()) {
    const members = histories.get(lineage)!;
    v.result.histories.push({
      lineage,
      streams: members.map((s) => s.summary).sort((a, b) => ascii(a.stream, b.stream)),
    });
  }
}

export function cutoverMembershipKnown(v: Verification): boolean {
  if (!v.histories.size) return false;
  const roots = new Set<string>();
  for (const [lineage, members] of v.histories) {
    if (!members.some((s) => !s.body!.previous && s.body!.legacy_cutover)) return false;
    roots.add(lineage);
  }
  for (const stream of v.streams.values()) {
    if (stream.limit >= 0) continue;
    for (const candidate of stream.contenders) {
      if (candidate.kind !== "stream_open") continue;
      const body: Fields = candidate.body;
      if (
        (body.previous !== undefined &&
          (typeof body.previous !== "object" || Array.isArray(body.previous))) ||
        (body.lineage !== undefined && typeof body.lineage !== "string") ||
        candidate.unknown ||
        !body.previous ||
        !roots.has(body.lineage as string)
      )
        return false;
    }
  }
  return true;
}
