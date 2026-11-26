// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { basename } from "node:path";
import { withRecorderFileExclusions } from "../chain-set.js";
import type { KeyObject } from "node:crypto";
import { appraiseDecisions } from "./decision.js";
import { verifyCutover } from "./cutover.js";
import {
  checkExpectations,
  verifySuccession,
  type VerifiedStream,
  type OpenBody,
} from "./history.js";
import { discover, inputLines, validateOptions, type VerifyV3Options } from "./input.js";
import {
  newResult,
  finish,
  finding,
  type RecordPosition,
  type V3Projection,
  type V3Result,
} from "./result.js";
import { Stage, type Staged } from "./store.js";
import {
  checkBody,
  digest,
  embeddedKey,
  findings,
  genesis,
  limits,
  parseLine,
  signatureFinding,
  validatedKey,
} from "./wire.js";

type Discovery = ReturnType<typeof discover>;
type InputFile = Discovery["files"][number];

export interface Verification {
  opts: VerifyV3Options;
  result: V3Result;
  store: Stage;
  used: Set<string>;
  streams: Map<string, VerifiedStream>;
  histories: Map<string, VerifiedStream[]>;
  add(code: string, loc?: RecordPosition | string): void;
}

class Verifier implements Verification {
  readonly result: V3Result;
  readonly store = new Stage();
  readonly used = new Set<string>();
  readonly streams = new Map<string, VerifiedStream>();
  readonly histories = new Map<string, VerifiedStream[]>();
  private readonly keys = new Map<string, KeyObject | undefined>();
  private readonly trusted = new Set<string>();

  constructor(
    readonly opts: VerifyV3Options,
    ignored: number,
  ) {
    this.result = newResult(opts, ignored);
  }

  add(code: string, loc: RecordPosition | string = ""): void {
    this.result.findings.push(finding(code, loc));
  }

  private addStream(stream: string): void {
    if (!this.streams.has(stream))
      this.streams.set(stream, {
        limit: limits.integer,
        forked: false,
        successors: [],
        segment: -1,
        summary: { stream: "", signer: "", records: 0, end: "open" },
      });
  }

  discoverKeys(files: InputFile[]): void {
    for (const key of this.opts.keys ?? []) {
      const raw = Buffer.from(key, "hex");
      const id = digest(raw);
      this.trusted.add(id);
      this.keys.set(id, validatedKey(raw));
    }
    for (const file of files) {
      if (file.code || file.start > 0) continue;
      for (const { line, complete } of inputLines(file.path)) {
        if (complete) {
          const record = parseLine(line);
          if (typeof record !== "string") {
            const raw = embeddedKey(record);
            if (raw && !this.keys.has(record.signer))
              this.keys.set(record.signer, validatedKey(raw));
          }
        }
        break;
      }
    }
  }

  stageFiles(files: InputFile[]): void {
    const tails: { start: number; last: Staged }[] = [];
    const maxStarts = new Map<string, number>();
    for (const file of files) {
      if (file.code) {
        this.add(file.code, file.stream);
        continue;
      }
      const state = this.stageFile(file);
      if (!state.complete) continue;
      maxStarts.set(
        state.stream,
        Math.max(maxStarts.get(state.stream) ?? state.start, state.start),
      );
      if (state.torn && state.last) tails.push({ start: state.start, last: state.last });
    }
    for (const { start, last } of tails) {
      if (last.kind === "stream_close") this.add("DATA_AFTER_CLOSE", last);
      else if (start < maxStarts.get(last.stream)!) this.add("FILE_LAYOUT", last.stream);
      else this.add("TORN_TAIL", last);
    }
    this.store.seal();
  }

  private stageFile(file: InputFile) {
    const state = {
      stream: file.stream,
      start: file.start,
      broken: false,
      afterDamage: false,
      complete: false,
      torn: false,
      last: undefined as Staged | undefined,
    };
    let offset = 0;
    for (const { line, complete } of inputLines(file.path)) {
      if (!complete) {
        state.torn = state.complete;
        break;
      }
      if (!this.stageLine(line, state, offset++)) {
        state.broken = true;
        state.afterDamage = true;
      }
    }
    if (!state.complete && !state.broken) this.add("FILE_LAYOUT", state.stream);
    return state;
  }

  private stageLine(line: Buffer, state: FileState, offset: number): boolean {
    const record = parseLine(line);
    if (typeof record === "string") {
      this.add(record, state.stream);
      return false;
    }
    const issue = signatureFinding(record, this.keys.get(record.signer));
    if (issue) {
      this.add(issue, state.stream);
      return false;
    }
    this.used.add(record.signer);
    if (!state.complete) {
      if (
        offset === 0 &&
        state.start >= 0 &&
        (state.stream !== record.stream || state.start !== record.seq)
      ) {
        this.add("FILE_LAYOUT", record);
        return false;
      }
      if (state.start < 0) {
        state.stream = record.stream;
        state.start = record.seq - offset;
      }
    }
    if (record.stream !== state.stream || (!state.broken && record.seq !== state.start + offset)) {
      this.add("STREAM_ORDER", record);
      return false;
    }
    if (offset > 0 && state.last?.kind === "stream_close") {
      this.add("DATA_AFTER_CLOSE", record);
      return false;
    }
    if (
      !state.broken &&
      record.seq !== 0 &&
      (record.kind === "stream_open" ||
        (state.last && (state.last.id !== record.prev || state.last.signer !== record.signer)))
    ) {
      this.add("STREAM_ORDER", record);
      return false;
    }
    const { message: _message, signature: _signature, ...fields } = record;
    state.complete = true;
    state.last = { ...fields, ...checkBody(record), afterDamage: state.afterDamage };
    this.addStream(state.stream);
    this.store.add(state.last);
    state.afterDamage = false;
    return true;
  }

  verifyStreams(): void {
    for (const id of [...this.streams.keys()].sort()) {
      const stream = this.streams.get(id)!;
      this.verifyStream(id, stream);
      if (stream.broken) {
        delete stream.open;
        delete stream.body;
        delete stream.last;
      } else if (stream.body) {
        const lineage = stream.body.lineage;
        if (!this.histories.has(lineage)) this.histories.set(lineage, []);
        this.histories.get(lineage)!.push(stream);
      }
    }
  }

  private verifyStream(id: string, stream: VerifiedStream): void {
    let previous: Staged | undefined;
    let beat = 0;
    const publish = (current: Staged) => {
      const prior = stream.last;
      stream.last = current;
      let order = "";
      if (!prior) {
        if (current.seq !== 0 || current.kind !== "stream_open" || current.prev !== genesis(id))
          order = "STREAM_ORDER";
      } else if (prior.kind === "stream_close") order = "DATA_AFTER_CLOSE";
      else if (
        current.seq !== prior.seq + 1 ||
        current.prev !== prior.id ||
        current.signer !== prior.signer ||
        current.kind === "stream_open"
      )
        order = "STREAM_ORDER";
      if (
        order === "STREAM_ORDER" &&
        current.afterDamage &&
        (current.seq > (prior?.seq ?? 0) + 1 || (!prior && current.seq > 0))
      ) {
        stream.broken = true;
        this.checkStagedBody(current);
      } else if (order) this.add(order, current);
      else if (!this.checkStagedBody(current)) stream.broken = true;
      else {
        if (current.seq === 0 && current.kind === "stream_open") {
          stream.open = current;
          if (!current.unknown) stream.body = current.body as unknown as OpenBody;
        }
        if (prior && current.ts < prior.ts) this.add("CLOCK_REGRESSION", current);
        if (current.kind === "heartbeat" && !current.unknown && current.body.beat !== ++beat)
          this.add("HEARTBEAT_GAP", current);
        stream.summary.records++;
      }
    };
    const contested: string[] = [];
    for (const current of this.store.walk(id, limits.integer)) {
      if (stream.forked) {
        if (current.seq !== stream.limit + 1) break;
        this.add("FORK", current);
        if (stream.limit < 0) contested.push(current.id);
      } else if (previous?.seq === current.seq) {
        stream.forked = true;
        stream.limit = current.seq - 1;
        this.add("FORK", previous);
        this.add("FORK", current);
        if (stream.limit < 0) contested.push(previous.id, current.id);
        previous = undefined;
      } else {
        if (previous) publish(previous);
        previous = current;
      }
    }
    if (contested.length) this.result.contested_streams.push({ stream: id, records: contested });
    if (previous) publish(previous);
  }

  private checkStagedBody(record: Staged): boolean {
    if (record.bodyCode) {
      this.add(record.bodyCode, record);
      return findings[record.bodyCode] !== "invalid";
    }
    if (this.trusted.size && !this.trusted.has(record.signer)) this.add("TRUST", record);
    return true;
  }
}

interface FileState {
  stream: string;
  start: number;
  broken: boolean;
  afterDamage: boolean;
  complete: boolean;
  last?: Staged;
}

export interface VerifyV3Report {
  result: V3Result;
  projection: V3Projection;
}

/** Verify explicitly supplied files or the top-level evidence in one directory. */
export async function verifyV3Paths(
  paths: readonly string[],
  options: VerifyV3Options = {},
): Promise<VerifyV3Report> {
  const opts: VerifyV3Options = {
    ...options,
    keys: options.keys?.slice(),
    expectHeads: options.expectHeads?.map((head) => ({ ...head })),
    expectSequences: options.expectSequences?.map((sequence) => ({ ...sequence })),
    acceptDiscontinuities: options.acceptDiscontinuities?.slice(),
    allowPartialHistories: options.allowPartialHistories?.slice(),
  };
  validateOptions(paths, opts);
  const { files, legacy, inventories, ignored } = discover(paths, opts);
  const v = new Verifier(opts, ignored);
  try {
    v.discoverKeys(files);
    v.stageFiles(files);
    v.verifyStreams();
    verifySuccession(v);
    const cutoverEnds = await withRecorderFileExclusions(
      opts.directory ? files.map(({ path }) => basename(path)) : [],
      () => verifyCutover(v, legacy, inventories, files.length > 0),
    );
    appraiseDecisions(v);
    checkExpectations(v, cutoverEnds);
    v.result.trust.keys = [...v.used].sort();
    if (!files.length && v.result.legacy.length)
      throw new Error("legacy-only evidence requires the legacy verification path");
    if (!files.length && !v.result.findings.length) v.add("NO_EVIDENCE");
    const projection = finish(v.result, opts);
    return { result: v.result, projection };
  } finally {
    v.store.close();
  }
}
