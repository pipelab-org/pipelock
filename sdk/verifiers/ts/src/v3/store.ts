// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import {
  closeSync,
  mkdtempSync,
  openSync,
  readSync,
  rmdirSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ascii, type RecordV3 } from "./wire.js";

export type Staged = Omit<RecordV3, "message" | "signature"> & {
  bodyCode: string;
  unknown: boolean;
  afterDamage: boolean;
};

type Offset = Pick<Staged, "seq" | "id" | "kind" | "afterDamage"> & {
  start: number;
  size: number;
};

// Index positions in memory, keeping the decoded stream payloads in a private
// spool. Reads always deserialize one record at a time.
export class Stage {
  private readonly streams = new Map<string, Map<string, Offset>>();
  private readonly ordered = new Map<string, Offset[]>();
  private readonly dir = mkdtempSync(join(tmpdir(), "pipelock-v3-"));
  private readonly path = join(this.dir, "records");
  private readonly fd: number;
  private end = 0;

  constructor() {
    try {
      this.fd = openSync(this.path, "wx+", 0o600);
    } catch (error) {
      rmdirSync(this.dir);
      throw error;
    }
  }

  close(): void {
    try {
      closeSync(this.fd);
    } finally {
      unlinkSync(this.path);
      rmdirSync(this.dir);
    }
  }

  add(record: Staged): void {
    let stream = this.streams.get(record.stream);
    if (!stream) {
      stream = new Map();
      this.streams.set(record.stream, stream);
    }
    const key = record.seq + ":" + record.id;
    const existing = stream.get(key);
    if (existing) {
      existing.afterDamage &&= record.afterDamage;
      return;
    }
    const bytes = Buffer.from(JSON.stringify(record));
    let offset = 0;
    while (offset < bytes.length)
      offset += writeSync(this.fd, bytes, offset, bytes.length - offset, this.end + offset);
    stream.set(key, {
      seq: record.seq,
      id: record.id,
      kind: record.kind,
      afterDamage: record.afterDamage,
      start: this.end,
      size: bytes.length,
    });
    this.end += bytes.length;
  }

  seal(): void {
    for (const [stream, offsets] of this.streams)
      this.ordered.set(
        stream,
        [...offsets.values()].sort((a, b) => a.seq - b.seq || ascii(a.id, b.id)),
      );
    this.streams.clear();
  }

  *walk(stream: string, end: number): Generator<Staged> {
    for (const entry of this.ordered.get(stream) ?? []) {
      if (entry.seq > end) break;
      const bytes = Buffer.allocUnsafe(entry.size);
      let offset = 0;
      while (offset < entry.size) {
        const size = readSync(this.fd, bytes, offset, entry.size - offset, entry.start + offset);
        if (!size) throw new Error("incomplete staged receipt");
        offset += size;
      }
      const record: Staged = JSON.parse(bytes.toString("utf8"));
      record.afterDamage = entry.afterDamage;
      yield record;
    }
  }

  pin(stream: string, seq: number, limit: number): Offset | undefined {
    if (seq > limit) return undefined;
    const items = this.ordered.get(stream) ?? [];
    let low = 0;
    let high = items.length;
    while (low < high) {
      const middle = low + Math.floor((high - low) / 2);
      if (items[middle].seq < seq) low = middle + 1;
      else high = middle;
    }
    return items[low]?.seq === seq ? items[low] : undefined;
  }
}
