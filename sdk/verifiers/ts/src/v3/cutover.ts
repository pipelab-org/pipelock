// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { closeSync, readSync } from "node:fs";
import { cutoverMembershipKnown, type Cutover } from "./history.js";
import { openEvidence } from "./input.js";
import { legacyIdentity, verifyLegacy, type LegacyRow } from "./legacy.js";
import { prefixVerdict } from "./result.js";
import type { Staged } from "./store.js";
import type { Verification } from "./verify.js";
import { ascii, digest, isDigest, isID, limits } from "./wire.js";

const emptyInventory = digest('{"chains":[],"v":1}');

function compareRows(a: LegacyRow, b: LegacyRow): number {
  return ascii(a.format, b.format) || ascii(a.chain, b.chain);
}

function validRow(row: LegacyRow): boolean {
  if (
    !row ||
    typeof row.record !== "string" ||
    typeof row.chain !== "string" ||
    !isDigest(row.record) ||
    !Number.isSafeInteger(row.seq) ||
    row.seq < 0 ||
    row.seq > limits.integer
  )
    return false;
  switch (row.format) {
    case "action_v1":
      return isDigest(row.chain) || isID(row.chain);
    case "evidence_v2":
      return isDigest(row.chain);
    case "receipt_group":
      return isID(row.chain);
    default:
      return false;
  }
}

// Inventory fields are ASCII and have a fixed canonical shape. Each row
// fits in 256 bytes by construction, but the number of rows is unbounded.
const rowPattern =
  /^\{"chain":"([0-9a-f:sh]+)","format":"(action_v1|evidence_v2|receipt_group)","record":"(sha256:[0-9a-f]{64})","seq":(0|[1-9][0-9]*)\}$/u;
const journalPrefix = ',"journal":"';
const digestWidth = 71;

class InventoryReader {
  private readonly hash = createHash("sha256");
  private readonly chunk = Buffer.allocUnsafe(64 * 1024);
  private pending = "";
  private eof = false;

  constructor(private readonly fd: number) {}

  private fill(size: number): void {
    while (this.pending.length < size && !this.eof) {
      const read = readSync(this.fd, this.chunk, 0, this.chunk.length, null);
      if (!read) {
        this.eof = true;
        break;
      }
      const data = this.chunk.subarray(0, read);
      this.hash.update(data);
      this.pending += data.toString("latin1");
    }
  }

  take(size: number): string {
    this.fill(size);
    const bytes = this.pending.slice(0, size);
    this.pending = this.pending.slice(size);
    return bytes;
  }

  eat(value: string): boolean {
    this.fill(value.length);
    if (!this.pending.startsWith(value)) return false;
    this.pending = this.pending.slice(value.length);
    return true;
  }

  row(): LegacyRow | undefined {
    this.fill(256);
    const end = this.pending.indexOf("}");
    if (end < 0 || end >= 256) return undefined;
    const match = rowPattern.exec(this.take(end + 1));
    if (!match) return undefined;
    const [, chain, format, record, seq] = match;
    const row = { chain, format, record, seq: Number(seq) };
    return validRow(row) ? row : undefined;
  }

  matches(id: string): boolean {
    return !this.take(1) && "sha256:" + this.hash.digest("hex") === id;
  }
}

function decodeInventory(reader: InventoryReader, pin: Cutover): LegacyRow[] | undefined {
  if (!reader.eat('{"chains":[')) return undefined;
  const chains: LegacyRow[] = [];
  if (!reader.eat("]")) {
    do {
      const row = reader.row();
      const previous = chains.at(-1);
      if (
        !row ||
        (pin.chains >= 0 && chains.length >= pin.chains) ||
        (previous && compareRows(previous, row) >= 0)
      )
        return undefined;
      chains.push(row);
    } while (reader.eat(","));
    if (!reader.eat("]")) return undefined;
  }
  if (pin.chains >= 0 && chains.length !== pin.chains) return undefined;
  if (reader.eat(journalPrefix) && (!isDigest(reader.take(digestWidth)) || !reader.eat('"')))
    return undefined;
  if (!reader.eat(',"v":1}') || !reader.matches(pin.inventory)) return undefined;
  return chains;
}

function readInventory(path: string | undefined, pin: Cutover): LegacyRow[] | string {
  if (!path) {
    if (pin.inventory !== emptyInventory) return "CUTOVER_INVENTORY_NOT_PRESENTED";
    return pin.chains > 0 ? "CUTOVER_INVENTORY_MISMATCH" : [];
  }
  const fd = openEvidence(path);
  try {
    return decodeInventory(new InventoryReader(fd), pin) ?? "CUTOVER_INVENTORY_MISMATCH";
  } finally {
    closeSync(fd);
  }
}

export async function verifyCutover(
  v: Verification,
  legacy: string[],
  inventories: Map<string, string[]>,
  claimed: boolean,
): Promise<Map<string, Staged>> {
  const old = await verifyLegacy(v, legacy);
  if (old.size && claimed && !v.opts.directory)
    throw new Error("old-format and v3 evidence require directory scope; verify the directory");
  const unproven = new Map<string, Staged>();
  if (!claimed) return unproven;
  const checked = new Set<string>();
  const listed = new Set<string>();
  let known = cutoverMembershipKnown(v);
  for (const id of [...v.streams.keys()].sort()) {
    const stream = v.streams.get(id)!;
    const cutover = stream.body?.legacy_cutover;
    if (!cutover) continue;
    const open = stream.open!;
    checked.add(cutover.inventory);
    let inventory: LegacyRow[] | undefined;
    for (const path of inventories.get(cutover.inventory) ?? [undefined]) {
      const checked = readInventory(path, cutover);
      if (typeof checked === "string") v.add(checked, open);
      else inventory = checked;
    }
    if (!inventory) {
      known = false;
      continue;
    }
    for (const row of inventory) {
      const key = legacyIdentity(row);
      listed.add(key);
      const actual = old.get(key);
      if (!actual) v.add("LEGACY_CHAIN_NOT_PRESENTED", open);
      else if (
        actual.seq > row.seq ||
        (actual.record !== row.record &&
          !actual.forked &&
          actual.actionPositions &&
          [...actual.actionPositions.values()].includes(row.record))
      )
        v.add("LEGACY_EXTENDED_AFTER_CUTOVER", open);
      else if (actual.seq < row.seq) v.add("LEGACY_CHAIN_TRUNCATED", open);
      else if (actual.forked || actual.record !== row.record)
        v.add("LEGACY_CHAIN_HEAD_MISMATCH", open);
      else if (actual.verdict === prefixVerdict) unproven.set(open.id, open);
    }
  }
  for (const [id, paths] of inventories) {
    if (checked.has(id)) continue;
    for (const path of paths) {
      const result = readInventory(path, { inventory: id, chains: -1 });
      if (typeof result === "string") v.add(result);
    }
  }
  for (const key of old.keys()) {
    if (!listed.has(key)) v.add(known ? "LEGACY_CHAIN_UNLISTED" : "LEGACY_MEMBERSHIP_UNKNOWN");
  }
  return unproven;
}
