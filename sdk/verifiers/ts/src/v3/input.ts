// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
} from "node:fs";
import { basename, join } from "node:path";
import { parseEvidenceFilename } from "../chain-set.js";
import { byteOrder, isDigest, isID, isKey, limits, profilePrefix } from "./wire.js";

export interface V3Position {
  record: string;
  seq: number;
}

export interface V3Sequence {
  stream: string;
  seq: number;
}

export interface V3Head extends V3Sequence, V3Position {}

export interface VerifyV3Options {
  keys?: readonly string[];
  directory?: boolean;
  explicitV3?: boolean;
  allowPrefix?: boolean;
  allowUnpinned?: boolean;
  expectLineage?: string;
  expectHeads?: readonly V3Head[];
  expectSequences?: readonly V3Sequence[];
  acceptDiscontinuities?: readonly string[];
  allowPartialHistories?: readonly string[];
}

export function parseSequence(value: string): V3Sequence {
  const match = /^([a-f0-9]{32}):(0|[1-9][0-9]*)$/u.exec(value);
  const seq = Number(match?.[2]);
  if (!match || seq > limits.integer) throw new Error("expected sequence must be stream:seq");
  return { stream: match[1], seq };
}

export function parseHead(value: string): V3Head {
  const match = /^([^:]+:[^:]+):(sha256:[0-9a-f]{64})$/u.exec(value);
  if (match) {
    try {
      return { ...parseSequence(match[1]), record: match[2] };
    } catch {
      // Report the head syntax for an invalid sequence inside a head.
    }
  }
  throw new Error("expected head must be stream:seq:sha256:digest");
}

export function validateOptions(paths: readonly string[], opts: VerifyV3Options): void {
  if (opts.explicitV3 && opts.directory)
    throw new Error("explicit v3 format applies only to a single file");
  if (opts.explicitV3 && paths.length !== 1)
    throw new Error("explicit v3 format requires exactly one file");
  if (opts.directory && paths.length !== 1)
    throw new Error("directory scope requires exactly one directory");
  if (opts.keys?.some((key) => !isKey(key)))
    throw new Error("key must be 64 lowercase hexadecimal characters");
  if (opts.expectLineage && !isID(opts.expectLineage))
    throw new Error("expected lineage must be 32 lowercase hexadecimal characters");
  if (opts.allowPartialHistories?.some((id) => !isID(id)))
    throw new Error("partial history must name a 32-character stream ID");
  if (opts.acceptDiscontinuities?.some((id) => !isDigest(id)))
    throw new Error("accepted discontinuity must be a record ID");
  for (const head of opts.expectHeads ?? []) parseHead(headValue(head));
  for (const sequence of opts.expectSequences ?? []) parseSequence(sequenceValue(sequence));
}

export const sequenceValue = ({ stream, seq }: V3Sequence): string => stream + ":" + seq;
export const headValue = (head: V3Head): string => sequenceValue(head) + ":" + head.record;

interface InputFile {
  path: string;
  start: number;
  stream: string;
  code?: string;
}

const profileName = /\.receipt-v([0-9]+)\.jsonl$/u;
const streamName = /^([0-9a-f]{32})-([0-9]{16})\.receipt-v3\.jsonl$/u;
const inventoryName = /^receipt-v3-cutover-([0-9a-f]{64})\.json$/u;

function identify(path: string): InputFile | undefined {
  const name = basename(path);
  const version = profileName.exec(name);
  if (!version) return undefined;
  if (version[1] !== "3") return { path, start: -1, stream: "", code: "UNKNOWN_PROFILE" };
  const parts = streamName.exec(name);
  if (!parts) return { path, start: -1, stream: "", code: "FILE_LAYOUT" };
  return { path, start: Number(parts[2]), stream: parts[1] };
}

export function isGroupArtifact(name: string): boolean {
  return name.startsWith("receipt-group-") && name.endsWith(".json");
}

// Go discovery: internal/receipt/v3/legacy.go:43, internal/receipt/chain_set.go:358,
// internal/ael/emitter.go:138 and internal/receipt/group_inventory.go:83.
export function legacyCandidate(name: string): boolean {
  return (
    parseEvidenceFilename(name) !== undefined ||
    name === "ael" ||
    (name.startsWith("chain-link-") && name.endsWith(".json")) ||
    isGroupArtifact(name) ||
    [
      "activation-receipts.jsonl",
      "redaction-receipts.jsonl",
      "ratification-receipts.jsonl",
    ].includes(name)
  );
}

export function openEvidence(path: string): number {
  const fd = openSync(
    realpathSync(path),
    constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW,
  );
  try {
    if (!fstatSync(fd).isFile()) throw new Error("evidence path is not a regular file: " + path);
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

const prefix = Buffer.from(profilePrefix);

export function claimsV3Input(path: string): boolean {
  return identify(path) !== undefined || startsWithProfile(path);
}

function nestedReceiptProfile(root: string): string | undefined {
  // Dirent.isDirectory does not follow symlinks, so the walk stays on the tree
  // the caller named. A profile-shaped symlink still claims its parent directory.
  const pending = readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(root, entry.name));
  const seen = new Set<string>();
  while (pending.length) {
    const path = pending.pop();
    if (path === undefined || seen.has(path)) continue;
    seen.add(path);
    const children = readdirSync(path, { withFileTypes: true });
    for (const child of children) {
      const childPath = join(path, child.name);
      if (child.isDirectory()) {
        pending.push(childPath);
        continue;
      }
      if (
        profileName.test(child.name) ||
        (child.isFile() && legacyCandidate(child.name) && startsWithProfile(childPath))
      ) {
        return path;
      }
    }
  }
  return undefined;
}

function startsWithProfile(path: string): boolean {
  const fd = openEvidence(path);
  try {
    const bytes = Buffer.alloc(prefix.length);
    let offset = 0;
    while (offset < bytes.length) {
      const size = readSync(fd, bytes, offset, bytes.length - offset, null);
      if (!size) return false;
      offset += size;
    }
    return bytes.equals(prefix);
  } finally {
    closeSync(fd);
  }
}

export function discover(paths: readonly string[], options: VerifyV3Options) {
  let ignored = 0;
  const oldCandidates: string[] = [];
  if (options.directory) {
    const dir = realpathSync(paths[0]);
    paths = readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      if (!profileName.test(entry.name) && legacyCandidate(entry.name)) {
        if (entry.name !== "ael" && !entry.isFile())
          throw new Error("evidence path is not a regular file: " + join(dir, entry.name));
        oldCandidates.push(join(dir, entry.name));
        return [];
      }
      if (
        !profileName.test(entry.name) &&
        !inventoryName.test(entry.name) &&
        !legacyCandidate(entry.name)
      ) {
        ignored++;
        return [];
      }
      const path = join(dir, entry.name);
      if (!entry.isFile()) throw new Error("evidence path is not a regular file: " + path);
      return [path];
    });
    const nested = nestedReceiptProfile(dir);
    if (nested) {
      throw new Error(
        "receipt profile in " +
          nested +
          " is outside this directory verification; run 'pipelock verify-receipt --chain " +
          nested +
          "' with the trusted signer key",
      );
    }
  } else {
    for (const path of paths) closeSync(openEvidence(path));
  }
  const namedV3 =
    !options.directory && !options.explicitV3 && paths.some((path) => identify(path) !== undefined);
  const files: InputFile[] = [];
  const legacy: string[] = oldCandidates;
  const inventories = new Map<string, string[]>();
  for (const path of [...new Set(paths)].sort(byteOrder)) {
    const inventory = inventoryName.exec(basename(path));
    if (inventory && !options.explicitV3) {
      const id = "sha256:" + inventory[1];
      if (!inventories.has(id)) inventories.set(id, []);
      inventories.get(id)!.push(path);
      continue;
    }
    const file = identify(path);
    if (file) files.push(file);
    else if (options.explicitV3) files.push({ path, start: -1, stream: "" });
    else if (namedV3 || legacyCandidate(basename(path))) legacy.push(path);
    else if (startsWithProfile(path))
      files.push({ path, start: -1, stream: "", code: "V3_CONTENT_UNCLAIMED" });
    else legacy.push(path);
  }
  return { files, legacy, inventories, ignored };
}

export interface InputLine {
  line: Buffer;
  complete: boolean;
}

// Keep at most one record plus a 64 KiB read buffer, even for overlong lines.
export function* inputLines(path: string): Generator<InputLine> {
  const fd = openEvidence(path);
  const chunk = Buffer.allocUnsafe(64 * 1024);
  const line = Buffer.allocUnsafe(limits.line_bytes + 1);
  let used = 0;
  try {
    for (;;) {
      const size = readSync(fd, chunk, 0, chunk.length, null);
      if (!size) break;
      let start = 0;
      while (start < size) {
        const lf = chunk.subarray(0, size).indexOf(0x0a, start);
        const end = lf === -1 ? size : lf + 1;
        used += chunk.copy(line, used, start, Math.min(end, start + line.length - used));
        if (lf !== -1) {
          yield { line: line.subarray(0, used), complete: true };
          used = 0;
        }
        start = end;
      }
    }
    if (used) yield { line: line.subarray(0, used), complete: false };
  } finally {
    closeSync(fd);
  }
}
