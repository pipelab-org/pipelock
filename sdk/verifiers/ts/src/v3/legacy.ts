// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { basename, dirname } from "node:path";
import { canonicalizeActionRecord } from "../canonical.js";
import { evidenceChainKey, receiptHash, verifyChain } from "../chain.js";
import {
  baseHealthy,
  checkFileEntrySessions,
  parseEvidenceFilename,
  recorderExcludedNames,
  readSessionEvidence,
  resolveBaseSessionsExcludingReceiptGroups,
  runSessionBase,
  sessionEvidenceFiles,
  verifyBase,
  withPinnedEvidenceDirectorySync,
} from "../chain-set.js";
import { verifyReceiptGroups } from "../group.js";
import { closeEndsChain } from "../lifecycle.js";
import { trimGoSpace } from "../line-space.js";
import { bindExtSource, objectMemberSpan } from "../rawjson.js";
import {
  parseEntryLinesText,
  type ExtractedReceipts,
  type ParsedRecorderLine,
} from "../recorder.js";
import { recorderEntryHash, verifyRecorderChain } from "../recorder-chain.js";
import { validateSecretEgressSource } from "../secret-egress.js";
import { validateV1Receipt } from "../strict.js";
import type { Receipt } from "../types.js";
import { forEachVerifierJSONLLine, rejectDuplicateKeys } from "../util.js";
import { isGroupArtifact } from "./input.js";
import { prefixVerdict, sortLegacy, type V3LegacyResult } from "./result.js";
import type { Verification } from "./verify.js";
import { byteOrder, digest, limits } from "./wire.js";

const actionFormat = "action_v1";
const evidenceFormat = "evidence_v2";
const groupFormat = "receipt_group";
const evidenceType = "evidence_receipt_v2";
const legacyInvalid = "INVALID";

export interface LegacyRow {
  format: string;
  chain: string;
  record: string;
  seq: number;
}

export interface LegacyPresentation extends LegacyRow {
  verdict: string;
  position: number;
  forked?: boolean;
  positions?: Map<number, string>;
}

export function compareCutoverPosition(actual: LegacyPresentation, row: LegacyRow): number {
  if (actual.record !== row.record && !actual.forked) {
    for (const [position, record] of actual.positions ?? []) {
      if (position >= 0 && position < actual.position && record === row.record) return 1;
    }
    // An absent sequence-zero pin can start a later signing epoch.
    if (actual.format === actionFormat && row.seq === 0 && actual.seq > 0) return -1;
  }
  return Math.sign(actual.seq - row.seq);
}

interface Batch extends ExtractedReceipts {
  recorder: boolean;
}

const identity = (format: string, chain: string): string => format + ":" + chain;
export const legacyIdentity = ({ format, chain }: LegacyRow): string => identity(format, chain);
const legacyDigest = (hash: string): string =>
  hash.startsWith("sha256:") ? hash : "sha256:" + hash;

function legacyVerdict(v: Verification, item: LegacyPresentation): V3LegacyResult {
  const row: V3LegacyResult = {
    chain: item.chain,
    format: item.format,
    verdict: item.verdict,
    class: "pass",
  };
  if (item.format === groupFormat) {
    if (item.verdict !== "GROUP_VALID") row.class = "failure";
    return row;
  }
  const label = item.format === evidenceFormat ? "EVIDENCE CHAIN" : "CHAIN";
  if (item.verdict === legacyInvalid || item.forked) {
    row.class = "failure";
    row.verdict = label + " BROKEN";
  } else if (item.verdict === prefixVerdict) {
    if (!v.opts.allowPrefix || (!v.opts.keys?.length && !v.opts.allowUnpinned))
      row.class = "failure";
  } else if (!v.opts.keys?.length) {
    row.verdict = label + " UNPINNED";
    if (!v.opts.allowUnpinned) row.class = "failure";
  } else {
    row.verdict = label + " VALID";
  }
  return row;
}

function unavailable(error: unknown): boolean {
  const err = error as NodeJS.ErrnoException;
  return (
    ["EACCES", "EPERM", "EIO", "EINTR", "EAGAIN", "ESTALE"].includes(err.code ?? "") ||
    /evidence (?:file )?changed (?:while|during)/u.test(err.message)
  );
}

function failure(
  v: Verification,
  chain: string,
  format: string,
  verdict: string,
  incomplete = false,
): void {
  v.add(incomplete ? "LEGACY_GROUP_INCOMPLETE" : "LEGACY_INVALID");
  v.result.legacy.push({ chain, format, verdict, class: "failure" });
}

function readLegacy(path: string): Batch {
  const batch: Batch = { action: [], evidence: [], recorder: false };
  let mode = "";
  let previous: ParsedRecorderLine | undefined;
  let unrecognized = false;
  forEachVerifierJSONLLine(path, false, (raw) => {
    if (unrecognized) return;
    const line = trimGoSpace(raw);
    if (!line) return;
    const item: Receipt = JSON.parse(line);
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      if (item !== null) throw new Error("malformed legacy record");
      unrecognized = true;
      return;
    }
    const kind =
      item.record_type === evidenceType
        ? "evidence"
        : !item.record_type && item.version === 1 && !item.type
          ? "action"
          : item.type && item.session_id
            ? "recorder"
            : "";
    if (mode && mode !== kind) throw new Error("mixed legacy record");
    mode = kind;
    switch (mode) {
      case "action": {
        rejectDuplicateKeys(line);
        validateV1Receipt(item);
        const span = objectMemberSpan(line, 0, "ext");
        if (span) bindExtSource(item, line.slice(span.start, span.end));
        batch.action.push(item);
        break;
      }
      case "evidence":
        rejectDuplicateKeys(line);
        validateSecretEgressSource(item, line);
        batch.evidence.push(item);
        break;
      case "recorder": {
        const entry = parseEntryLinesText(line)[0];
        const fields = entry.entry as typeof entry.entry & { hash?: string };
        const claim = parseEvidenceFilename(basename(path));
        const seq = BigInt(fields.seq ?? 0);
        if (
          (claim &&
            (claim.session !== fields.session_id || (!previous && claim.seqStart !== seq))) ||
          recorderEntryHash(entry.line) !== fields.hash ||
          (!previous && seq === 0n && fields.prev_hash !== "genesis") ||
          (previous &&
            (previous.entry.session_id !== fields.session_id ||
              BigInt(previous.entry.seq ?? 0) + 1n !== seq ||
              recorderEntryHash(previous.line) !== fields.prev_hash))
        )
          throw new Error("recorder entry has invalid sequence or hash");
        previous = entry;
        if (fields.type === "action_receipt") {
          validateV1Receipt(fields.detail);
          batch.action.push(fields.detail as Receipt);
        } else if (fields.type === "evidence_receipt")
          batch.evidence.push(fields.detail as Receipt);
        break;
      }
      default:
        unrecognized = true;
    }
  });
  batch.recorder = mode === "recorder";
  return batch;
}

function readBareEvidence(dir: string, session: string): Receipt[] | undefined {
  // Apply Go's compatibility discriminator before reading recorder metadata.
  return withPinnedEvidenceDirectorySync(dir, () => {
    const evidence: Receipt[] = [];
    const notBare = Symbol("not bare evidence");
    try {
      for (const file of sessionEvidenceFiles(".", session)) {
        forEachVerifierJSONLLine(basename(file), true, (raw) => {
          const line = trimGoSpace(raw);
          if (!line) return;
          let item: { type?: unknown; detail?: Receipt };
          try {
            rejectDuplicateKeys(line);
            item = JSON.parse(line);
          } catch {
            throw notBare;
          }
          if (
            !item ||
            Object.keys(item).length !== 2 ||
            item.type !== "evidence_receipt" ||
            !item.detail ||
            typeof item.detail !== "object" ||
            Array.isArray(item.detail)
          )
            throw notBare;
          const span = objectMemberSpan(line, 0, "detail");
          validateSecretEgressSource(item.detail, line, span?.start);
          evidence.push(item.detail);
        });
      }
    } catch (err) {
      if (err === notBare) return undefined;
      throw err;
    }
    return evidence.length ? evidence : undefined;
  });
}

function readSession(dir: string, session: string): Batch {
  const bare = readBareEvidence(dir, session);
  if (bare) return { action: [], evidence: bare, recorder: true };
  return withPinnedEvidenceDirectorySync(dir, () => {
    const { lines, typed } = readSessionEvidence(".", session);
    checkFileEntrySessions("evidence-" + session + "-0.jsonl", lines);
    const issue = verifyRecorderChain(lines);
    if (issue) throw new Error(issue);
    return { ...typed, recorder: true };
  });
}

class LegacyVerifier {
  readonly presented = new Map<string, LegacyPresentation>();
  private readonly positions = new Map<string, Map<number, string>>();
  private readonly forks = new Set<string>();
  private readonly keys: string;

  constructor(private readonly v: Verification) {
    this.keys = (v.opts.keys ?? []).join(",");
  }

  async verifyBatch(batch: Batch): Promise<void> {
    await this.verifyChains(batch.action, actionFormat, batch.recorder);
    await this.verifyChains(batch.evidence, evidenceFormat, batch.recorder);
  }

  private async verifyChains(records: Receipt[], format: string, recorder: boolean): Promise<void> {
    const action = format === actionFormat;
    const seq = (item: Receipt) => (action ? item.action_record?.chain_seq : item.chain_seq) ?? 0;
    const hash = (item: Receipt): string => {
      try {
        return action
          ? digest(canonicalizeActionRecord(item.action_record!))
          : legacyDigest(receiptHash(item));
      } catch {
        return "sha256:";
      }
    };
    for (let first = 0; first < records.length;) {
      let end = first + 1;
      while (
        end < records.length &&
        (recorder ||
          seq(records[end]) !== 0 ||
          (action && records[end].action_record?.key_transition !== undefined))
      )
        end++;
      const chain = records.slice(first, end);
      const id = (action && chain[0].action_record?.run_nonce) || hash(chain[0]);
      const key = identity(format, id);
      const positions = this.positions.get(key) ?? new Map<number, string>();
      this.positions.set(key, positions);
      for (const [index, item] of chain.entries()) {
        const slot = action ? index : seq(item);
        const record = hash(item);
        if (slot > limits.integer || (positions.has(slot) && positions.get(slot) !== record))
          this.forks.add(key);
        if (slot <= limits.integer) positions.set(slot, record);
        const signer = action
          ? item.signer_key
          : typeof item.signature === "object"
            ? item.signature?.signer_key_id
            : undefined;
        if (typeof signer === "string" && /^[0-9a-f]{64}$/iu.test(signer))
          this.v.used.add(digest(Buffer.from(signer, "hex")));
      }
      const trusted = action ? this.keys : evidenceChainKey(this.keys, chain);
      let valid = false;
      try {
        valid = (await verifyChain(chain, trusted, { allowUnpinned: !trusted })).valid;
      } catch {
        // Parsed legacy claims can still fail verification structurally.
      }
      const last = chain.at(-1)!;
      const verdict = action && closeEndsChain(chain) ? "VALID" : prefixVerdict;
      const item: LegacyPresentation = {
        chain: id,
        format,
        seq: seq(last),
        record: hash(last),
        verdict,
        position: action ? chain.length - 1 : seq(last),
        positions,
      };
      this.save(key, item, valid);
      first = end;
    }
  }

  private save(key: string, item: LegacyPresentation, valid: boolean): void {
    if (item.seq > limits.integer || item.position > limits.integer) {
      this.v.add("LEGACY_INVALID");
      return;
    }
    const prior = this.presented.get(key);
    const selected = !prior || item.position > prior.position ? item : prior;
    if (!valid) this.v.add("LEGACY_INVALID");
    if (!valid || prior?.verdict === legacyInvalid) selected.verdict = legacyInvalid;
    selected.forked = this.forks.has(key);
    this.presented.set(key, selected);
  }
}

export async function verifyLegacy(
  v: Verification,
  paths: string[],
): Promise<Map<string, LegacyPresentation>> {
  const verifier = new LegacyVerifier(v);
  const sessions = new Map<string, string>();
  const groupDirs = new Map<string, boolean>();
  const bases = new Map<string, string>();
  for (const path of paths) {
    const dir = dirname(path);
    const name = basename(path);
    if (v.opts.directory) {
      groupDirs.set(dir, false);
      if (isGroupArtifact(name)) continue;
      const parsed = parseEvidenceFilename(name);
      if (parsed) {
        sessions.set(parsed.session, dir);
        continue;
      }
    }
    try {
      const batch = readLegacy(path);
      if (batch.action.length || batch.evidence.length) await verifier.verifyBatch(batch);
      else if (batch.recorder && v.opts.directory) v.result.ignored_files++;
      else v.add("UNRECOGNIZED_FILE");
    } catch (error) {
      failure(v, "", actionFormat, unavailable(error) ? "CHAIN UNAVAILABLE" : "CHAIN BROKEN");
    }
  }

  for (const dir of [...groupDirs.keys()].sort(byteOrder)) {
    const summary = await verifyReceiptGroups(
      dir,
      v.opts.keys ?? [],
      (group) => {
        if (group.verdict === "GROUP_INCOMPLETE") v.add("LEGACY_GROUP_INCOMPLETE");
        if (group.verdict === "GROUP_INVALID") v.add("LEGACY_INVALID");
        const head = group.close_manifest_sha256 ?? group.open_manifest_sha256;
        verifier.presented.set(identity(groupFormat, group.group_id), {
          chain: group.group_id,
          format: groupFormat,
          record: head ? legacyDigest(head) : "",
          seq: group.shard_count,
          position: 0,
          verdict: group.verdict,
        });
      },
      recorderExcludedNames(),
    );
    if (summary.error)
      failure(
        v,
        "",
        groupFormat,
        summary.unavailable ? "GROUP_INCOMPLETE" : "GROUP_INVALID",
        summary.unavailable,
      );
    groupDirs.set(dir, summary.groups > 0 || summary.error !== undefined);
  }

  const ordinary = new Map<string, string[]>();
  for (const session of [...sessions.keys()].sort(byteOrder)) {
    const dir = sessions.get(session)!;
    const base = runSessionBase(session);
    if (groupDirs.get(dir)) {
      const name = base ?? session;
      if (!ordinary.has(name))
        ordinary.set(name, resolveBaseSessionsExcludingReceiptGroups(dir, name));
      if (!ordinary.get(name)!.includes(session)) continue;
    }
    if (base !== undefined) bases.set(base, dir);
    try {
      const batch = readSession(dir, session);
      if (batch.action.length || batch.evidence.length) await verifier.verifyBatch(batch);
      else v.result.ignored_files++;
    } catch (error) {
      failure(v, session, actionFormat, unavailable(error) ? "CHAIN UNAVAILABLE" : "CHAIN BROKEN");
    }
  }

  for (const base of [...bases.keys()].sort(byteOrder)) {
    const dir = bases.get(base)!;
    try {
      const restart = await verifyBase(dir, base, {
        trustedKeys: [...(v.opts.keys ?? [])],
        endorsements: [],
        excludeReceiptGroupSessions: groupDirs.get(dir),
      });
      if (!baseHealthy(restart)) failure(v, base, actionFormat, "RESTART CONTINUITY FAILED");
    } catch {
      failure(v, base, actionFormat, "RESTART CONTINUITY INCOMPLETE");
    }
  }

  for (const item of verifier.presented.values()) v.result.legacy.push(legacyVerdict(v, item));
  sortLegacy(v.result.legacy);
  return verifier.presented;
}
