// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import type { AuditPacket, AuditPacketReport, ChainResult, Receipt, Totals } from "./types.js";
import * as ed25519 from "@noble/ed25519";
import { computeTotals, evidenceChainKey, verifyChain } from "./chain.js";
import { isRunSession } from "./chain-set.js";
import { analyzeLifecycle, closeEndsChain } from "./lifecycle.js";
import { extractTypedFromEntries, readEntryLines, selectReceiptChain } from "./recorder.js";
import { verifyRecorderChain } from "./recorder-chain.js";
import { validateAuditPacket } from "./schema.js";
import {
  decodeUTF8,
  readVerifierBytes,
  rejectDuplicateKeys,
  resolveArtifactPath,
  resolvePacketPath,
  resolveSignerKey,
  sha256Hex,
} from "./util.js";

export interface AuditPacketOptions {
  signerKey: string;
  // signerKeys is the trusted key set (each a hex key or key file), used
  // instead of signerKey when non-empty, as repeated --key flags give it.
  signerKeys?: string[];
  offline: boolean;
  allowSelfConsistentOnly: boolean;
  noTrustRequired: boolean;
  expectSha256: string;
}

const zeroTotals: Totals = {
  allow: 0,
  block: 0,
  warn: 0,
  ask: 0,
  strip: 0,
  forward: 0,
  redirect: 0,
  other: 0,
};

function reportFromPacket(packetPath: string, packet?: AuditPacket): AuditPacketReport {
  return {
    integrity: "invalid",
    end_proof: { proven: false, evidence: [] },
    scope: "audit_packet",
    status: "PACKET INVALID",
    path: packetPath,
    verdict: packet?.verifier?.verdict ?? "",
    trusted: packet?.verifier?.trusted ?? false,
    valid: false,
    summary: {
      receipt_count: 0,
      totals: { ...zeroTotals },
    },
    posture: {
      enforcement_mode: packet?.posture?.enforcement_mode ?? "",
      unsupported_paths: packet?.posture?.unsupported_paths ?? [],
    },
    run: {
      provider: packet?.run?.provider ?? "",
      repository: packet?.run?.repository,
      sha: packet?.run?.sha,
      agent_identity: packet?.run?.agent_identity ?? "",
    },
    warnings: packet
      ? [
          "run and posture fields are packet claims and are not authenticated by receipt-chain verification",
        ]
      : undefined,
    schema_check: "skipped",
    chain_check: "skipped",
    cross_check: "skipped",
    lifecycle_assessment: "not_assessed",
    lifecycle_assessment_reason: "chain re-verification did not complete",
  };
}

function pushError(report: AuditPacketReport, message: string): void {
  report.errors = [...(report.errors ?? []), message];
}

function trustVerdict(packet: AuditPacket, opts: AuditPacketOptions): boolean {
  if (opts.noTrustRequired) return true;
  switch (packet.verifier?.verdict) {
    case "valid":
      return packet.verifier.trusted === true;
    case "self_consistent_only":
      return opts.allowSelfConsistentOnly;
    default:
      return false;
  }
}

function crossCheck(packet: AuditPacket, chain: ChainResult, receipts: Receipt[]): string[] {
  const errors: string[] = [];
  const receiptCount = packet.summary?.receipt_count ?? -1;
  if (chain.receipt_count !== receiptCount) {
    errors.push(
      `chain receipt_count ${chain.receipt_count} != packet.summary.receipt_count ${receiptCount}`,
    );
  }
  const expectedTotals = computeTotals(receipts);
  const gotTotals = { ...zeroTotals, ...(packet.summary?.totals ?? {}) };
  for (const key of Object.keys(expectedTotals).sort() as (keyof Totals)[]) {
    if (expectedTotals[key] !== gotTotals[key]) {
      errors.push(`totals[${key}]: chain=${expectedTotals[key]} packet=${gotTotals[key]}`);
    }
  }
  if (packet.verifier?.root_hash && packet.verifier.root_hash !== chain.root_hash) {
    errors.push(`root_hash mismatch: chain=${chain.root_hash} packet=${packet.verifier.root_hash}`);
  }
  if (packet.verifier?.final_seq !== undefined && packet.verifier.final_seq !== chain.final_seq) {
    errors.push(
      `final_seq mismatch: chain=${chain.final_seq} packet=${String(packet.verifier?.final_seq)}`,
    );
  }
  switch (packet.verifier?.verdict) {
    case "valid":
    case "self_consistent_only":
      if (!chain.valid) {
        errors.push(`verdict=${packet.verifier.verdict} but chain rejected: ${chain.error ?? ""}`);
      }
      break;
    case "invalid":
      if (chain.valid) errors.push("verdict=invalid but chain re-verified successfully");
      break;
  }
  return errors;
}

function recorderInteger(value: unknown, label: string): bigint {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)) return BigInt(value);
  throw new Error(`${label} is missing or invalid`);
}

async function verifyV2RecorderEnd(
  lines: ReturnType<typeof readEntryLines>,
  actionReceipts: Receipt[],
  actionChain: ChainResult,
): Promise<boolean> {
  const outer = verifyRecorderChain(lines);
  if (outer !== undefined) throw new Error(`recorder hash chain: ${outer}`);

  const actionIndexes = lines.flatMap((line, index) =>
    line.entry.type === "action_receipt" ? [index] : [],
  );
  const evidenceIndexes = lines.flatMap((line, index) =>
    line.entry.type === "evidence_receipt" ? [index] : [],
  );
  if (actionIndexes.length !== actionReceipts.length) {
    throw new Error("recorder action receipt inventory differs from the verified chain");
  }

  const roots = lines.flatMap((line, index) =>
    line.entry.type === "transcript_root" ? [index] : [],
  );
  if (roots.length === 0) {
    await validateCheckpoints(lines, actionIndexes);
    return false;
  }
  const rootIndex = roots[roots.length - 1] as number;
  for (const index of roots) {
    const entry = lines[index]?.entry;
    const detail = entry?.detail;
    if (typeof detail !== "object" || detail === null || Array.isArray(detail)) {
      throw new Error("transcript_root detail is not an object");
    }
    const record = detail as Record<string, unknown>;
    if (typeof record["session_id"] !== "string") {
      throw new Error("transcript_root session_id is missing");
    }
    recorderInteger(record["final_seq"], "transcript_root final_seq");
    recorderInteger(record["receipt_count"], "transcript_root receipt_count");
    if (typeof record["root_hash"] !== "string") {
      throw new Error("transcript_root root_hash is missing");
    }
  }
  const rootEntry = lines[rootIndex]?.entry;
  const root = rootEntry?.detail;
  if (typeof root !== "object" || root === null || Array.isArray(root)) {
    throw new Error("transcript_root detail is not an object");
  }
  const rootDetail = root as Record<string, unknown>;
  const rootSession = rootDetail["session_id"];
  const entrySession = rootEntry.session_id;
  if (typeof rootSession !== "string" || typeof entrySession !== "string") {
    throw new Error("transcript_root session_id is missing");
  }
  if (rootSession !== entrySession) {
    throw new Error("transcript_root detail session differs from its recorder entry");
  }
  const finalSeq = recorderInteger(rootDetail["final_seq"], "transcript_root final_seq");
  const receiptCount = recorderInteger(
    rootDetail["receipt_count"],
    "transcript_root receipt_count",
  );
  const rootHash = rootDetail["root_hash"];
  if (typeof rootHash !== "string") throw new Error("transcript_root root_hash is missing");
  if (
    actionIndexes.length === 0 ||
    actionIndexes.at(-1)! >= rootIndex ||
    evidenceIndexes.some((index) => index >= rootIndex) ||
    finalSeq !== BigInt(actionChain.final_seq) ||
    rootHash !== actionChain.root_hash ||
    receiptCount === 0n ||
    receiptCount > BigInt(actionReceipts.length) ||
    receiptCount !== BigInt(finalSegmentReceiptCount(actionReceipts))
  ) {
    throw new Error("transcript_root does not match the verified action receipt chain");
  }

  const afterRoot = lines.slice(rootIndex + 1);
  if (afterRoot.length > 1 || (afterRoot.length > 0 && afterRoot[0]?.entry.type !== "checkpoint")) {
    throw new Error("transcript_root is followed by unsealed recorder entries");
  }
  await validateCheckpoints(lines, actionIndexes);
  if (!isRunSession(rootSession)) return false;
  const checkpoint = afterRoot[0];
  if (checkpoint === undefined) return false;
  const detail = checkpoint.entry.detail;
  if (typeof detail !== "object" || detail === null || Array.isArray(detail)) {
    throw new Error("trailing checkpoint detail is not an object");
  }
  const signature = (detail as Record<string, unknown>)["signature"];
  if (typeof signature !== "string") throw new Error("trailing checkpoint signature is missing");
  return signature !== "";
}

function finalSegmentReceiptCount(receipts: Receipt[]): number {
  let start = 0;
  for (let index = 0; index < receipts.length; index++) {
    if (receipts[index]?.action_record?.key_transition !== undefined) start = index;
  }
  return receipts.length - start;
}

async function validateCheckpoints(
  lines: ReturnType<typeof readEntryLines>,
  actionIndexes: number[],
): Promise<void> {
  let previousCheckpointSeq: bigint | undefined;
  for (const [index, line] of lines.entries()) {
    if (line.entry.type !== "checkpoint") continue;
    const seq = recorderInteger(line.entry.seq, "checkpoint sequence");
    const preceding = lines[index - 1];
    if (preceding === undefined) throw new Error("checkpoint has no preceding recorder entry");
    const precedingSeq = recorderInteger(preceding.entry.seq, "checkpoint preceding sequence");
    const detail = line.entry.detail;
    if (typeof detail !== "object" || detail === null || Array.isArray(detail)) {
      throw new Error("checkpoint detail is not an object");
    }
    const checkpoint = detail as Record<string, unknown>;
    const firstSeq = recorderInteger(checkpoint["first_seq"], "checkpoint first_seq");
    const lastSeq = recorderInteger(checkpoint["last_seq"], "checkpoint last_seq");
    const entryCount = recorderInteger(checkpoint["entry_count"], "checkpoint entry_count");
    if (
      lastSeq !== precedingSeq ||
      firstSeq > lastSeq ||
      entryCount === 0n ||
      entryCount - 1n !== lastSeq - firstSeq ||
      (previousCheckpointSeq !== undefined && firstSeq <= previousCheckpointSeq)
    ) {
      throw new Error(`checkpoint span is invalid at recorder seq ${seq}`);
    }
    previousCheckpointSeq = seq;

    const signature = checkpoint["signature"];
    if (typeof signature !== "string") throw new Error("checkpoint signature is missing");
    if (signature === "") continue;
    if (!/^[0-9a-f]{128}$/u.test(signature)) throw new Error("checkpoint signature is malformed");
    const previousHash = line.entry.prev_hash;
    if (typeof previousHash !== "string") throw new Error("checkpoint prev_hash is missing");
    const previousIndex = [...actionIndexes].reverse().find((receiptIndex) => receiptIndex < index);
    const nextIndex = actionIndexes.find((receiptIndex) => receiptIndex > index);
    const signerKeyAt = (receiptIndex: number): string => {
      const key = (lines[receiptIndex]?.entry.detail as Record<string, unknown> | undefined)?.[
        "signer_key"
      ];
      if (typeof key !== "string" || !/^[0-9a-f]{64}$/u.test(key)) {
        throw new Error("signed checkpoint has no valid action receipt signer");
      }
      return key;
    };
    const verifyWith = async (receiptIndex: number): Promise<boolean> =>
      ed25519.verifyAsync(
        Buffer.from(signature, "hex"),
        Buffer.from(previousHash),
        Buffer.from(signerKeyAt(receiptIndex), "hex"),
        { zip215: false },
      );
    if (previousIndex !== undefined) {
      if (await verifyWith(previousIndex)) continue;
      if (
        nextIndex !== undefined &&
        signerKeyAt(previousIndex) !== signerKeyAt(nextIndex) &&
        (await verifyWith(nextIndex))
      ) {
        continue;
      }
    } else if (nextIndex !== undefined && (await verifyWith(nextIndex))) {
      continue;
    }
    throw new Error(`checkpoint signature is invalid at recorder seq ${seq}`);
  }
}

// withoutClaimedTrust keeps a failed verification from repeating the
// packet's own trust claim. The report starts with the packet's verdict and
// trusted fields, so any failure after that point would otherwise report
// "verdict: valid, trusted: true" beside an INVALID result. A report that is
// not valid never claims trust, and a success verdict becomes invalid. A
// successful report and the offline report are unchanged.
function withoutClaimedTrust(report: AuditPacketReport): AuditPacketReport {
  if (report.valid) return report;
  report.trusted = false;
  if (report.status === "VALID PREFIX, END UNPROVEN") {
    report.verdict = report.status;
    return report;
  }
  if (report.verdict === "valid" || report.verdict === "self_consistent_only") {
    report.verdict = "invalid";
  }
  return report;
}

export async function verifyAuditPacket(
  target: string,
  opts: AuditPacketOptions,
): Promise<AuditPacketReport> {
  return withoutClaimedTrust(await verifyAuditPacketReport(target, opts));
}

async function verifyAuditPacketReport(
  target: string,
  opts: AuditPacketOptions,
): Promise<AuditPacketReport> {
  const { packetPath, baseDir } = resolvePacketPath(target);
  const rawPacket = readVerifierBytes(packetPath);
  const report = reportFromPacket(packetPath);

  if (opts.expectSha256 !== "") {
    const got = sha256Hex(rawPacket);
    const want = opts.expectSha256.trim().toLowerCase();
    if (got !== want) {
      pushError(report, `packet sha256 mismatch: got ${got}, want ${want}`);
      return report;
    }
  }

  let packet: AuditPacket;
  try {
    const packetText = decodeUTF8(rawPacket, "packet json");
    // Reject duplicate object keys before parsing, matching the Go verifier and
    // the receipt path. Last-wins parsing would otherwise let this verifier
    // accept a packet the Go verifier rejects, resolving the duplicate to the
    // attacker's second value.
    rejectDuplicateKeys(packetText);
    packet = JSON.parse(packetText) as AuditPacket;
  } catch (err) {
    pushError(report, `packet json: ${(err as Error).message}`);
    return report;
  }
  Object.assign(report, reportFromPacket(packetPath, packet));
  if (opts.offline) {
    report.verdict = "";
    report.trusted = false;
  }

  const schemaErrors = validateAuditPacket(packet);
  if (schemaErrors.length > 0) {
    report.schema_check = "fail";
    for (const err of schemaErrors) pushError(report, `schema: ${err}`);
    return report;
  }
  report.schema_check = "pass";

  if (opts.offline) {
    report.status = "TRUST UNVERIFIED";
    report.lifecycle_assessment_reason = "offline mode skips chain re-verification";
    report.verdict = "schema_checked_trust_unverified";
    report.trusted = false;
    report.valid = false;
    pushError(report, "schema checked, trust unverified: chain and signer were not verified");
    return report;
  }

  let receipts: Receipt[];
  let chain: ChainResult;
  let otherChainError: string | undefined;
  let evidenceLines: ReturnType<typeof readEntryLines>;
  let typed: ReturnType<typeof extractTypedFromEntries>;
  try {
    const evidencePath = resolveArtifactPath(baseDir, packet.artifacts?.evidence ?? "");
    evidenceLines = readEntryLines(evidencePath);
    typed = extractTypedFromEntries(evidenceLines.map((line) => line.entry));
    receipts = selectReceiptChain(typed);
    const listed = (opts.signerKeys ?? []).filter((key) => key.trim() !== "");
    let keyInput = listed.length > 0 ? "" : opts.signerKey;
    if (listed.length === 0 && keyInput.trim() === "") {
      const packetKey = packet.verifier?.signer_key ?? "";
      if (opts.expectSha256.trim() !== "" || opts.noTrustRequired) {
        keyInput = packetKey;
      } else if (
        packet.verifier?.verdict === "self_consistent_only" &&
        opts.allowSelfConsistentOnly
      ) {
        keyInput = packetKey;
      } else {
        throw new Error("trusted Audit Packet verification requires --key or --expect-sha256");
      }
    }
    const keyHex =
      listed.length > 0
        ? listed.map((key) => resolveSignerKey(key)).join(",")
        : resolveSignerKey(keyInput);
    const primaryKey = typed.action.length === 0 ? evidenceChainKey(keyHex, receipts) : keyHex;
    chain = await verifyChain(receipts, primaryKey, {
      allowUnpinned: opts.allowSelfConsistentOnly,
    });
    // The evidence file of a current run holds an ActionReceipt v1 chain and
    // an EvidenceReceipt v2 chain, each signed on its own. The packet's counts
    // and root describe the first; the second must verify too, or a forged
    // decision record in it would sit behind a trusted verdict.
    if (typed.action.length > 0 && typed.evidence.length > 0) {
      const other = await verifyChain(typed.evidence, evidenceChainKey(keyHex, typed.evidence), {
        allowUnpinned: opts.allowSelfConsistentOnly,
      });
      if (!other.valid) {
        otherChainError = `evidence receipt chain: ${other.error ?? "verification failed"}`;
      }
    }
  } catch (err) {
    report.chain_check = "fail";
    report.status = (err as Error).message.includes("requires --key")
      ? "TRUST UNVERIFIED"
      : "CHAIN BROKEN";
    pushError(report, `chain: ${(err as Error).message}`);
    return report;
  }
  if (otherChainError !== undefined) {
    chain = { ...chain, valid: false, error: otherChainError };
  }
  report.chain_check = chain.valid ? "pass" : "fail";
  if (!chain.valid) pushError(report, `chain: ${chain.error ?? "verification failed"}`);
  const lifecycle = analyzeLifecycle(receipts, chain);
  report.lifecycle_status = lifecycle.status;
  report.lifecycle_reason = lifecycle.reason;
  report.lifecycle_assessment = "assessed";
  delete report.lifecycle_assessment_reason;
  if (chain.valid)
    report.summary = { receipt_count: receipts.length, totals: computeTotals(receipts) };

  const crossErrors = crossCheck(packet, chain, receipts);
  if (crossErrors.length > 0) {
    report.cross_check = "fail";
    report.status = "CHAIN BROKEN";
    for (const err of crossErrors) pushError(report, `cross-check: ${err}`);
    return report;
  }
  report.cross_check = "pass";
  const trusted = chain.valid && lifecycle.status !== "BROKEN" && trustVerdict(packet, opts);
  const actionEndProven = chain.valid && closeEndsChain(receipts);
  let v2EndProof = true;
  if (chain.valid && typed.evidence.length > 0) {
    try {
      v2EndProof = await verifyV2RecorderEnd(evidenceLines, typed.action, chain);
    } catch (err) {
      report.chain_check = "fail";
      chain = {
        ...chain,
        valid: false,
        error: `whole-recorder endpoint: ${(err as Error).message}`,
      };
      pushError(report, `chain: ${chain.error}`);
      v2EndProof = false;
    }
  }
  const endProven = actionEndProven && v2EndProof;
  report.integrity = chain.valid ? "valid" : "invalid";
  report.end_proof = { proven: endProven, evidence: endProven ? ["session_close"] : [] };
  report.scope = "audit_packet";
  report.status =
    !chain.valid || lifecycle.status === "BROKEN"
      ? "CHAIN BROKEN"
      : !trusted
        ? "TRUST UNVERIFIED"
        : !endProven
          ? "VALID PREFIX, END UNPROVEN"
          : "CHAIN VALID";
  if (trusted && !endProven) report.verdict = "VALID PREFIX, END UNPROVEN";
  report.valid = trusted && endProven && chain.valid;
  report.trusted = report.trusted && report.valid && !opts.noTrustRequired;
  if (lifecycle.status === "BROKEN") pushError(report, `lifecycle: ${lifecycle.reason}`);
  if (!report.valid) pushError(report, "packet not trusted");
  return report;
}
