// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// The `aarp` subcommand, ported from cmd/pipelock-verifier/aarp.go (+ the SVID
// arm from aarp_svid.go). Usage:
//
//   pipelock-verifier-ts aarp PATH --trust TRUST_JSON [--svid SVID_JSON] [--chain] [--json]
//
// --svid attaches an X.509-SVID proof-of-possession appraisal to a single
// envelope (never with --chain); without it the output is the plain envelope
// appraisal, unchanged.
//
// Exit codes: 0 appraised (single) / endpoint-proven or explicitly accepted
// prefix (chain); 1 fatal or broken/untrusted chain; 2 I/O or trust-file error;
// 3 valid chain prefix with unproven end; 64 usage. On fatal with --json the
// verifier prints {"envelope_fatal":true} and exits non-zero; the gate compares
// only the non-zero exit for fatal fixtures.

import { parseArgs } from "node:util";
import { readVerifierBytes } from "../util.js";
import { comparableAppraisal } from "./appraise.js";
import { canonicalize } from "./canonical.js";
import { loadTrustFile, unmarshal, verify, verifyChain } from "./index.js";
import type { Envelope } from "./index.js";
import { appraiseWithSVID, loadSVIDFile } from "./svid.js";
import { GENESIS_PRIOR_HASH, payloadDigest } from "./envelope.js";

// CodedError is anything carrying a numeric exit `code`. Our module errors all do.
interface CodedError {
  code: number;
  message: string;
}

function isCodedError(err: unknown): err is CodedError {
  return (
    typeof err === "object" &&
    err !== null &&
    typeof (err as { code?: unknown }).code === "number" &&
    typeof (err as { message?: unknown }).message === "string"
  );
}

// AARPUsageError marks a usage error (exit 64).
export class AARPUsageError extends Error {
  readonly code = 64;
}

const USAGE =
  "Usage: pipelock-verifier-ts aarp PATH --trust TRUST_JSON [--svid SVID_JSON] [--chain] [--allow-prefix] [--expect-head HASH] [--expect-seq N] [--json]";

// emitFatal prints the envelope-fatal marker (or human text) and returns 1.
function emitFatal(jsonMode: boolean, cause: string): number {
  if (jsonMode) {
    process.stdout.write(`${canonicalize({ envelope_fatal: true })}\n`);
  } else {
    process.stderr.write(`ENVELOPE FATAL: ${cause}\n`);
  }
  return 1;
}

// runAARPChain verifies linkage, trusted signatures, and an independently
// supplied end proof. AARP has no terminal record, so an unpinned stream is a
// valid prefix even when every envelope is authentic.
function runAARPChain(
  data: string,
  opts: ReturnType<typeof loadTrustFile>,
  jsonMode: boolean,
  allowPrefix: boolean,
  expectHead: string,
  expectSeq: string,
): number {
  const lines = data.trim().split("\n");
  const envs: Envelope[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = (lines[i] as string).trim();
    if (line === "") continue;
    let env: Envelope;
    try {
      env = unmarshal(line);
    } catch (err) {
      return emitFatal(
        jsonMode,
        `chain line ${i}: ${isCodedError(err) ? err.message : String(err)}`,
      );
    }
    envs.push(env);
  }

  let linked = verifyChain(envs);
  let signaturesVerified = false;
  let failure = "";
  try {
    signaturesVerified = envs.length > 0 && envs.every((env) => verify(env, opts).assertion_signed);
    if (!linked) throw new Error("chain links are not contiguous");
    const first = envs[0];
    if (
      first?.chain === undefined ||
      first.chain.seq !== "0" ||
      first.chain.prior_hash !== GENESIS_PRIOR_HASH
    ) {
      throw new Error("chain does not start at the genesis link");
    }
    if (!signaturesVerified)
      throw new Error(
        "no signature verified against pinned trust; pass --trust with the signer key",
      );
  } catch (err) {
    failure = isCodedError(err) ? err.message : String(err);
  }

  const evidence: string[] = [];
  if (!failure && (expectHead !== "" || expectSeq !== "")) {
    const last = envs[envs.length - 1];
    if (last === undefined || last.chain === undefined) {
      failure = "empty chain";
    } else if (expectHead !== "" && payloadDigest(last) !== expectHead) {
      failure = "chain tip does not match expected head (tail truncated or different scope)";
    } else if (expectSeq !== "" && BigInt(last.chain.seq) !== BigInt(expectSeq)) {
      failure = `final_seq ${last.chain.seq} does not match expected seq ${expectSeq}`;
    } else {
      if (expectHead !== "") evidence.push("operator_head");
      if (expectSeq !== "") evidence.push("operator_seq");
    }
  }

  const valid = failure === "";
  const report = {
    chain_linked: linked,
    length: envs.length,
    integrity: valid ? "valid" : "invalid",
    end_proof: { proven: evidence.length > 0, evidence },
    scope: "aarp_chain",
    status: !valid
      ? "CHAIN BROKEN"
      : evidence.length > 0
        ? "CHAIN VALID"
        : "VALID PREFIX, END UNPROVEN",
    signatures_verified: signaturesVerified,
    ...(failure === "" ? {} : { error: failure }),
  };
  if (jsonMode) {
    process.stdout.write(`${canonicalize(report)}\n`);
  } else {
    process.stdout.write(`AARP chain: ${envs.length} envelopes\n`);
    process.stdout.write(`  signatures_verified: ${signaturesVerified}\n`);
    process.stdout.write(`  status: ${report.status}\n`);
    if (evidence.length > 0) process.stdout.write(`  end_proof: ${evidence.join(", ")}\n`);
    if (failure !== "") process.stderr.write(`  error: ${failure}\n`);
  }
  if (!valid) return 1;
  return evidence.length > 0 || allowPrefix ? 0 : 3;
}

// runAARPCommand executes the aarp subcommand and returns its process exit code.
export function runAARPCommand(args: string[]): number {
  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        trust: { type: "string", default: "" },
        svid: { type: "string", default: "" },
        json: { type: "boolean", default: false },
        chain: { type: "boolean", default: false },
        "allow-prefix": { type: "boolean", default: false },
        "expect-head": { type: "string", default: "" },
        "expect-seq": { type: "string", default: "" },
      },
    });
  } catch (err) {
    throw new AARPUsageError(`${USAGE}\n${(err as Error).message}`);
  }
  if (parsed.positionals.length !== 1) {
    throw new AARPUsageError(`${USAGE}\naccepts 1 arg, received ${parsed.positionals.length}`);
  }
  const target = parsed.positionals[0] as string;
  const trustPath = parsed.values.trust ?? "";
  const svidPath = parsed.values.svid ?? "";
  const jsonMode = parsed.values.json === true;
  const chainMode = parsed.values.chain === true;
  const allowPrefix = parsed.values["allow-prefix"] === true;
  const expectHead = parsed.values["expect-head"] ?? "";
  const expectSeq = parsed.values["expect-seq"] ?? "";

  // An SVID binding appraises a single envelope; the chain arm verifies stream
  // linkage and never attaches per-envelope SVID claims.
  if (svidPath !== "" && chainMode) {
    throw new AARPUsageError(
      `${USAGE}\n--svid is single-envelope only and cannot combine with --chain`,
    );
  }
  if ((allowPrefix || expectHead !== "" || expectSeq !== "") && !chainMode) {
    throw new AARPUsageError(`${USAGE}\nend-proof flags require --chain`);
  }
  if (expectSeq !== "") {
    if (!/^[0-9]+$/u.test(expectSeq) || BigInt(expectSeq) > 0xffff_ffff_ffff_ffffn) {
      throw new AARPUsageError(`${USAGE}\n--expect-seq requires an unsigned integer`);
    }
  }

  // Trust-file and envelope read errors are exit-2 (I/O), propagated as coded
  // errors so the top-level handler maps them.
  const opts = loadTrustFile(trustPath);

  let data: string;
  try {
    data = readVerifierBytes(target).toString("utf8");
  } catch (err) {
    const e = new Error(`read envelope: ${(err as Error).message}`) as Error & { code: number };
    e.code = 2;
    throw e;
  }

  if (chainMode) {
    return runAARPChain(data, opts, jsonMode, allowPrefix, expectHead, expectSeq);
  }

  // A malformed --svid sidecar (bad pinned-bundle DER, inverted window, empty
  // domain, unknown field) is an operator-config error (exit 2), propagated as a
  // coded error before any envelope appraisal -- never a fixture verdict.
  const svid = svidPath === "" ? null : loadSVIDFile(svidPath);

  let env: Envelope;
  try {
    env = unmarshal(data);
  } catch (err) {
    return emitFatal(jsonMode, isCodedError(err) ? err.message : String(err));
  }

  let appraisalBytes: string;
  try {
    const ap =
      svid === null ? verify(env, opts) : appraiseWithSVID(env, svid.evidence, opts, svid.opts);
    appraisalBytes = comparableAppraisal(ap);
  } catch (err) {
    return emitFatal(jsonMode, isCodedError(err) ? err.message : String(err));
  }

  if (jsonMode) {
    process.stdout.write(`${appraisalBytes}\n`);
  } else {
    process.stdout.write(`AARP appraisal (${env.profile})\n`);
  }
  return 0;
}
