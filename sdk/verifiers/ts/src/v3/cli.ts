// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { closeSync, statSync } from "node:fs";
import { parseArgs } from "node:util";
import { claimsV3Input, openEvidence, parseHead, parseSequence } from "./input.js";
import { canonicalV3 } from "./result.js";
import { verifyV3Paths } from "./verify.js";

const usage =
  "Usage: pipelock-verifier-ts v3 [--key HEX]... [--allow-unpinned] [--allow-prefix] " +
  "[--accept-discontinuity RECORD_ID]... [--allow-partial-history STREAM_ID]... " +
  "[--expect-lineage ID] [--expect-head STREAM:SEQ:sha256:HEX]... [--expect-seq STREAM:SEQ]... " +
  "[--format v3] [--output result|projection] PATH... | v3 --claims PATH";

export async function runV3Command(args: string[]): Promise<number> {
  try {
    if (args.length === 1 && args[0] === "--help") {
      process.stdout.write(usage + "\n");
      return 0;
    }
    const { values, positionals, tokens } = parseArgs({
      args,
      allowPositionals: true,
      tokens: true,
      options: {
        key: { type: "string", multiple: true },
        "allow-unpinned": { type: "boolean" },
        "allow-prefix": { type: "boolean" },
        "accept-discontinuity": { type: "string", multiple: true },
        "allow-partial-history": { type: "string", multiple: true },
        "expect-lineage": { type: "string" },
        "expect-head": { type: "string", multiple: true },
        "expect-seq": { type: "string", multiple: true },
        format: { type: "string" },
        output: { type: "string" },
        claims: { type: "boolean" },
      },
    });

    if (values.claims) {
      if (
        positionals.length !== 1 ||
        tokens.filter((token) => token.kind === "option").length !== 1
      )
        throw new Error("--claims requires exactly one path and no other flags");
      closeSync(openEvidence(positionals[0]));
      process.stdout.write(String(claimsV3Input(positionals[0])) + "\n");
      return 0;
    }

    if (values.format !== undefined && values.format !== "v3")
      throw new Error("--format must be v3");
    const output = values.output ?? "result";
    if (output !== "result" && output !== "projection")
      throw new Error("--output must be result or projection");
    let directory = false;
    if (positionals.length === 1) directory = statSync(positionals[0]).isDirectory();
    const { result, projection } = await verifyV3Paths(positionals, {
      keys: values.key,
      directory,
      explicitV3: values.format === "v3",
      allowPrefix: values["allow-prefix"],
      allowUnpinned: values["allow-unpinned"],
      expectLineage: values["expect-lineage"],
      expectHeads: values["expect-head"]?.map(parseHead),
      expectSequences: values["expect-seq"]?.map(parseSequence),
      acceptDiscontinuities: values["accept-discontinuity"],
      allowPartialHistories: values["allow-partial-history"],
    });
    process.stdout.write(canonicalV3(output === "projection" ? projection : result) + "\n");
    return result.exit_code;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(message.replace(/[\r\n\u0085\u2028\u2029]+/gu, " ") + "\n");
    return 2;
  }
}
