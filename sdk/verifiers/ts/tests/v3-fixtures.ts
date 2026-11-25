// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalJSON } from "../src/v3/result.js";

interface Envelope {
  payloadType: string;
  signatures: { keyid: string; sig: string }[];
  payload: { body: Record<string, unknown>; seq: number; prev: string; kind: string };
}

export const fixtureHash = (bytes: Buffer | string): string =>
  createHash("sha256").update(bytes).digest("hex");

export function readV3Fixture(file: string): Envelope[] {
  return readFileSync(file, "utf8")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
}

// Match the public Go corpus's deterministic test signer.
export function resignV3Fixture(records: Envelope[]): string {
  const seed = Buffer.from(fixtureHash("receipt v3 conformance first"), "hex");
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  let previous = "";
  return records
    .map(({ payloadType, payload, signatures }, seq) => {
      payload.seq = seq;
      if (seq) payload.prev = previous;
      if (payload.kind === "stream_close") payload.body.records = seq + 1;
      const raw = canonicalJSON(payload);
      const message = Buffer.from(
        `DSSEv1 ${payloadType.length} ${payloadType} ${Buffer.byteLength(raw)} ${raw}`,
      );
      previous = "sha256:" + fixtureHash(message);
      const signed = [
        { keyid: signatures[0].keyid, sig: sign(null, message, key).toString("base64") },
      ];
      return (
        JSON.stringify({ payloadType, signatures: signed }).slice(0, -1) +
        ',"payload":' +
        raw +
        "}\n"
      );
    })
    .join("");
}
