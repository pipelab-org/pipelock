// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt } from "../src/signing.js";
import type { Receipt } from "../src/types.js";

// Fixed here, not read back from the fixture, so a re-signed fixture with
// changed outcome fields fails.
const EXPECTED: [string, string, string, string][] = [
  ["legacy completion", "outcome", "allow", "status=200 bytes=16 reason=complete"],
  ["admission without outcome", "intent", "allow", ""],
  [
    "delivered representation",
    "outcome",
    "allow",
    "status=200 bytes=16 reason=complete delivered_bytes=130",
  ],
  [
    "upstream failure",
    "outcome",
    "warn",
    "status=502 bytes=unknown reason=fetch_failed delivered_bytes=120",
  ],
  [
    "partial delivery",
    "outcome",
    "warn",
    "status=200 bytes=16 reason=delivery_error delivered_bytes=7",
  ],
  [
    "denied response",
    "outcome",
    "block",
    "status=403 bytes=unknown reason=compressed_response delivered_bytes=7",
  ],
];

test("proxy delivery observations retain existing verdict and phase fields", async () => {
  const root = "../../conformance/testdata/";
  const key = JSON.parse(readFileSync(root + "test-key.json", "utf8")) as {
    public_key_hex: string;
  };
  const vectors = JSON.parse(readFileSync(root + "proxy-delivery-outcomes.json", "utf8")) as {
    name: string;
    receipt: Receipt;
  }[];
  assert.equal(vectors.length, EXPECTED.length);
  for (const [index, vector] of vectors.entries()) {
    const record = vector.receipt.action_record;
    assert.ok(record);
    assert.deepEqual(
      [vector.name, record.decision_phase ?? "", record.verdict, record.pattern ?? ""],
      EXPECTED[index],
    );
    await verifyReceipt(vector.receipt, key.public_key_hex);
    const changed = structuredClone(vector.receipt);
    assert.ok(changed.action_record);
    changed.action_record.pattern = (changed.action_record.pattern ?? "") + " tampered";
    await assert.rejects(verifyReceipt(changed, key.public_key_hex), /signature/iu, vector.name);
  }
});
