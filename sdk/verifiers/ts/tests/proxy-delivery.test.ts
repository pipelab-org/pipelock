// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { verifyReceipt } from "../src/signing.js";
import type { Receipt } from "../src/types.js";

test("proxy delivery observations retain existing verdict and phase fields", async () => {
  const root = "../../conformance/testdata/";
  const key = JSON.parse(readFileSync(root + "test-key.json", "utf8")) as {
    public_key_hex: string;
  };
  const vectors = JSON.parse(readFileSync(root + "proxy-delivery-outcomes.json", "utf8")) as {
    name: string;
    receipt: Receipt;
  }[];
  assert.equal(vectors.length, 6);
  for (const vector of vectors) {
    await verifyReceipt(vector.receipt, key.public_key_hex);
    const changed = structuredClone(vector.receipt);
    assert.ok(changed.action_record);
    changed.action_record.pattern = (changed.action_record.pattern ?? "") + " tampered";
    await assert.rejects(verifyReceipt(changed, key.public_key_hex), /signature/iu, vector.name);
  }
});
