// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import test from "node:test";
import { runReceipt } from "../src/receipt.js";

test("signed field names match shared parity fixture", async () => {
  const dir = "../../conformance/testdata";
  const key = JSON.parse(readFileSync(`${dir}/test-key.json`, "utf8")) as {
    public_key_hex: string;
  };
  const fixture = JSON.parse(readFileSync(`${dir}/signed-field-names.json`, "utf8")) as {
    cases: { file: string; valid: boolean; error?: string }[];
  };
  for (const entry of fixture.cases) {
    // A missing fixture must fail here, not read as an expected rejection.
    readFileSync(`${dir}/${entry.file}`);
    const report = await runReceipt(`${dir}/${entry.file}`, key.public_key_hex);
    assert.equal(report.valid, entry.valid, `${entry.file}: ${report.error ?? "no error"}`);
    if (!entry.valid) {
      assert.ok(entry.error, `${entry.file}: negative case names no expected error`);
      assert.ok(
        report.error?.includes(entry.error),
        `${entry.file}: error ${JSON.stringify(report.error)} lacks ${JSON.stringify(entry.error)}`,
      );
    }
  }
});
