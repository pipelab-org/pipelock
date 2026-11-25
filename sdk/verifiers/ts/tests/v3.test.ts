// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import test from "node:test";
import { canonicalV3, claimsV3Input, verifyV3Paths } from "../src/index.js";
import { findPackageRoot } from "./paths.js";
import { readV3Fixture, resignV3Fixture } from "./v3-fixtures.js";
import { limits } from "../src/v3/wire.js";

const root = findPackageRoot(import.meta.url);
const corpus = resolve(root, "../../conformance/testdata/v3");
const cli = resolve(root, "dist/src/cli.js");

interface Request {
  inputs: string[];
  keys: string[];
  directory?: boolean;
  legacy?: boolean;
  format?: "v3";
  allow_prefix?: boolean;
  allow_unpinned?: boolean;
  expect_lineage?: string;
  accept_discontinuities?: string[];
}

test("shared v3 projections, legacy detection, and full-document order determinism", async (t) => {
  let matched = 0;
  let ordered = 0;
  let full = 0;
  let legacy = 0;
  for (const vector of readdirSync(corpus).sort()) {
    const dir = join(corpus, vector);
    if (!existsSync(join(dir, "request.json"))) continue;
    const request: Request = JSON.parse(readFileSync(join(dir, "request.json"), "utf8"));
    await t.test(vector, async () => {
      const paths = request.inputs.map((name) => join(dir, name));
      if (request.legacy) {
        assert.equal(claimsV3Input(paths[0]), false);
        legacy++;
        return;
      }
      const options = {
        keys: request.keys,
        directory: request.directory,
        explicitV3: request.format === "v3",
        allowPrefix: request.allow_prefix,
        allowUnpinned: request.allow_unpinned,
        expectLineage: request.expect_lineage,
        acceptDiscontinuities: request.accept_discontinuities,
      };
      const compare = async (orderedPaths: string[], reverse = false) => {
        if (!request.directory) return verifyV3Paths(orderedPaths, options);
        const scratch = mkdtempSync(join(tmpdir(), "ts-v3-corpus-"));
        try {
          const names = reverse ? [...request.inputs].reverse() : request.inputs;
          for (const name of names) {
            const target = join(scratch, name);
            mkdirSync(dirname(target), { recursive: true });
            copyFileSync(join(dir, name), target);
          }
          return await verifyV3Paths([scratch], options);
        } finally {
          rmSync(scratch, { recursive: true });
        }
      };
      const { result, projection } = await compare(paths);
      if (paths.length > 1) {
        const reverse = await compare([...paths].reverse(), true);
        assert.equal(canonicalV3(reverse.result), canonicalV3(result));
        ordered++;
      }
      const projected = canonicalV3(projection) + "\n";
      if (canonicalV3(result) + "\n" === readFileSync(join(dir, "expect.json"), "utf8")) full++;
      assert.equal(projected, readFileSync(join(dir, "projection.json"), "utf8"));
      matched++;
    });
  }
  t.diagnostic(
    `projections ${matched}, same full documents as Go ${full}, order checks ${ordered}, legacy ${legacy}`,
  );
});

function invoke(...args: string[]) {
  return spawnSync(process.execPath, [cli, "v3", ...args], { encoding: "utf8" });
}

test("v3 CLI emits canonical JSON and maps proof and usage exits", () => {
  for (const name of ["g01-bom", "g01-empty-input"]) {
    const dir = join(corpus, name);
    const fixture: Request = JSON.parse(readFileSync(join(dir, "request.json"), "utf8"));
    for (const output of ["projection", "result"] as const) {
      const command = invoke(
        "--output",
        output,
        ...fixture.keys.flatMap((key) => ["--key", key]),
        ...fixture.inputs.map((file) => join(dir, file)),
      );
      const bytes = readFileSync(
        join(dir, output === "projection" ? "projection.json" : "expect.json"),
        "utf8",
      );
      assert.equal(command.stdout, bytes);
      assert.equal(command.status, JSON.parse(bytes).exit_code);
      assert.equal(command.stderr, "");
    }
  }
  for (const args of [
    ["--unknown"],
    ["--key"],
    ["--key", "a".repeat(63)],
    ["--key", "A".repeat(64)],
    ["--accept-discontinuity", "not-a-digest"],
    ["--allow-partial-history", "not-a-stream"],
    ["--expect-lineage", "not-a-lineage"],
    ["--expect-head", "not-a-head"],
    ["--expect-seq", "not-a-seq"],
    ["--output", "other"],
    ["--format", "other"],
    ["--format", "v3"],
    ["--format", "v3", corpus],
    ["--claims"],
    ["--claims", "--output", "result", corpus],
    ["--claims", join(corpus, "missing")],
    [join(corpus, "missing")],
  ]) {
    const command = invoke(...args);
    assert.equal(command.status, 2, JSON.stringify(args));
    assert.equal(command.stdout, "");
    assert.match(command.stderr, /^[^\n]+\n$/u);
  }
  const damaged = resolve(
    corpus,
    "g01-bom",
    "11111111111111111111111111111111-0000000000000000.receipt-v3.jsonl",
  );
  const claimed = invoke("--claims", damaged);
  assert.equal(claimed.status, 0);
  assert.equal(claimed.stdout, "true\n");
  assert.equal(claimed.stderr, "");
});

test("v3 CLI endpoint pins distinguish valid, invalid, and open histories", () => {
  const dir = join(corpus, "g04-open-end");
  const request: Request = JSON.parse(readFileSync(join(dir, "request.json"), "utf8"));
  const expected = JSON.parse(readFileSync(join(dir, "expect.json"), "utf8"));
  const { stream, tip } = expected.histories[0].streams[0];
  const keys = request.keys.flatMap((key) => ["--key", key]);
  const path = join(dir, request.inputs[0]);

  assert.equal(invoke(...keys, path).status, 3);
  assert.equal(invoke(...keys, "--allow-prefix", path).status, 0);
  const proof = invoke(
    ...keys,
    "--expect-head",
    `${stream}:${tip.seq}:${tip.record}`,
    "--expect-seq",
    `${stream}:${tip.seq}`,
    path,
  );
  assert.equal(proof.status, 0);
  assert.equal(JSON.parse(proof.stdout).verdict, "VALID");
  const mismatch = invoke(...keys, "--expect-seq", `${stream}:${tip.seq + 1}`, path);
  assert.equal(mismatch.status, 1);
  assert.ok(
    JSON.parse(mismatch.stdout).findings.some(
      (f: { code: string }) => f.code === "EXPECTATION_NOT_MET",
    ),
  );
  assert.equal(invoke(...keys, "--expect-head", `${stream}:01:${tip.record}`, path).status, 2);
  assert.match(invoke("--help").stdout, /^Usage: pipelock-verifier-ts v3/u);
});

test("mixed v3 input verifies legacy g1 links and rotations", async (t) => {
  const fixture = join(corpus, "g01-valid-line");
  const request: Request = JSON.parse(readFileSync(join(fixture, "request.json"), "utf8"));
  const shared = resolve(corpus, "..");
  const keyFile = JSON.parse(readFileSync(join(shared, "test-key.json"), "utf8")) as {
    public_key_hex: string;
    rotated_public_key_hex: string;
    rotated_twice_public_key_hex: string;
  };
  const opts = {
    directory: true,
    keys: [
      ...request.keys,
      keyFile.public_key_hex,
      keyFile.rotated_public_key_hex,
      keyFile.rotated_twice_public_key_hex,
    ],
  };
  const dir = mkdtempSync(join(tmpdir(), "ts-v3-mixed-g1-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const v3 = join(dir, request.inputs[0]);
  copyFileSync(join(fixture, request.inputs[0]), v3);
  for (const [name, valid] of [
    ["g1-valid-chain", true],
    ["g1-restart-chain", true],
    ["g1-rotated-close-count-valid", true],
    ["g1-rotated-twice-valid", true],
    ["g1-ext-chain", true],
    ["g1-ext-tampered-invalid", false],
    ["g1-rotated-same-key-invalid", false],
    ["g1-broken-genesis", false],
  ] as const) {
    const legacy = join(dir, "evidence-conformance-session-0.jsonl");
    copyFileSync(join(shared, name + ".jsonl"), legacy);
    const { result, projection } = await verifyV3Paths([dir], opts);
    assert.equal(!result.findings.some((f) => f.code === "LEGACY_INVALID"), valid, name);
    assert.equal(result.verdict, "INVALID", name);
    if (valid) assert.deepEqual(projection.finding_codes, ["LEGACY_CHAIN_UNLISTED"], name);
  }
  const plain = join(shared, "g1-valid-chain.jsonl");
  await assert.rejects(verifyV3Paths([v3, plain], { keys: opts.keys }), /require directory scope/u);
  await assert.rejects(
    verifyV3Paths([plain], { keys: opts.keys }),
    /requires the legacy verification path/u,
  );
});

function fixture(name: string): { path: string; keys: string[] } {
  const dir = join(corpus, name);
  const request: Request = JSON.parse(readFileSync(join(dir, "request.json"), "utf8"));
  return { path: join(dir, request.inputs[0]), keys: request.keys };
}

test("v3 appraises legal pieces after a missing predecessor", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "ts-v3-partial-"));
  t.after(() => rmSync(dir, { recursive: true }));
  const stream = "1".repeat(32);
  const path = join(dir, stream + "-0000000000000000.receipt-v3.jsonl");
  const previous = readV3Fixture(fixture("g04-predecessor-absent").path)[0].payload.body
    .previous as {
    stream: string;
  };
  const pin = { ...previous, stream: "4".repeat(32) };
  for (const [name, at] of [
    ["g05-completed", 2],
    ["g05-completed", 3],
    ["g05-completed", 4],
    ["g05-correcting-block", 3],
    ["g05-retry-after-refusal", 1],
  ] as const) {
    const source = fixture(name);
    const records = readV3Fixture(source.path);
    const close = records.at(-1)!;
    const action = records[at];
    if (action.payload.body.attempt) action.payload.body.attempt = limits.integer;
    delete records[0].payload.body.legacy_cutover;
    records[0].payload.body.previous = pin;
    writeFileSync(path, resignV3Fixture([records[0], action, close]));
    const { result } = await verifyV3Paths([path], {
      keys: source.keys,
      allowPartialHistories: [stream],
    });
    assert.equal(result.verdict, "VALID, GAPS ACCEPTED", `${name} ${at}: ${canonicalV3(result)}`);
    assert.deepEqual(result.counts, { scope: "not_appraised" });
  }
});

test("v3 still verifies evidence when its decision index fills", async () => {
  const { path, keys } = fixture("g05-completed");
  const limit = limits.decisions;
  try {
    limits.decisions = 0;
    const { result, projection } = await verifyV3Paths([path], { keys });
    assert.equal(result.verdict, "INCOMPLETE");
    assert.deepEqual(projection.finding_codes, ["DECISION_INDEX_FULL"]);
    assert.equal(result.histories[0].streams[0].end, "closed");
    assert.ok(result.limits.includes("L-DECISION-INDEX"));
    assert.deepEqual(result.counts, { scope: "not_appraised" });
  } finally {
    limits.decisions = limit;
  }
});

test("v3 cutover recognizes a bare legacy EvidenceReceipt v2 session", async (t) => {
  const input = fixture("g01-valid-line");
  const legacy = fixture("g10-valid-transformed-intent");
  const dir = mkdtempSync(join(tmpdir(), "ts-v3-bare-v2-"));
  t.after(() => rmSync(dir, { recursive: true }));
  copyFileSync(input.path, join(dir, basename(input.path)));
  const raw = readFileSync(legacy.path, "utf8").trimEnd();
  writeFileSync(
    join(dir, "evidence-legacy-0.jsonl"),
    '{"detail":' + raw + ',"type":"evidence_receipt"}\n',
  );
  const { result, projection } = await verifyV3Paths([dir], {
    directory: true,
    keys: [...input.keys, ...legacy.keys],
  });
  assert.deepEqual(projection.finding_codes, ["LEGACY_CHAIN_UNLISTED"]);
  assert.equal(result.legacy.length, 1);
  assert.equal(result.legacy[0].format, "evidence_v2");
  assert.equal(result.legacy[0].verdict, "VALID PREFIX, END UNPROVEN");
});
