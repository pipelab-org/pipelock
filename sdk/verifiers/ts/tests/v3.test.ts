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
  renameSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import test from "node:test";
import { canonicalV3, claimsV3Input, verifyV3Paths } from "../src/index.js";
import { findPackageRoot } from "./paths.js";
import { readV3Fixture, resignV3Fixture } from "./v3-fixtures.js";
import { digest, limits } from "../src/v3/wire.js";
import { readInventory } from "../src/v3/cutover.js";
import { claimHold, Decision } from "../src/v3/decision.js";
import { verifyLegacy } from "../src/v3/legacy.js";
import { finding, newResult } from "../src/v3/result.js";
import { Stage } from "../src/v3/store.js";

test("receipt v3 canonical output rejects sparse arrays", () => {
  const document = newResult({}, 0);
  document.findings.length = 2;
  assert.throws(() => canonicalV3(document), /sparse/i);
  document.findings.length = 0;
  assert.deepEqual(JSON.parse(canonicalV3(document)).findings, []);
});

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
      if (vector === "g04-absent-max-write-error-pin") {
        const parent = result.histories[0].streams[0];
        assert.equal(parent.end, "closed");
        assert.deepEqual(parent.tip, parent.last);
        assert.equal(parent.unconfirmed_from, undefined);
      }
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

test("v3 rejects missing or directory inputs even when filename claims v3", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-v3-input-err-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const good = join(dir, "good.jsonl");
  writeFileSync(good, "{}\n");
  const absentV3 = join(dir, "absent.receipt-v3.jsonl");
  const absentV4 = join(dir, "absent.receipt-v4.jsonl");
  const dirV3 = join(dir, "dir.receipt-v3.jsonl");
  mkdirSync(dirV3);

  for (const args of [
    ["--claims", absentV3],
    ["--claims", absentV4],
    ["--claims", dirV3],
    [absentV3],
    [absentV4],
    [good, absentV3],
    [good, absentV4],
    [good, dirV3],
  ]) {
    const command = invoke(...args);
    assert.equal(command.status, 2, JSON.stringify(args));
    assert.equal(command.stdout, "", JSON.stringify(args));
    assert.match(command.stderr, /^[^\n]+\n$/u, JSON.stringify(args));
  }
});

test("v3 claims require the exact profile filename suffix", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-v3-suffix-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "other.receipt-v3.jsonl\n");
  writeFileSync(path, "{}\n");
  assert.equal(claimsV3Input(path), false);
});

test("v3 canonical results reject unpaired surrogates", () => {
  const result = newResult({}, 0);
  for (const invalid of ["\ud800", "\udc00"]) {
    assert.throws(() => canonicalV3({ ...result, [invalid]: 1 }), TypeError);
    assert.throws(() => canonicalV3({ ...result, verdict: invalid } as typeof result), TypeError);
  }
  assert.match(
    canonicalV3({ ...result, ["\ud83d\ude00"]: "\ud83d\ude00" } as typeof result),
    /"😀":"😀"/u,
  );
});

test("v3 canonical results reject non-finite numbers", () => {
  for (const invalid of [NaN, Infinity, -Infinity]) {
    assert.throws(() => canonicalV3(newResult({}, invalid)), TypeError);
  }
  assert.match(canonicalV3(newResult({}, 0)), /"ignored_files":0/u);
});

test("v3 canonical results omit undefined optional members", async () => {
  const { path, keys } = fixture("g05-completed");
  const { result } = await verifyV3Paths([path], { keys });
  const expected = canonicalV3(result);
  const stream = result.histories[0].streams[0];
  assert.equal(stream.previous, undefined);
  stream.previous = undefined;
  assert.equal(canonicalV3(result), expected);
});

test("v3 verification holds the original option values across awaits", async () => {
  const { path, keys } = fixture("g05-completed");
  const { result } = await verifyV3Paths([path], { keys });
  const stream = result.histories[0].streams[0];
  const head = { stream: stream.stream, ...stream.tip! };
  const opts = { keys, expectHeads: [head], allowPrefix: false };
  const expected = await verifyV3Paths([path], opts);
  const pending = verifyV3Paths([path], opts);
  opts.allowPrefix = true;
  head.record = "sha256:" + "0".repeat(64);
  opts.expectHeads.push({ ...head, stream: "0".repeat(32) });
  assert.deepEqual(await pending, expected);
});

test("v3 verification holds the original prefix policy across awaits", async () => {
  const { path, keys } = fixture("g04-open-end");
  const opts = { keys, allowPrefix: false };
  const pending = verifyV3Paths([path], opts);
  opts.allowPrefix = true;
  assert.equal((await pending).result.exit_code, 3);
  assert.equal((await verifyV3Paths([path], opts)).result.exit_code, 0);
});

test("v3 discards provisional groups when the inventory fails", async () => {
  const id = "a".repeat(32);
  const opts = { directory: true };
  const result = newResult(opts, 0);
  const store = new Stage();
  try {
    const presented = await verifyLegacy(
      {
        opts,
        result,
        store,
        used: new Set(),
        streams: new Map(),
        histories: new Map(),
        add: (code, loc = "") => result.findings.push(finding(code, loc)),
      },
      [`example/receipt-group-${id}-open.json`],
      async (_dir, _keys, visit) => {
        visit?.({
          group_id: id,
          verdict: "GROUP_VALID",
          shard_count: 1,
          close_manifest_sha256: "b".repeat(64),
        });
        return {
          groups: 1,
          incomplete: 0,
          invalid: 0,
          unavailable: true,
          error: "inventory changed",
        };
      },
    );
    assert.equal(presented.size, 0);
    assert.deepEqual(result.legacy, [
      { chain: "", class: "failure", format: "receipt_group", verdict: "GROUP_INCOMPLETE" },
    ]);
  } finally {
    store.close();
  }
});

test("v3 does not exclude a replaced bare wrapper from restart continuity", async (t) => {
  const vector = join(corpus, "g09-legacy-bare-evidence-under-run-name");
  const request: Request = JSON.parse(readFileSync(join(vector, "request.json"), "utf8"));
  const dir = mkdtempSync(join(tmpdir(), "pipelock-v3-bare-"));
  const fs = createRequire(import.meta.url)("node:fs") as typeof import("node:fs");
  const original = fs.readdirSync;
  try {
    for (const name of request.inputs) copyFileSync(join(vector, name), join(dir, name));
    const options = { keys: request.keys, directory: true };
    const codes = async (): Promise<string[]> =>
      (await verifyV3Paths([dir], options)).result.findings.map((f) => f.code);
    assert.deepEqual(await codes(), ["LEGACY_CHAIN_UNLISTED"], "control");
    const wrapper = join(dir, "evidence-example.run.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0.jsonl");
    let replaced = false;
    t.mock.method(fs, "readdirSync", (...args: unknown[]) => {
      // The restart check lists the directory under its history snapshot.
      if (!replaced && new Error().stack?.includes("withBaseHistorySnapshot")) {
        replaced = true;
        writeFileSync(wrapper + ".new", "not a recorder entry");
        renameSync(wrapper + ".new", wrapper);
      }
      return Reflect.apply(original, fs, args);
    });
    syncBuiltinESMExports();
    const changed = await codes();
    assert.ok(replaced, "the continuity check never listed the directory");
    assert.ok(changed.includes("LEGACY_INVALID"), changed.join());
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("v3 binds bare wrapper reads to the discovered shards", async (t) => {
  const vector = join(corpus, "g09-legacy-bare-evidence-under-run-name");
  const request: Request = JSON.parse(readFileSync(join(vector, "request.json"), "utf8"));
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-bare-shard-set-"));
  const fs = createRequire(import.meta.url)("node:fs") as typeof import("node:fs");
  const list = fs.readdirSync;
  try {
    for (const name of request.inputs) copyFileSync(join(vector, name), join(dir, name));
    const wrapper = request.inputs.find((name) => name.startsWith("evidence-"))!;
    const extra = join(dir, wrapper.replace(/-0\.jsonl$/u, "-8.jsonl"));
    let added = false;
    t.mock.method(fs, "readdirSync", (...args: unknown[]) => {
      if (!added && new Error().stack?.includes("readBareEvidence")) {
        added = true;
        writeFileSync(extra, "");
      } else if (
        added &&
        existsSync(extra) &&
        new Error().stack?.includes("withBaseHistorySnapshot")
      ) {
        rmSync(extra);
      }
      return Reflect.apply(list, fs, args);
    });
    syncBuiltinESMExports();
    const options = { keys: request.keys, directory: true };
    const { result } = await verifyV3Paths([dir], options);
    assert.ok(added);
    assert.ok(result.findings.some((finding) => finding.code === "LEGACY_INVALID"));
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("v3 does not settle bare wrappers without file identity", async (t) => {
  const vector = join(corpus, "g09-legacy-bare-evidence-under-run-name");
  const request: Request = JSON.parse(readFileSync(join(vector, "request.json"), "utf8"));
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-bare-no-identity-"));
  const fs = createRequire(import.meta.url)("node:fs") as typeof import("node:fs");
  const lstat = fs.lstatSync;
  try {
    for (const name of request.inputs) copyFileSync(join(vector, name), join(dir, name));
    t.mock.method(fs, "lstatSync", (...args: unknown[]) => {
      const info = Reflect.apply(lstat, fs, args);
      if (new Error().stack?.includes("fileStamp")) info.ino = 0n;
      return info;
    });
    syncBuiltinESMExports();
    const { result } = await verifyV3Paths([dir], { keys: request.keys, directory: true });
    assert.ok(result.legacy.some((row) => row.verdict === "RESTART CONTINUITY INCOMPLETE"));
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("v3 bare wrapper indexing and stamp checks scale with shard count", async (t) => {
  const vector = join(corpus, "g09-legacy-bare-evidence-under-run-name");
  const request: Request = JSON.parse(readFileSync(join(vector, "request.json"), "utf8"));
  const wrapper = request.inputs.find((name) => name.startsWith("evidence-"))!;
  const dir = mkdtempSync(join(tmpdir(), "pipelock-ts-bare-stamp-count-"));
  const fs = createRequire(import.meta.url)("node:fs") as typeof import("node:fs");
  const lstat = fs.lstatSync;
  const opts = { keys: request.keys, directory: true };
  const result = newResult(opts, 0);
  const store = new Stage();
  try {
    const paths = Array.from({ length: 12 }, (_, i) =>
      join(dir, wrapper.replace("evidence-example.", `evidence-base${i}.`)),
    );
    for (const file of paths) copyFileSync(join(vector, wrapper), file);
    let pathReads = 0;
    const observed = new Proxy(paths, {
      get(target, property, receiver) {
        if (typeof property === "string" && /^\d+$/u.test(property)) pathReads++;
        return Reflect.get(target, property, receiver);
      },
    });
    let stats = 0;
    t.mock.method(fs, "lstatSync", (...args: unknown[]) => {
      if (new Error().stack?.includes("fileStamp")) stats++;
      return Reflect.apply(lstat, fs, args);
    });
    syncBuiltinESMExports();
    await verifyLegacy(
      {
        opts,
        result,
        store,
        add: (code: string) => result.findings.push(finding(code, "")),
      } as never,
      observed,
      async () => ({ groups: 0, incomplete: 0, invalid: 0, unavailable: false }),
    );
    assert.deepEqual(
      [pathReads <= paths.length * 2, stats <= paths.length * 4],
      [true, true],
      `${pathReads} discovery path reads, ${stats} wrapper stamp reads`,
    );
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("v3 pending hold replay retains only its identity", () => {
  const hold = "hold-".repeat(16384);
  const action = {
    action_id: "test",
    action_type: "test",
    phase: "hold",
    verdict: "defer",
    effect_boundary: "approval_prompt",
    effect_relation: "before",
    transport: "",
    method: "",
    target: "",
    hold: { id: hold },
  };
  const matching = { ...action, phase: "resolution", verdict: "allow" };
  const different = { ...matching, hold: { id: "other" } };
  const pending = new Decision();
  assert.ok(pending.advance(action, false));
  assert.ok(!Object.values(pending).includes(hold));
  assert.ok(!pending.advance(different, false));
  assert.ok(pending.advance(matching, false));
  const inferred = new Decision();
  assert.ok(inferred.advance(matching, true));
  assert.deepEqual(inferred, pending);
});

test("v3 hold ownership shares the decision index budget", () => {
  const holds = new Map<string, string>();
  const long = "h".repeat(1 << 16);
  assert.equal(claimHold(holds, long, "first", 1), undefined);
  assert.equal(claimHold(holds, long, "second", 1), "conflict");
  assert.equal(claimHold(holds, long, "first", 1), undefined);
  assert.equal(claimHold(holds, "other", "first", 1), "full");
  assert.equal(holds.size, 1);
  assert.ok([...holds.keys()].every((key) => key.length < 100));
});

test("v3 validates an unreferenced inventory without retaining its rows", () => {
  const dir = mkdtempSync(join(tmpdir(), "pipelock-v3-inventory-"));
  try {
    const row = (chain: string): string =>
      `{"chain":"${chain}","format":"evidence_v2","record":"${digest(Buffer.from("r"))}","seq":0}`;
    const [low, high] = [digest(Buffer.from("a")), digest(Buffer.from("b"))].sort();
    const write = (name: string, rows: string[]): { path: string; inventory: string } => {
      const raw = `{"chains":[${rows.join(",")}],"v":1}`;
      const path = join(dir, name);
      writeFileSync(path, raw);
      return { path, inventory: digest(Buffer.from(raw)) };
    };
    const ordered = write("ordered.json", [row(low), row(high)]);
    assert.equal((readInventory(ordered.path, { ...ordered, chains: 2 }) as unknown[]).length, 2);
    assert.deepEqual(readInventory(ordered.path, { ...ordered, chains: -1 }), []);
    const reversed = write("reversed.json", [row(high), row(low)]);
    assert.equal(
      readInventory(reversed.path, { ...reversed, chains: -1 }),
      "CUTOVER_INVENTORY_MISMATCH",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
