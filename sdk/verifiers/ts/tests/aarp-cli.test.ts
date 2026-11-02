// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// End-to-end CLI tests for the aarp subcommand: exit codes (0 appraised/linked,
// 1 fatal/not-linked, 2 I/O or trust error, 64 usage), --json output, the human
// non-json path, and the --chain path. The CLI is run as a subprocess against
// the built dist so exit-code wiring through main() is exercised.

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { findPackageRoot } from "./paths.js";

const packageRoot = findPackageRoot(import.meta.url);
const CLI = resolve(packageRoot, "dist/src/cli.js");
const corpus = resolve(packageRoot, "../../conformance/testdata/aarp-corpus");
const endProof = resolve(packageRoot, "../../conformance/testdata/aarp-end-proof");
const trust = `${corpus}/trust.json`;
const provenanceFixture = resolve(
  packageRoot,
  "../../conformance/testdata/provenance/p00-valid.json",
);

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

function runCLI(args: string[]): RunResult {
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8" });
  return { status: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

test("cli aarp: appraise golden fixture exits 0 with comparable JSON", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`,
    "--trust",
    trust,
    "--json",
  ]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /"assertion_signed":true/u);
  assert.ok(r.stdout.endsWith("\n"));
});

test("cli aarp: human (non-json) appraise path exits 0", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`,
    "--trust",
    trust,
  ]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /AARP appraisal \(aarp\/v0\.1\)/u);
});

test("cli aarp: fatal envelope exits 1 and prints envelope_fatal in json mode", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/malicious/m09-profile-mismatch.aarp.json`,
    "--trust",
    trust,
    "--json",
  ]);
  assert.equal(r.status, 1);
  assert.equal(r.stdout.trim(), '{"envelope_fatal":true}');
});

test("cli aarp: fatal envelope non-json prints to stderr and exits 1", () => {
  const r = runCLI(["aarp", `${corpus}/edge/p07-unknown-field.aarp.json`, "--trust", trust]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /ENVELOPE FATAL/u);
});

test("cli aarp: --chain linked stream exits 0", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c01-valid-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
    "--json",
  ]);
  assert.equal(r.status, 3);
  const report = JSON.parse(r.stdout);
  assert.equal(report.chain_linked, true);
  assert.equal(report.integrity, "valid");
  assert.equal(report.status, "VALID PREFIX, END UNPROVEN");
  assert.deepEqual(report.end_proof, { proven: false, evidence: [] });
  assert.equal(report.signatures_verified, true);
});

test("cli aarp: --chain non-json human path exits 0", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c01-valid-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
  ]);
  assert.equal(r.status, 3);
  assert.match(r.stdout, /AARP chain: 3 envelopes/u);
  assert.match(r.stdout, /VALID PREFIX, END UNPROVEN/u);
});

test("cli aarp: --chain expected sequence proves endpoint", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c01-valid-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
    "--expect-seq",
    "2",
    "--json",
  ]);
  assert.equal(r.status, 0);
  const report = JSON.parse(r.stdout);
  assert.equal(report.status, "CHAIN VALID");
  assert.deepEqual(report.end_proof, { proven: true, evidence: ["operator_seq"] });
});

test("cli aarp: --allow-prefix succeeds but keeps partial verdict", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c01-valid-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
    "--allow-prefix",
    "--json",
  ]);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).status, "VALID PREFIX, END UNPROVEN");
});

test("cli aarp: chain requires trusted signatures", () => {
  const r = runCLI(["aarp", `${corpus}/chain/c01-valid-stream.aarp.jsonl`, "--chain", "--json"]);
  assert.equal(r.status, 1);
  assert.equal(JSON.parse(r.stdout).integrity, "invalid");
});

test("cli aarp: good parallel signature survives a bad signature", () => {
  const source = `${corpus}/chain/c01-valid-stream.aarp.jsonl`;
  const rows = readFileSync(source, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const dir = mkdtempSync(join(tmpdir(), "aarp-chain-"));
  try {
    const good = rows[1].signatures[0];
    const signature = good.sig as string;
    const bad = { ...good, sig: `${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}` };
    rows[1].signatures = [good, bad];
    const parallel = join(dir, "parallel.jsonl");
    writeFileSync(parallel, `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);
    const r = runCLI([
      "aarp",
      parallel,
      "--trust",
      trust,
      "--chain",
      "--expect-seq",
      "2",
      "--json",
    ]);
    assert.equal(r.status, 0);
    assert.equal(JSON.parse(r.stdout).signatures_verified, true);

    rows[1].signatures = [good];
    rows[1].signatures[0].protected.key_id = "unknown-key";
    const unknown = join(dir, "unknown-signer.jsonl");
    writeFileSync(unknown, `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);
    const rejected = runCLI(["aarp", unknown, "--trust", trust, "--chain", "--json"]);
    assert.equal(rejected.status, 1);
    assert.equal(JSON.parse(rejected.stdout).signatures_verified, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli aarp: forged signature and head cut fail", () => {
  const source = `${corpus}/chain/c01-valid-stream.aarp.jsonl`;
  const rows = readFileSync(source, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const dir = mkdtempSync(join(tmpdir(), "aarp-chain-"));
  try {
    const sig = rows[1].signatures[0].sig as string;
    rows[1].signatures[0].sig = `${sig.slice(0, -1)}${sig.endsWith("A") ? "B" : "A"}`;
    const forged = join(dir, "forged.jsonl");
    writeFileSync(forged, `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);
    let r = runCLI(["aarp", forged, "--trust", trust, "--chain", "--json"]);
    assert.equal(r.status, 1);
    assert.equal(JSON.parse(r.stdout).status, "CHAIN BROKEN");

    const cut = join(dir, "head-cut.jsonl");
    writeFileSync(cut, `${readFileSync(source, "utf8").trim().split("\n").slice(1).join("\n")}\n`);
    r = runCLI(["aarp", cut, "--trust", trust, "--chain", "--json"]);
    assert.equal(r.status, 1);
    assert.equal(JSON.parse(r.stdout).integrity, "invalid");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli aarp: shared end-proof conformance cases", () => {
  const manifest = JSON.parse(readFileSync(resolve(endProof, "expect.json"), "utf8")) as {
    trust: string;
    cases: Array<{
      name: string;
      file: string;
      flags: string[];
      exit: number;
      status: string;
      proven: boolean;
    }>;
  };
  const trustPath = resolve(endProof, manifest.trust);
  for (const c of manifest.cases) {
    const r = runCLI([
      "aarp",
      resolve(endProof, c.file),
      "--trust",
      trustPath,
      "--chain",
      "--json",
      ...c.flags,
    ]);
    assert.equal(r.status, c.exit, c.name);
    const report = JSON.parse(r.stdout);
    assert.equal(report.status, c.status, c.name);
    assert.equal(report.end_proof.proven, c.proven, c.name);
  }
});

test("cli aarp: --chain broken stream exits 1", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c02-reordered-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
    "--json",
  ]);
  assert.equal(r.status, 1);
});

test("cli aarp: --chain fatal line exits 1 with marker", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/chain/c03-mixed-issuer-stream.aarp.jsonl`,
    "--trust",
    trust,
    "--chain",
    "--json",
  ]);
  assert.equal(r.status, 1);
});

test("cli aarp: missing positional is usage error (64)", () => {
  const r = runCLI(["aarp", "--trust", trust]);
  assert.equal(r.status, 64);
});

test("cli aarp: unknown flag is usage error (64)", () => {
  const r = runCLI(["aarp", `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`, "--bogus"]);
  assert.equal(r.status, 64);
});

test("cli aarp: missing envelope file is I/O error (2)", () => {
  const r = runCLI(["aarp", "/nonexistent/file.aarp.json", "--trust", trust]);
  assert.equal(r.status, 2);
});

test("cli aarp: missing trust file is I/O error (2)", () => {
  const r = runCLI([
    "aarp",
    `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`,
    "--trust",
    "/nonexistent/trust.json",
  ]);
  assert.equal(r.status, 2);
});

test("cli aarp: no --trust runs with empty trust (every sig unknown_key)", () => {
  const r = runCLI(["aarp", `${corpus}/golden/g01-single-ed25519-mediated.aarp.json`, "--json"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /"status":"unknown_key"/u);
  assert.match(r.stdout, /"assertion_signed":false/u);
});

test("cli provenance: incomplete verification requires explicit opt-in", () => {
  const strict = runCLI(["provenance", provenanceFixture]);
  assert.equal(strict.status, 1);
  assert.equal(JSON.parse(strict.stdout).overall, "incomplete");

  const inspection = runCLI(["provenance", provenanceFixture, "--allow-incomplete"]);
  assert.equal(inspection.status, 0);
  assert.equal(JSON.parse(inspection.stdout).overall, "incomplete");
});

test("cli provenance: unreadable and invalid fixtures remain rejected", () => {
  const missing = runCLI(["provenance", resolve(packageRoot, "does-not-exist.json")]);
  assert.equal(missing.status, 1);
  assert.equal(JSON.parse(missing.stdout).overall, "invalid");

  const invalidFixture = resolve(
    packageRoot,
    "../../conformance/testdata/provenance/p02-bad-signature.json",
  );
  const invalid = runCLI(["provenance", invalidFixture, "--allow-incomplete"]);
  assert.equal(invalid.status, 1);
  assert.equal(JSON.parse(invalid.stdout).overall, "invalid");
});
