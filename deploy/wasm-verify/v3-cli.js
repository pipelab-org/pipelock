// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

// Node adapter for exercising the browser build through the conformance CLI.
const { readFileSync, readdirSync, statSync } = require("node:fs");
const path = require("node:path");
const { parseArgs } = require("node:util");
const { webcrypto } = require("node:crypto");

function readDirectory(root, dir, files) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const target = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      readDirectory(root, target, files);
    } else if (entry.isFile()) {
      files[path.relative(root, target).split(path.sep).join("/")] = readFileSync(target);
    } else {
      throw new Error(`evidence path is not a regular file: ${target}`);
    }
  }
}

async function main() {
  const [wasmDir, subcommand, ...args] = process.argv.slice(2);
  if (!wasmDir || subcommand !== "v3") throw new Error("expected WASM directory and v3");
  const { values, positionals } = parseArgs({
    args,
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
    allowPositionals: true,
  });
  if (values.claims && (positionals.length !== 1 || Object.keys(values).length !== 1)) {
    throw new Error("--claims requires one file and no other options");
  }
  if (values.format !== undefined && values.format !== "v3") throw new Error("format must be v3");
  if (values.format === "v3" && positionals.length !== 1) {
    throw new Error("explicit v3 format requires exactly one file");
  }

  const files = Object.create(null);
  const directory = !values.claims && positionals.length === 1 && statSync(positionals[0]).isDirectory();
  if (directory) {
    readDirectory(positionals[0], positionals[0], files);
  } else {
    const resolved = positionals.map((file) => path.resolve(file));
    const ranks = new Map([...new Set(resolved)].sort().map((file, i) => [file, i]));
    for (const file of resolved) {
      // Preserve the basename and the host's stable path ordering.
      const rank = String(ranks.get(file)).padStart(8, "0");
      files[`${rank}/${path.basename(file)}`] = readFileSync(file);
    }
  }

  globalThis.crypto ??= webcrypto;
  require(path.resolve(wasmDir, "wasm_exec.js"));
  const go = new globalThis.Go();
  const binary = readFileSync(path.join(wasmDir, "pipelock-verifier.wasm"));
  const { instance } = await WebAssembly.instantiate(binary, go.importObject);
  void go.run(instance).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  });
  if (values.claims) {
    const claimed = globalThis.pipelockClaimsReceiptV3(files);
    if (typeof claimed !== "boolean") throw new Error(claimed.error);
    process.stdout.write(`${claimed}\n`);
    return;
  }
  const result = globalThis.pipelockVerifyReceiptV3(files, {
    keys: values.key,
    allow_unpinned: values["allow-unpinned"],
    allow_prefix: values["allow-prefix"],
    accept_discontinuities: values["accept-discontinuity"],
    allow_partial_histories: values["allow-partial-history"],
    expect_lineage: values["expect-lineage"],
    expect_heads: values["expect-head"],
    expect_sequences: values["expect-seq"],
    format: values.format,
    directory,
  }, values.output ?? "result");
  if (typeof result !== "string") throw new Error(result.error);
  process.stdout.write(result);
  process.exitCode = JSON.parse(result).exit_code;
}

main().catch((error) => {
  process.stderr.write(`${error.message.replaceAll("\n", "; ")}\n`);
  process.exitCode = 2;
});
