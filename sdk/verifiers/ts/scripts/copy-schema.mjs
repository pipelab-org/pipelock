import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(here, "..");
const repoRoot = resolve(packageDir, "../../..");
const source = resolve(repoRoot, "sdk/audit-packet/v0.json");
const target = resolve(packageDir, "dist/src/v0.schema.json");

mkdirSync(dirname(target), { recursive: true });
copyFileSync(source, target);
// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

const {
  profile,
  layout,
  limits,
  kinds,
  objects,
  conditions,
  enums,
  findings,
  normalization_profiles,
} = JSON.parse(readFileSync(resolve(repoRoot, "sdk/receipt-v3/registry.json"), "utf8"));
writeFileSync(
  resolve(packageDir, "dist/src/v3/registry.json"),
  JSON.stringify({
    profile,
    layout,
    limits,
    kinds,
    objects,
    conditions,
    enums,
    findings,
    normalization_profiles,
  }),
);
