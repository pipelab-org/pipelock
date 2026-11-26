// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

const { mkdirSync, readFileSync, writeFileSync } = require("node:fs");
const { dirname, join, relative } = require("node:path");

const [lockPath, packPath, destination] = process.argv.slice(2);
const lock = JSON.parse(readFileSync(lockPath, "utf8"));
const [pack] = JSON.parse(readFileSync(packPath, "utf8"));
const { name, version, dependencies, bin, engines } = lock.packages[""];
if (
  lock.lockfileVersion !== 3 ||
  pack.name !== name ||
  pack.version !== version ||
  !pack.integrity
) {
  throw new Error(
    "npm tarball does not match the TypeScript verifier lockfile",
  );
}

const tarball =
  "file:" + relative(destination, join(dirname(packPath), pack.filename));
const consumer = {
  name: "receipt-v3-conformance",
  private: true,
  dependencies: { [name]: tarball },
};
// Keep the locked dependency paths, versions, resolved URLs and integrity values.
// Only the source root is replaced by the package actually being tested.
const packages = Object.fromEntries(
  Object.entries(lock.packages).filter(
    ([location, entry]) => location && !entry.dev,
  ),
);
packages[""] = { name: consumer.name, dependencies: consumer.dependencies };
packages["node_modules/" + name] = {
  version,
  resolved: tarball,
  integrity: pack.integrity,
  dependencies,
  bin,
  engines,
};

mkdirSync(destination, { recursive: true });
writeFileSync(join(destination, "package.json"), JSON.stringify(consumer));
writeFileSync(
  join(destination, "package-lock.json"),
  JSON.stringify({ name: consumer.name, lockfileVersion: 3, packages }),
);
