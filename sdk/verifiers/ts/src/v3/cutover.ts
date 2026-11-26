// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { closeSync, readSync } from "node:fs";
import { openEvidence } from "./input.js";
import type { Staged } from "./store.js";
import type { Verification } from "./verify.js";

const empty = Buffer.from('{"chains":[],"v":1}');

function isEmptyInventory(path: string): boolean {
  const fd = openEvidence(path);
  try {
    const bytes = Buffer.alloc(empty.length + 1);
    let size = 0;
    while (size < bytes.length) {
      const n = readSync(fd, bytes, size, bytes.length - size, null);
      if (!n) break;
      size += n;
    }
    return size === empty.length && bytes.subarray(0, size).equals(empty);
  } finally {
    closeSync(fd);
  }
}

export function verifyEmptyCutover(
  v: Verification,
  inventories: Map<string, string[]>,
  claimed: boolean,
): Map<string, Staged> {
  if (!claimed) return new Map();
  const checked = new Set<string>();
  for (const stream of v.streams.values()) {
    const pin = stream.body?.legacy_cutover;
    if (!pin || !stream.open) continue;
    checked.add(pin.inventory);
    const paths = inventories.get(pin.inventory) ?? [];
    if (!paths.length && pin.chains !== 0) v.add("CUTOVER_INVENTORY_MISMATCH", stream.open);
    for (const path of paths)
      if (pin.chains !== 0 || !isEmptyInventory(path))
        v.add("CUTOVER_INVENTORY_MISMATCH", stream.open);
  }
  for (const [id, paths] of inventories)
    if (!checked.has(id))
      for (const path of paths) if (!isEmptyInventory(path)) v.add("CUTOVER_INVENTORY_MISMATCH");
  return new Map();
}
