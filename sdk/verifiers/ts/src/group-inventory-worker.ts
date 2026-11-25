// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { verifyReceiptGroupsInProcess, type GroupInventoryMessage } from "./group.js";

process.once("message", async (request: { dir: string; trustedKeys: string[] }) => {
  const send = (message: GroupInventoryMessage) => process.send!(message);
  const summary = await verifyReceiptGroupsInProcess(request.dir, request.trustedKeys, (group) =>
    send({ group }),
  );
  send({ summary });
  process.disconnect?.();
});
