# pipelock verify-receipt

Verify a signed receipt, a chain, a whole recorder, or a receipt group. Pin the trusted signer with `--key`; repeat it for rotated keys. See the [receipt verification guide](../guides/receipt-verification.md) for formats and trust limits.

```bash
pipelock verify-receipt receipt.json --key signer.pub
pipelock verify-receipt --chain evidence --whole-recorder --key signer.pub
pipelock verify-receipt --chain evidence --session proxy --allow-prefix --key signer.pub
```

Chain verification reports integrity and endpoint proof separately. A terminal signed session close proves an action-chain end, and a transcript root covered by its trailing signed checkpoint proves a whole-recorder end, when the run recorded under its own per-run session. A complete group close proves the group scope. `--expect-head HASH` or `--expect-seq N` pins an independently known receipt endpoint. Restart links and recovery seals don't prove an end. Mixed v1/v2 input verifies both chains; endpoint pins apply to v2. A pin must select one run when the directory has several.

Pipelock has recorded each run under its own per-run session (`<base>.run.<id>`) since v3.6.0. Older releases recorded every run under one shared session such as `proxy` and resumed that chain after each restart, so a close or seal there doesn't show that nothing came after it. Those chains exit 3. In receipt-chain mode, pin the endpoint with `--expect-head` or `--expect-seq`. Under `--whole-recorder` a receipt pin can't authenticate the recorder entries, so it never proves the end there; use `--allow-prefix` to accept the prefix.

| Flag | Effect |
|---|---|
| `--chain DIR` | Verify the selected session or every run of its base. |
| `--session ID` | Select one exact run; its restart base is still checked. |
| `--whole-recorder` | Verify every recorder entry and the authenticated outer boundary. |
| `--require-seal` | Treat a missing transcript root as invalid evidence. Requires `--whole-recorder`. |
| `--allow-prefix` | Return 0 for a valid prefix while retaining `VALID PREFIX, END UNPROVEN`, including with `--fleet-report`. |
| `--expect-head HASH` | Require the independently known final receipt hash. |
| `--expect-seq N` | Require the independently known final unsigned sequence. |
| `--json` | Emit separate `integrity`, `end_proof`, `scope`, and `status` fields plus per-chain signer trust. |
| `--clean-report PATH` | Write `pipelock.clean_report.v2` JSON with the same endpoint status and separate signer-trust mode. |
| `--group ID` | Verify a complete signed group in `--chain DIR` with pinned keys. |
| `--allow-unpinned` | Acknowledge reduced signer trust; this doesn't accept an unproven end. |

For chains, exit 0 means integrity verified and the endpoint proven for the declared scope. Exit 1 means invalid evidence; exit 2 means usage or configuration failure; exit 3 means `VALID PREFIX, END UNPROVEN`. `--allow-prefix` changes only the last exit to 0 while preserving the prefix label. Single receipts keep their existing exit contract. Fleet reports verify their signature and arithmetic, but neither current fleet format proves a final endpoint, so a report that verifies prints `VALID PREFIX, END UNPROVEN` and exits 3 by default. With `--allow-prefix`, that verified prefix exits 0 and keeps the same label; this does not prove a complete report. `--expect-head`, `--expect-seq`, and `--json` remain refused with `--fleet-report`. Report-write failures remain errors. A script that treats any non-zero exit as failure now stops on an unproven end; add `--allow-prefix` where an open chain or fleet report is expected.

Group verification refuses a native evidence run stream above 256 MiB, and the writer doesn't stop before that ceiling, so restart a multi-chain proxy before a run reaches it. See [receipt groups with multiple chains](../guides/receipt-verification.md#receipt-groups-with-multiple-chains). The published PyPI package `pipelock-verify` 0.4.1 doesn't verify groups or end proof.

Clean-report readers must dispatch by `schema_version` and reject unknown versions.
Validate historical `pipelock.clean_report.v1` reports with the unchanged
[v1 schema](../evidence/clean-report-v1.schema.json), which has no endpoint status.
New reports use the [v2 schema](../evidence/clean-report-v2.schema.json), which
requires `integrity`, `end_proof`, `scope`, and `status` as well as the chain,
actions, and signer-trust mode. `CHAIN UNPINNED` means valid integrity and a
proven end without pinned signer trust. An unproven end keeps
`VALID PREFIX, END UNPROVEN`, including with `--allow-unpinned` or `--allow-prefix`.
