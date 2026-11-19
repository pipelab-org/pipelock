# Recover a v3 receipt directory

Stop the process writing to the evidence directory before checking it. Supply public keys from your own records. Use one `--key` per signer, including prior signers.

```sh
pipelock evidence receipt-recovery ./evidence \
  --key ./current.pub --key ./previous.pub
```

The command checks the directory lock and verifies the history against those keys without writing to the directory. Exit 0 means the history meets the writer's verification rules. The writer checks the history and flushes its predecessor again when it starts.

## A storage error or an unsealed end

Fix the storage problem before restarting. If `receipt-recovery` succeeds, keep the same evidence directory. A stream marked `superseded_write_error` has a confirmed tip and may have later records marked `UNCONFIRMED`. A stream marked `superseded_unsealed` ended without a confirmed close. Keep these files together with their successor streams.

To accept a specific unproven end for offline verification, use the record ID of the successor's `stream_open`. For an open stream with no successor, use its tip record ID. Take the ID from the `END_UNPROVEN` finding.

```sh
pipelock verify-receipt --chain ./evidence --key ./current.pub \
  --key ./previous.pub --accept-discontinuity "$DISCONTINUITY_RECORD_ID"
```

Acceptance applies to that verification command. It records your choice in the result and leaves the signed files untouched.

## The signer key changed or was lost

If the original private key is unavailable, use a new signing key and add the previous **public** key to `flight_recorder.receipt_group_prior_signer_keys`. Supply both public keys to `receipt-recovery` and `verify-receipt`. If you can't recover a trustworthy copy of the earlier public key, preserve the old directory and begin a new history in an empty directory.

## Another process holds the lock

Stop the process that owns the evidence directory and rerun `receipt-recovery`. A second writer needs its own directory.

## Startup reports invalid, unsupported, or incomplete history

Keep a copy of any directory that reports `PREDECESSOR_TRUNCATED` or `DECISION_INCONSISTENT`. Start in a new empty evidence directory and retain the original files for verification. Acceptance flags apply to unproven ends and permitted gaps. Neither flag clears an integrity failure.

For `ACTION_UNINTERPRETED` or `DECISIONS_NOT_APPRAISED`, the startup check names the action body version that the writer needs. Use a compatible release, or preserve the existing directory and start a new history elsewhere.

For missing streams, cutover inventories, or legacy receipt files, restore the complete evidence from a trusted copy and rerun the check. This applies to `LEGACY_MEMBERSHIP_UNKNOWN` and `LEGACY_GROUP_INCOMPLETE`. If you can't restore the files, preserve the directory and start in a new empty one.

For `NO_EVIDENCE`, rerun the check against the directory containing the v3 receipt files.

If offline verification reports `DECISION_INDEX_FULL`, rerun `pipelock verify-receipt` with `--disk-index`. If startup still can't appraise every decision, preserve the directory for verification and start in a new empty one.

## Switch an existing legacy directory

Stop the legacy writer and verify its directory with the public keys you trust.

```sh
pipelock verify-receipt --chain ./evidence --key ./current.pub
```

Resolve any pending legacy holds while the legacy runtime still owns the directory, then stop it again. The v3 writer refuses a switch while holds remain unresolved. Keep the old receipts and journal in place. If the evidence uses earlier signing keys, put those public keys in `flight_recorder.receipt_group_prior_signer_keys`.

On a release that writes v3 receipts, set `flight_recorder.receipt_format: v3` and start with the same `flight_recorder.dir`. The first v3 stream pins the inventory of the legacy evidence. Stop the writer and run `verify-receipt --chain` again with all trusted signer keys. Keep the `receipt-v3-cutover-*.json` inventory alongside both sets of receipts.

## Return to legacy receipts

Stop the writer, choose a new empty directory for `flight_recorder.dir`, and set `flight_recorder.receipt_format: legacy`. Use the new directory also when rolling back to a binary released before v3 support. Preserve the switched directory with its cutover inventory and legacy chains so it can still be verified.

Verify the new legacy directory with `verify-receipt --chain` and its signer key before relying on the new receipts.
