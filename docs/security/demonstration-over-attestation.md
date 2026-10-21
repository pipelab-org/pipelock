<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Demonstration Over Attestation

Pipelock's evidence story is not "trust the vendor dashboard." A buyer can
re-run the shipped verifier against signed artifacts with a pinned public key.

## What The Buyer Verifies

- Receipt signatures use trusted Ed25519 public keys.
- Receipt chains link by sequence and previous hash.
- Fleet reports bind follower evidence into an offline-verifiable report.
- Tampering, missing links, wrong keys, and unpinned keys fail closed unless the
  operator explicitly chooses structural-only mode.

## Customer-Path Demo

Collect the evidence directory from a current single-chain Pipelock recorder,
then verify it offline. Replace the paths with your evidence directory and the
recorder signer's trusted public-key file, obtained independently of the evidence:

```bash
pipelock verify-receipt \
  --chain /path/to/evidence-dir --whole-recorder \
  --key /path/to/recorder-signing.pub
```

This checks the v1 and v2 receipt chains present, every recorder entry, and each
selected run's transcript-root seal without contacting Pipelock, Conductor, or a
hosted service. Exit 0 means those single-chain runs' ends are proven. Exit 3
(`VALID PREFIX, END UNPROVEN`) means the signatures and links check out but an end
is unproven, as with an unsealed running recorder or a legacy shared-session chain.

For a multi-chain run, verify its complete receipt group explicitly:

```bash
pipelock verify-receipt \
  --chain /path/to/evidence-dir --group <group-id> \
  --key /path/to/recorder-signing.pub
```

Use the run's group ID from its signed group manifest. `GROUP_VALID` (exit 0)
proves the selected group's signed close and shard commitments; an incomplete or
invalid group exits nonzero. This group command does not take `--whole-recorder`.
Directory verification also discovers and checks receipt groups automatically;
see [multi-chain receipts](../guides/receipt-verification.md#receipt-groups-with-multiple-chains).

To check a receipt file instead, pass its filename without `--chain`; see
[receipt verification](../guides/receipt-verification.md) for the file's scope
and endpoint options.

For a fleet report:

```bash
pipelock verify-receipt \
  --fleet-report /path/to/fleet-report.json \
  --key /path/to/fleet-report-signing.pub
```

What this does: verifies the signed fleet report with the pinned report-signing
public key.

## Negative Demo

Change one byte in a receipt or use the wrong public key, then rerun the same
command. Expected result: verification exits non-zero and reports the signature
or chain failure.

## Boundary

Offline verification proves the integrity of the emitted evidence. It does not
prove that no unmediated traffic happened outside Pipelock; that property is
deployment-enforced by routing and egress controls.
