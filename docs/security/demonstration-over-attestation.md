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

Collect the evidence directory from a current Pipelock recorder, then verify it offline:

```bash
pipelock verify-receipt \
  --chain /path/to/evidence-dir --whole-recorder \
  --key 70b991eb77816fc4ef0ae6a54d8a4119ddc5a16c9711c332c39e743079f6c63e
```

For single-chain runs, this checks the v1 and v2 receipt chains present, every recorder entry, and each run's transcript-root seal without contacting Pipelock, Conductor, or a hosted service. Multi-chain runs are checked as complete receipt groups. Exit 0 means the included runs' ends are proven. Exit 3 (`VALID PREFIX, END UNPROVEN`) means the signatures and links check out but an end is unproven, as with an unsealed running recorder or a legacy shared-session chain. To check a receipt file instead, pass its filename without `--chain`; see [receipt verification](../guides/receipt-verification.md) for the file's scope and endpoint options.

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
