# Fleet Receipt Report v2

Fleet Receipt Report v2 groups accepted audit batches by recorder namespace so
independent recorder runs and v3 writers can reuse sequence numbers within one
fleet report window. It retains the DSSE envelope, in-toto Statement v1 subject
anchors, report signing purpose, summary arithmetic, and completeness checks of
[Fleet Receipt Report v1](fleet-receipt-v1.md).

## Version and compatibility

The statement uses `predicateType: "https://pipelab.org/attestation/fleet-receipt/v2"`
and the predicate uses `schemaVersion: 2`. Both markers must match. The in-toto
statement type remains `https://in-toto.io/Statement/v1`, and the DSSE payload type
remains `application/vnd.in-toto+json`. Unknown report versions are rejected.

`pipelock conductor fleet report` mints v2 by default. `--report-version 1` mints
v1 with its original per-follower ordering and overlap checks; it refuses a
window containing overlapping recorder runs. It does not omit sources or
silently switch versions. `--report-version 2` explicitly selects v2. Minting
still requires Enterprise; offline verification remains free:

```bash
pipelock verify-receipt fleet-receipt.dsse.json --fleet-report --key fleet-report.pub
```

The verifier accepts v1 and v2. V1 cannot contain v2 chain identities. An older
v1-only verifier rejects v2; update the verifier before moving report producers
to v2. Archived v1 reports retain their validation and canonical encoding.

## Source batch identity

Every v2 `sourceBatches` element adds a required `chain` object. For v2 recorder
entries it contains:

```json
{"entryVersion": 2, "sessionId": "recorder-run-a"}
```

For v3 recorder entries it contains:

```json
{"entryVersion": 3, "sessionId": "recorder-run-a", "chainKind": "recorder", "writerInstanceId": "writer-a"}
```

Only recorder entry versions 2 and 3 are supported. `sessionId` is nonempty and
cannot contain NUL. V3 requires nonempty `chainKind` and `writerInstanceId`
without NUL; v2 cannot carry those fields. These are the recorder namespace
rules, not a new operator-assigned grouping field. Identity is scoped by
`orgId`, `fleetId`, and `instanceId` as well as all four chain fields.

The report builder derives this object from the actual stored payload after
checking its byte count and SHA-256 against the enrolled audit signer's signed
envelope, and verifying that envelope with the enrolled audit key. It validates
the segment's sequence range, head/tail hashes, entry schemas, links and entry
count. Every entry must have the same nonempty session and its recomputed
recorder hash must match. V3 entries must also match the envelope namespace.
The final entry must be the envelope's checkpoint, including its sequence,
hash and signature bytes. An embedded recorder public key does not establish
independent authority. Invalid or unresolved identity causes report refusal;
there is no fallback grouping or source omission.

The new object is part of the canonical, signed report payload. Existing
subjects still bind each original source batch's `envelopeHash`. The enrolled
signer chooses the recorder session: a session identifies a sequence namespace,
not proof that a restart was honest or that no history was rewritten. Report
v2 changes no receiver admission or fork-detection policy.

## Ordering and completeness

Source batches sort lexicographically by `orgId`, `fleetId`, `instanceId`, then
chain `entryVersion` (numeric), `sessionId`, `chainKind`, `writerInstanceId`,
then `seqStart` and `seqEnd` (numeric), `receivedAt`, and `batchId`. Subjects are
emitted in the corresponding source-batch order. The verifier rejects reordered
source batches and overlaps within one scoped namespace. Cross-namespace
sequence overlap is permitted. Batch identity remains globally unique within
the report by `(orgId, fleetId, instanceId, batchId)` even across namespaces.

All selected batches remain included. Report windows use the existing
received-at interval and fail on evidence-set truncation. Follower totals
aggregate all included namespaces; each summary breakdown and completeness
fraction retains v1's exact arithmetic checks. A bad source fails the report
rather than producing an incomplete fleet report.

## Verification limits

L1 verifies the report signature, canonical payload, source anchors, namespace
shape and ordering, uniqueness, summary arithmetic and completeness arithmetic.
It authenticates the report signer's attestation that the builder derived the
namespaces from verified payloads. Offline L1 does not replay raw audit payloads,
verify follower audit signatures, or independently reproduce namespace
derivation. It does not prove honest restart, absence of bypass, or evidence
outside the report window. `verificationLevel: "L2"` remains unsupported.

The schema is [fleet-receipt-v2.schema.json](../../schemas/fleet-receipt-v2.schema.json).
The frozen Go conformance corpus is `sdk/conformance/testdata/fleet-receipt-v2/`;
the v1 corpus remains unchanged. Namespace derivation and malformed signed
payloads are exercised separately by the report-builder tests.
