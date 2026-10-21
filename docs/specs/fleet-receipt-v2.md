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
not proof that a restart was honest or that no history was rewritten.

The accompanying receiver policy accepts overlapping sequence ranges from distinct validated chain namespaces. It rejects divergent overlaps within one namespace and treats unresolved identities as conflicting. These comparisons cover retained batch history; durable session observations don't preserve conflict detection after the corresponding batch history is pruned. The report format records these limits and doesn't establish continuity between sessions.

## Ordering and completeness

Source batches sort by `orgId`, `fleetId`, `instanceId`, then
chain `entryVersion` (numeric), `sessionId`, `chainKind`, `writerInstanceId`,
then `seqStart` and `seqEnd` (numeric), `receivedAt`, and `batchId`. String
fields compare bytewise on their UTF-8 encoding, as Go's string comparison does. Subjects are
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

L1 does not prove continuity between source batches, including batches in the
same namespace. The builder checks sequence contiguity and hash linkage inside
each batch's own segment, but the report's source anchors include only each
segment tail hash, not its head hash or previous-tail link (the audit envelope
carries them; the report does not copy them). Gaps and lineage breaks between
non-overlapping batches are therefore not detected. Received-at windows can
omit intervening batches. This limitation also applies to v1.

A fixed recorder session combined with lost recorder state can reuse sequence
numbers in the same namespace. These overlapping batches remain refused;
operators must preserve recorder state or use per-run sessions. The report does
not exclude the affected follower.

The schema is [fleet-receipt-v2.schema.json](../../schemas/fleet-receipt-v2.schema.json).
The frozen Go conformance corpus is `sdk/conformance/testdata/fleet-receipt-v2/`;
the v1 corpus remains unchanged. Namespace derivation and malformed signed
payloads are exercised separately by the report-builder tests.

## Receiver observations and retention

New v2 producers include an optional signed `history` object. Existing v2
reports without it remain valid and mean receiver observations unavailable and
cross-session continuity unproven. V1 has no history object.

`history.continuity` is always `cross_session_continuity_unproven`.
`multipleSessions` reports multiple session IDs for a follower, across included
source batches and the durable receiver observations. It does not treat a
writer change within one session as a new session. `sessions` lists constituent
chain observations from the scoped fleet's receiver snapshot: follower identity,
full chain identity, first/last server arrival, observed sequence span and
`retainedBackfill`. These are all-time receiver context, separate from report
window action totals; sequence spans do not assert complete intermediate coverage.
`retainedBackfill` means the earliest observation available from retained history,
not actual recorder startup.

`gaps` lists inclusive missing sequence ranges between included batches within
one full chain identity. The first included range need not start at zero, and
missing outer ranges or unsubmitted history cannot be inferred. Validators
recompute gaps and multiple-session facts from the declared evidence. They do
not authenticate the receiver observation table independently of the report signer.

`retention.observationsSince` records when durable observation tracking began;
`historyUnknown` preserves legacy or unresolved coverage. `prunedBefore`, when
present, records the receiver's greatest payload pruning cutoff, not proof that
all older evidence ever arrived. Pruning retains observations while deleting
payloads and their batch conflict metadata. No arrival ordering, timestamp or
retention field establishes a predecessor between sessions. A valid report
signature and its arithmetic do not establish source continuity.
