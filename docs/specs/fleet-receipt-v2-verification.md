# Fleet Receipt Report v2: Offline Verification

Use the free offline verifier with the fleet-report signing public key:

```bash
pipelock verify-receipt fleet-receipt.dsse.json --fleet-report --key fleet-report.pub
```

The command accepts both report versions. V2 requires the v2 predicate URI and
`schemaVersion: 2`, and checks the signed source-batch namespace for every batch.
Source batches follow one canonical order across the whole report, as defined
in the v2 contract. Sequence non-overlap applies within each follower's recorder
namespace; batch uniqueness and report arithmetic apply to the whole report. Unknown
versions, mixed version markers, missing chain identity, duplicates, and
same-namespace overlaps are rejected. V1 keeps its original per-follower checks.

The verifier pins the report signer. L1 does not replay the underlying audit
payloads or verify their follower signatures. It trusts the report signer's
attestation of payload-derived grouping and cannot distinguish an honest restart
from an enrolled signer's rewrite under a new session.

See [the v2 contract](fleet-receipt-v2.md) for namespace fields, canonical ordering,
producer validation and compatibility, and [v1 verification](fleet-receipt-v1-verification.md)
for the unchanged signature, trust-pinning, canonicality and arithmetic checks.
The versioned schema and frozen corpus are linked from the v2 contract.
