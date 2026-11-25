# Card presentation differential oracle

`card-main-a689c65b1.jsonl.gz` records the behavior of commit `a689c65b1e911029f1e834efd1559199af36053a`. The first JSONL record identifies that revision, the case count and a SHA-256 of every serialized input case in order. Each following record contains its case ID and a verdict bit mask: text DLP = 1, JSON request body = 2, URL scan = 4, standalone redaction = 8. Set bits mean blocked or redacted.

The version-independent generator is `internal/cardcorpus`. It imports no production scanner, normalizer, issuer validator or exception classifier. Its matrix includes three synthetic PANs and invalid-checksum twins per issuer/length, every two- and three-group partition, 4,096 additional distinct composition masks for each of the 15- and 16-digit cases, and a complete separator/context cross for representative contiguous, canonical, decimal and column groupings. The remaining dimensions use deterministic rotating coverage rather than the full Cartesian product. Published examples are transcribed from Stripe's test-card documentation. JSON number pieces strip leading zeros to remain valid JSON.

`TestCardMainDifferential` exercises `ScanTextForDLP`, the actual proxy `scanRequestBody` JSON path, `Scanner.Scan` and the standalone matcher. It retains each checkout's shipped card rule and immutable core rules. Unrelated configurable DLP patterns, injection scanning, entropy, rate limiting and data budgets are disabled to avoid masking card changes. No request is sent to an upstream; configured DNS SSRF checks are disabled.

Record the golden only from the pinned main checkout:

```sh
git worktree add --detach "$capture/main" a689c65b1e911029f1e834efd1559199af36053a
cp -R internal/cardcorpus "$capture/main/internal/cardcorpus"
cp internal/proxy/card_differential_test.go "$capture/main/internal/proxy/"
(cd "$capture/main" && go test -count=1 -v -run '^TestCardMainDifferential$' ./internal/proxy -card-record-main "$capture/card-main.jsonl.gz")
cp "$capture/card-main.jsonl.gz" internal/proxy/testdata/card-main-a689c65b1.jsonl.gz
go test -count=1 -v -run '^TestCardMainDifferential$' ./internal/proxy
```

Recording refuses a different HEAD or modified tracked production files. Input changes fail the hash check and require rerunning the pinned main recorder. The branch compares every verdict. Only presentations requiring a single decimal-point join, tab/CR/LF joins, or exact published PANs can lose enforcement. Redaction can lose only exact published PANs. The exception decision uses presentation content, never a list of case IDs or the production detector. Added blocks and redactions are logged by category.
