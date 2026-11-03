# Decision inventory

The JSONL golden records production decisions for built-in defaults and each embedded preset. The test loads preset YAML through LoadPolicyBundleBytes, calls ResolveRuntime, and records CanonicalPolicyHash before applying each named fixture variant. Policy hashes live in decision-inventory-policy.golden.jsonl, one line per preset with a hash for each resolved runtime. Behavior rows live in decision-inventory.golden.jsonl, so a hash-only change leaves them unchanged. The same test and regenerate flag check both files.

Run and regenerate from the repository root:

    go test ./internal/proxy -run '^TestDecisionInventory$'
    go test ./internal/proxy -run '^TestDecisionInventory$' -update-decision-inventory

The ordinary proxy package test in CI compares every generated row with the checked-in file. Regeneration is explicit; CI doesn't update either file.

## Reading a row

- preset, runtime: the loaded and resolved policy before fixture adjustments; the separate policy golden binds its hash.
- variant: an explicit operator setting used to reach a part or an exception. Stock preserves the preset.
- transport_part, input_class, detectors: the exercised part, synthetic input class, and observed detector names. URL scans record the first failing stage and the production ResultClass; they don't claim later stages ran.
- resolved_action: the production scanner, capture, or streaming decision before the final transport disposition. Audit can deliver a finding whose scanner action is block.
- disposition: allow, warn, block, or refuse. Refuse identifies an incomplete inspection that withheld delivery; an incomplete inspection can also warn and deliver.
- inspection: inspected, skipped, or incomplete for the named part. A clean result isn't evidence that another part was inspected. Body inspection_source names handler-capture or scan-request-body-probe; the latter also supplies the diagnostic and failure-layer detector.
- http_status, delivered: actual handler status and delivery. SSE delivery compares the complete returned event bytes because HTTP 200 can precede an event refusal. The standalone MCP scan command emits verdicts only, so its rows always have delivered: false.
- diagnostic: stable production detail for incomplete inspections and stream findings. Fixtures contain no real credentials.
- block_reason, block_reason_source: the production HTTP block-reason header, MCP denial data, or signed block receipt layer. Receipt layers retain their own vocabulary; they aren't translated into HTTP blockreason codes. not-emitted marks a handler denial without a reason code; not-emitted:scanner-decision and not-emitted:scan-verdict mark rows whose exercised functions don't emit a transport block reason. These rows leave block_reason absent rather than inventing a code. The malformed and duplicate-key MCP input fixtures stop at the redaction gate before a pending receipt action exists; their BlockedRequest has no ErrorData. No production block code or receipt is available for those refusals.

## Test setup and variants

URL rows call Scanner.Scan and the proxy's urlResultBlocks decision, and the test fails if the production forward handler delivers differently. HTTP rows call the production forward handler with an in-memory RoundTripper; body and response actions come from the existing capture observer. Body inspection comes from the handler capture when available. DLPVerdictRecord and bodyScanToFindings don't expose FileInspectionIncomplete, UnscannedEncoding, ScanError, or Reason. Incomplete-body inspection and diagnostic fields therefore come from a separate scanRequestBody probe, labeled in the row. This probe uses production scanning but doesn't observe the handler's invocation; observing that metadata requires a production capture change outside this inventory. Block reasons still come from the handler's response. Header rows exercise a provider credential in its documented Bearer carrier and a lookalike destination. The same credential in a URL query has no audience allowance under the scoped rules: audit warns and delivers, while the other preset/default fixtures block. SSE rows also call the production dispatcher to retain its finding or inspection error. MCP rows drive ScanRequest, ForwardScannedInput, ForwardScanned, or ScanStreamResult. Issuer rows observe a delivered response through recordDeliveredIssuerQuery, then use that store in the production query-allowance scan.

Scanners are reused by the production policy hash within each preset; proxy and session state are new for each HTTP fixture, and the fixed requests stay below request and data budgets. The test opens no listener and performs no network access. A fixed resolver returns a public address, except for the private-DNS fixture. Ambient environment-secret discovery is disabled during scanner construction, and the kill-switch token environment override is empty. The URL-grant and response-size/passthrough clocks are fixed to 2026-01-01. No preset file changes.

Named variants admit the synthetic destination to the API allowlist; add a private-service IP allowance; set body pattern actions, body trust, or enforce; or enable TLS interception for issuer evidence. Opaque-response variants use the existing 1 MiB response-cap fixture with a larger attachment, a matching 1 MiB whole-buffer scan ceiling, block response action, a size-exempt host, and no, live, or expired exact passthrough entry. Their fixed expiry dates are evaluated through the existing response clock.

## Scope

Covered: URL path/query/subdomain entropy, URL size, blocklist, literal and resolved private addresses, private-service allowance and metadata floor, core and contextual DLP, provider audience and lookalike rejection; request-body core/non-core and critical/high DLP, pattern warn overrides, injection under enforce/audit and body trust, entropy, malformed/compressed input, incomplete-file warnings/refusals; buffered responses, separate SSE decisions, opaque-response passthrough/expiry; MCP input content/structure and tool/response scanning; absent/populated issuer state, TLS disabled/enabled, and session separation.

This is a sampled decision inventory, not an exhaustive enforcement specification. Remaining matrices include named-agent profiles, signed/local policy merges, startup/reload, fetch/CONNECT/TLS-intercept transport integration, WebSocket, A2A, cross-origin OAuth issuance on both legs, issuer expiry/restart/lost state, cookie/server-ID relief, response core-observation exceptions, suppression/redaction, registered/environment values, full receipt lifecycle outcomes and required-receipt failures. The issuer rows test the production store and scanner decision; they don't establish a TLS connection.
