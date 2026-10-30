# Injection checker protocol v1

`internal/checker` defines one content assessment per request. A checker classifies content; callers retain delivery policy and independent security controls. The package contains the protocol, HTTP client, known-answer health check, and mock conformance tests. It has no scanner, proxy, MCP, configuration, or provider integration.

## Request

Send `POST` to an operator-configured endpoint such as `https://api.vendor.example/check`, with `Content-Type: application/json`. This example shows the schema. The request ID and digest are illustrative placeholders; clients generate a fresh 256-bit cryptographic random ID and compute the binding for each call.

```json
{
  "protocol_version": "pipelock.checker/v1",
  "request_id": "example-request-id",
  "policy_generation": "policy-1",
  "input_binding": "sha256-of-exact-item-json",
  "item": {
    "item_id": "item-1",
    "kind": "text",
    "surface": "tool_result",
    "transport": "mcp_stdio",
    "direction": "response",
    "extraction_version": "text/v1",
    "parts": [
      {"part_id": "raw", "role": "content", "representation": "original", "text": "aGVsbG8="},
      {"part_id": "decoded", "role": "decoded_view", "representation": "base64/v1", "text": "hello"}
    ],
    "original_bytes": 8,
    "submitted_bytes": 13,
    "completeness": {"status": "complete"},
    "context": [
      {"name": "tool", "value": "example", "origin": "tool_output", "trust": "untrusted"}
    ]
  }
}
```

`input_binding` is the lowercase SHA-256 digest of the exact `item` JSON value bytes sent, excluding whitespace outside that value. The server hashes those raw bytes, without reserialization. The Go client emits compact JSON with `encoding/json`; `checker.Binding` computes its digest. This binds identity, labels, ordered content, context, counts, and completeness. It does not attest what a model actually evaluated.

Each part has a unique nonempty ID, role, representation label, and exact UTF-8 text. Empty text is valid. Extractors define and version their surface, transport, direction, role, and representation labels. They preserve original and decoded/normalized views as separate ordered parts; producing views is outside this package. `original_bytes` counts source bytes before extraction. `submitted_bytes` is the sum of UTF-8 text bytes across all parts, including extra views, and can exceed original bytes. Neither count measures tokens or proves completeness.

Completeness is mandatory: `complete` has no reason; `partial` requires a typed reason. Partial input never yields a complete benign assessment. Context is optional, with no implicit conversation history. Each value declares a name, value, origin, and trust label. `untrusted` is valid for any named origin; `authenticated` is accepted only with `origin: operator`. Tool output cannot assert authenticated intent. Callers establish provenance and redact credentials before submission; labels alone do not authenticate a source.

`text` is supported. `action` and `image` are reserved kind names for future action-time and image checks. The client returns `not_checked/unsupported` without a network call for these and unknown kinds. The optional `payload` JSON field reserves their structured payloads, including proposed tool calls and authenticated task labels. Those formats remain future work; text items must omit `payload`. A server that does not implement a requested kind must return `not_checked/unsupported`.

## Response

HTTP 200 carries one result:

```json
{
  "protocol_version": "pipelock.checker/v1",
  "request_id": "example-request-id",
  "item_id": "item-1",
  "input_binding": "sha256-of-exact-item-json",
  "revision": {"checker": "example/v1", "model": "example-model/v1", "adapter": "example-adapter/v1"},
  "completeness": {"status": "complete"},
  "status": "assessed",
  "classification": "suspicious",
  "score": {"value": 0.9, "scale": "example-risk", "calibration_id": "example-calibration/v1"},
  "findings": [{"reason_id": "instruction_override", "part_ids": ["decoded"]}]
}
```

Assessed responses require `benign`, `suspicious`, or `abstain` classification and no failure reason. Findings have stable reason IDs and optional references to submitted parts. Benign responses cannot carry findings. Optional scores require a named scale, calibration ID, and finite numeric value. The captured policy pins the scale, calibration, and inclusive minimum/maximum; there is no universal range or cutoff. Scores do not override classification.

For an unavailable assessment, keep all identity, revision and completeness fields, omit classification, score, and findings, and replace the status fields with:

```json
{"status": "not_checked", "reason": "unavailable"}
```

This fragment is not a complete response. Wire reasons are `unavailable`, `timeout`, `canceled`, `refused`, `unsupported`, `over_budget`, `truncated`, `malformed`, and `stale_revision`. Unknown reasons reject. Responses have no advice text, source offsets, content replacements, or tool calls. Callers must not forward response fields as instructions to an agent.

## Typed outcomes

| Outcome | Go assessment state | Caller meaning |
|---|---|---|
| Off | `off` | No invocation |
| Complete assessed benign | `benign` | Selected checker assessed this complete item |
| Complete assessed suspicious | `finding` | Caller applies its captured policy |
| Suspicious on partial input/result | `finding` | Detection kept; partial completeness stays on the response |
| Abstention, or benign on partial input/result | `incomplete` | No complete benign conclusion |
| Not checked, except truncated/partial | `not_assessed` | Assessment unavailable |
| Invalid protocol response | `not_assessed`, status `invalid` | Never benign; no response exposed |
| Truncated | `incomplete` | Coverage incomplete |

These names match the scanner assessment vocabulary without importing scanner code. The package grants no authorization and implements no enforcement. Integrations withhold required failed/incomplete assessments in block mode; warn mode may deliver only when independent controls allow, with degraded coverage visible. Failures are not attack detections. Every mode preserves independent DLP, destination, tool policy, containment, and permissions.

## Strictness, limits, and transport

The decoder uses `internal/jsonscan` to reject duplicate keys, escaped duplicate spellings, schema aliases, unknown fields, and trailing JSON or junk. Unknown versions, missing/duplicate items, identity or binding mismatch, revision mismatch, missing completeness, invalid classifications/reasons, unknown part references, invalid scores, and response overflow produce typed invalid assessments. Arrays/batches are unsupported. Incompatible schemas require a new exact version; v1 does not ignore new fields.

The caller supplies an immutable `Policy`: mode, generation, pinned checker/model/adapter revisions, timeout, request/response byte budgets, and optional score bounds. The client has no inferred model limits, retries, cache, truncation, or fallback. Request budgets include the serialized envelope and context. The caller resolves them against backend capacity; tokenization and queue admission belong to later adapters. Checking response revision claims against configured pins is not independent artifact verification.

The client captures one fixed endpoint and authorization header. It rejects URL userinfo, queries, fragments, and authorization values that are not valid HTTP header values. A dedicated transport has `Proxy: nil`, refuses redirects, and disables connection reuse to prevent automatic transport replays. HTTPS uses system certificate verification. Plain HTTP requires explicit opt-in and a numeric loopback address. HTTP over an absolute Unix-socket path uses a synthetic `http://localhost/...` endpoint. `VerifyPeer` can check each socket connection; managed runner ownership and platform-specific peer checks remain integration work. An unset callback proves no peer identity.

Connection-time DNS validation applies the repository's non-overridable destination floor to every resolved address, in every embedded IPv4 form: cloud-metadata endpoints, link-local addresses (including container credential endpoints), multicast, and unspecified addresses. One refused address refuses the lookup. The client dials only checked addresses, in resolver order under the same deadline, without a second lookup, and permits explicitly configured private HTTPS services. Addresses are ordered as RFC 8305 section 4 describes, alternating IPv6 and IPv4 starting with the resolver's first family, and at most three are tried. Each attempt gets an even share of the remaining call deadline, with the same two-second floor Go's multi-address dialer uses, so one address that silently drops connections cannot consume the whole call. No attempt starts after the deadline. When every tried address fails, the call fails closed. Callers own endpoint authorization, hosted-data consent, and local service ownership. The transport ignores ambient proxy variables and never calls a scanner.

The original context deadline and configured whole-call timeout bound connection setup, the HTTP exchange, and response reading. Reading stops at the response budget plus one byte. HTTP/read errors produce typed unavailable results; cancellation and timeout have separate reasons. Raw endpoint, credential, response-body, and transport-error strings do not enter assessment errors.

## Health and conformance

`SelfTest` receives a checker, captured policy, and configured known-benign and known-suspicious items. Both must produce the corresponding complete assessed result under one shared deadline. An always-benign service fails the suspicious probe. Failure returns `*HealthError` identifying the probe and typed result, without probe text in its error message. It does not enable an off policy or substitute cached health for per-item assessment.

Use `checkertest.Run(t, factory)` in implementation tests. The factory receives a loopback mock endpoint and returns the client; the harness supplies test policy and content fixtures. The mock validates every request against this contract: strict request and item schemas, version, policy generation, a binding computed over the exact item bytes, an unchanged item, the request budget, and a request ID never reused within the run. Cases cover valid classifications, not-checked reasons, malformed replies, duplicate keys/items, binding/revision failures, trailing data, invalid scores, refused redirects, non-200 replies, oversized and endless bodies, off policies, and reserved or unknown kinds with no request sent. Client-specific tests also cover no retry, deadlines, concurrent identities, address checks, and Unix sockets. Mock conformance proves protocol behavior, not model accuracy or live provider compatibility.
