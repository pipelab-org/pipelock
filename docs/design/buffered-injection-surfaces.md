# Buffered injection checker surfaces

This document defines checker routing for buffered content. Each key belongs under
`prompt_injection_detection.surfaces`. The checker protocol and mode semantics are
those of the existing MCP result and description selections. See
[configuration](../configuration.md).

## Surface matrix

| Consumer | Surface key | Content unit and parts | Transport / direction | Built-in composition |
|---|---|---|---|---|
| Fetch response | `http_response` | Delivered title plus readable text, with hidden text as a separate part; raw body on the existing extraction fallback | `fetch` / response | Existing fetch response scan, including hidden content and suppressions |
| Forward, intercepted CONNECT, reverse response | `http_response` | Existing body text, image metadata, wide-character or opaque prose views; structured responses use the existing extracted string parts | `forward`, `connect`, `reverse` / response | Existing body/structured scan and suppressions |
| Browser Shield retained view | `browser_shield` | Existing pre-rewrite scan view, including readable and hidden fetch views | Parent HTTP transport / response | Existing pre-Shield classification; combine with delivered-view classification |
| HTTP request body | `http_request_body` | Existing extracted text fields and source-order joined text, before synthetic sorted joins | Existing HTTP audit transport (`forward`, `intercept`, `reverse`) / request | Existing outbound wording scan; DLP, URL, entropy and address checks remain independent |
| MCP request | `mcp_tool_input` | Existing raw or extracted joined argument text and individual string parts; Unicode-unescaped view for malformed JSON | Existing MCP audit transport; fallback `mcp` / request | Existing outbound wording scans; compose with input DLP and structural checks |
| MCP listener parameter headers | `mcp_tool_input` | Decoded parameter value, one item per header | `mcp_http` / request | Existing header wording scan; header DLP remains independent |
| Scan API prompt injection / tool call | `scan_api` | Requested content or existing extracted joined argument text | `scan_api` / request | Existing API wording result; tool-call DLP and policy remain independent |
| Claude Code / Cursor / Hermes tool input | `hook_tool_input` | Existing command, tool argument, or file-write text | `decide` or `hermes` / request | Existing hook wording result; DLP and tool policy remain independent |
| Claude Code / Cursor / Hermes tool result | `hook_tool_result` | Existing tool-result or file-read text | `decide` or `hermes` / response | Existing hook wording result; DLP and tool policy remain independent |
| Offline MCP response scan | `mcp_tool_result` (existing) | Existing MCP text extraction | `mcp` / response | Existing result seam |
| Tool description scanner's remaining direct call | `mcp_tool_description` (existing) | Existing description text | `mcp` / response | Already inside the description seam; don't assess each tool twice |
| Capture replay | Recorded buffered HTTP or MCP response surface; other records stay built-in-only | Retained scanner input | Recorded transport / response | Existing replay response result; summary-only records remain summary-only |
| Audit simulation and diagnostic direct wording probes | Built-in-only | Synthetic built-in pattern examples | Offline | These probes demonstrate the shipped basic pattern corpus; their MCP examples retain the existing MCP selection. External checker health is checked by its existing startup self-test records. |

Fetch, forward, intercept and reverse share a response selection because the
operator chooses a trust policy for upstream HTTP content independently of how
that content reaches the proxy. Transport labels retain the distinction. Browser
Shield has its own selection because the pre-rewrite view can include content
that the browser will never receive. Input and result hooks are separate because
sending work and receiving untrusted tool output have different trust boundaries.

## Items and composition

Original text parts keep source order. Unicode-tag and matching-normalized views
may accompany an original part, labelled as views, following the MCP seam.
No new base64 or hex decoded checker parts are introduced. Protocol byte budgets,
revision binding, completeness validation and off-host consent remain unchanged.
An empty content unit earns no external benign assessment.

Run the existing built-in pipeline under the selected surface context. External
ownership disables all built-in wording, including the wording core floor, even
when the external mode is off or its check fails. Deterministic controls remain
active. Compose one external result with the buffered wording result using the
existing MCP rules. Don't fall back to basic. A block finding is content evidence;
a block-mode failure is an infrastructure refusal, never a fabricated finding.

A block-mode external response result takes precedence over the transport's
wording action (including warn, strip or ask). Request findings retain the
surface's existing audit and destination-trust policy, described below. Warn
records the assessment and delivers without injection-driven taint or escalation. Watch runs off the delivery path and never
changes delivery. Only a complete benign assessment earns adaptive clean credit;
off, incomplete, not-checked and failed assessments don't.

| Mode / result | HTTP | MCP input | Scan API | Hooks / replay |
|---|---|---|---|---|
| Off | Existing non-wording controls decide | Same | Same | Same |
| Warn finding or failure | Deliver and record | Forward and record | Return assessment; finding may report warn | Allow with recorded observation; replay reports observation |
| Block finding | Response refusal; request policy below | Request policy below | Deny with finding | Request policy below; replay reports block |
| Block incomplete, not-checked or failure | Withhold using scan-error path | Infrastructure refusal | Existing scan-error response | Scan-error denial; replay reports scan error |
| Complete benign | Existing non-wording controls decide | Same | Same | Same |

## Request audit and destination trust

A completed external block finding is content evidence, like a built-in injection
finding. `enforce: false` applies only where the consumer already observes those
findings. A checker failure, incomplete answer or `not_checked` is a scan error,
not an injection finding; the existing scan-error refusal is retained.

| Surface | Completed block finding with `enforce: false` | Block-mode checker failure with `enforce: false` |
|---|---|---|
| Forward HTTP request body | With `request_body_scanning.action: warn`, record and forward; the existing forward path still refuses `action: block` | Refuse using scan-error path |
| CONNECT-intercept and reverse request body | Observe and forward unless another control blocks | Refuse using scan-error path |
| MCP stdio and HTTP listener request body | Warn and forward unless a floor or another control blocks | Refuse with scan error |
| MCP listener parameter headers | Refuse, as for built-in header injection | Refuse with parse-error reason |
| Scan API `prompt_injection` and `tool_call` | Return `deny` with findings; this classifier does not read `enforce` | Return HTTP 500 with `assessment_incomplete`, without attack findings |
| Claude Code / Cursor tool input | Allow with advisory evidence | Deny with scan-error evidence |
| Hermes tool input | Block; this adapter does not read `enforce` | Block with scan-error reason |

With enforcement on, HTTP body injection hard-blocks untrusted destinations.
`request_body_scanning.trusted_hosts` makes both built-in and external findings
follow `request_body_scanning.action`; it does not exempt checker failures or
other independent controls. MCP, API and hook block findings refuse with
enforcement on. Response-side external block findings and failures retain their
refusals regardless of `enforce`, including tool-result hooks.

## Compatibility and boundaries

With no new selection, preserve the original scans, actions, finding ordering and
output. Explicit basic uses the existing per-surface mode cap and original action.
Selections may reduce basic below the global wording mode but can't raise it.
External modes follow the existing independent checker policy. Missing selection
maps never enter canonical configuration hashing. Reload creates a new immutable
policy/checker snapshot; unrelated reloads retain equivalent effective behavior.

WebSocket frames, SSE, A2A, checker local runners, qualification and signed judged
input are separate work. This routing doesn't claim streaming coverage. Hermes
changes only its injection call through a shared hook helper; its combined-view
DLP traversal and credential-redaction design remain separate.
