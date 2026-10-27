// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strconv"
	"strings"
)

// ScannerBodyDLP and ScannerDenialOfWallet identify blocks emitted outside the
// URL scanner pipeline.
const (
	ScannerBodyDLP        = "body_dlp"
	AuditBodyEntropy      = "body_entropy"
	ScannerDenialOfWallet = "denial_of_wallet"

	// Audit* labels identify enforcement and warning families emitted outside
	// the URL scanner pipeline. Keeping their operator guidance in this table
	// gives generic blocked/anomaly events and dedicated audit events one source
	// of truth.
	AuditResponseScan                      = "response_scan"
	AuditHeaderDLP                         = "header_dlp"
	AuditReverseURLDLP                     = "dlp_reverse_url"
	AuditBodyPromptInjection               = "body_prompt_injection"
	AuditAddressProtection                 = "address_protection"
	AuditChainDetection                    = "chain_detection"
	AuditProvenance                        = "provenance"
	AuditMediaPolicy                       = "media_policy"
	AuditRequestPolicy                     = "request_policy"
	AuditAgentIdentity                     = "agent_identity"
	AuditTaintPolicy                       = "taint_policy"
	AuditSessionAnomaly                    = "session_anomaly"
	AuditAdaptiveEnforcement               = "adaptive_enforcement"
	AuditMCPSessionBinding                 = "mcp_session_binding"
	AuditMCPToolPolicy                     = "mcp_tool_policy"
	AuditToolScanning                      = "tool_scanning" // Released MCP blocked-event label
	AuditMCPInputDLP                       = "mcp_input_dlp"
	AuditMCPInputInjection                 = "mcp_input_injection"
	AuditMCPInputInspection                = "mcp_input_inspection"
	AuditMCPHeaderDLP                      = "mcp_header_dlp"
	AuditMCPHeaderInjection                = "mcp_header_injection"
	AuditMCPHeaderInspection               = "mcp_header_inspection"
	AuditMCPResponseInspection             = "mcp_response_inspection"
	AuditMCPProtocol                       = "mcp_protocol"
	AuditMCPRedirect                       = "mcp_redirect"
	AuditMCPRedirectOutputDLP              = "mcp_redirect_output_dlp"
	AuditMCPRedirectOutputInjection        = "mcp_redirect_output_injection"
	AuditMCPDefer                          = "mcp_defer"
	AuditFrozenTool                        = "frozen_tool"
	AuditSNIMismatch                       = "sni_mismatch"
	AuditKillSwitch                        = "kill_switch"
	AuditAirlock                           = "airlock"
	AuditCrossRequestEntropy               = "cross_request_entropy"
	AuditCrossRequestFragment              = "cross_request_fragment"
	AuditCrossRequestFragmentOwnerMismatch = "cross_request_fragment_owner_mismatch"
	AuditCrossRequestFragmentCapacity      = "cross_request_fragment_capacity"
	AuditGitProtection                     = "git_protection"
	AuditAgentBudget                       = "budget"
	AuditResponseSize                      = "response_size"
	AuditShieldOversize                    = "shield_oversize"
	AuditContract                          = "contract"
	AuditSSEStream                         = "sse_stream"
	AuditUnscannable                       = "unscannable_passthrough"
	AuditA2AScan                           = "a2a_scan"
	AuditA2ACardSignature                  = "a2a_card_signature"
	AuditRedaction                         = "redaction"
	AuditScannerUnavailable                = "scanner_unavailable"
	AuditMediationEnvelope                 = "mediation_envelope"
	AuditReceiptEmission                   = "receipt_emission"
	AuditReverseSubmit                     = "reverse_proxy_submit"
	AuditA2AHeader                         = "a2a_header"
	AuditA2AResponse                       = "a2a_response"
	AuditBudgetTruncated                   = "budget_truncated"
	AuditTLSResponseBlocked                = "tls_response_blocked"
	AuditSessionDeny                       = "session_deny"
	AuditTLSHandshakeError                 = "tls_handshake_error"
	AuditTLSAuthorityMismatch              = "tls_authority_mismatch"
)

// Decide*Label values identify non-URL blocks emitted by internal/decide.
// They are not URL scanner pipeline labels, but they share the remediation
// table so operator and agent guidance cannot drift by surface.
const (
	DecideInjectionLabel  = "injection"
	DecidePolicyLabel     = "policy"
	DecideStructuralLabel = "decide"
)

const (
	bodyDLPOperatorKnob        = "Request body DLP matched. For a non-core false positive, add a top-level `suppress:` entry with `rule:` set to the matched rule name and `path:` scoped to the request path. Core DLP matches cannot be suppressed; fix the core pattern's precision. A built-in provider-key pattern additionally checks the destination: the credential is allowed at its declared audience and reported everywhere else. Prefer sending it only to that audience. If a different destination is intentional, such as an internal relay you operate, a path-scoped `suppress:` entry does apply here; it warns at config load and every match stays audited."
	bodyEntropyOperatorKnob    = "If the global `request_body_scanning.content_entropy_action` is `block`, an exact, expiring `content_entropy_warn_routes` entry can keep one HTTPS upload route visible without blocking it. With global `warn`, that route control is unavailable; use the existing warning or set the action to `block` when opaque traffic must stop. For a WebSocket-only endpoint, use `websocket_proxy.content_entropy_exclusions`."
	bodyEntropyOperatorBroader = "Host-wide `request_body_scanning.content_entropy_exclusions`, `trusted_domains`, or a higher entropy threshold affect more traffic than one exact route; use them only when that broader scope is intended."
	denialOfWalletOperatorKnob = "Correct the denial-of-wallet condition named by the reason. `runaway expansion` and alternating `cycle detected` use fixed detector thresholds and have no per-detector limit knob. " +
		"To audit instead of block, set the matched `agents._default.budget.dow_action` (or `agents.<name>.budget.dow_action`) to `warn`; this changes enforcement for every denial-of-wallet finding."
	denialOfWalletToolCallsOperatorKnob    = "Raise `agents._default.budget.max_tool_calls_per_session` (or the matched `agents.<name>.budget.max_tool_calls_per_session`) if the DoW subject's per-window tool-call budget is intentionally higher."
	denialOfWalletWallClockOperatorKnob    = "Raise `agents._default.budget.max_wall_clock_minutes` (or the matched `agents.<name>.budget.max_wall_clock_minutes`) if the DoW subject's per-window active time is intentionally longer-lived."
	denialOfWalletRetriesOperatorKnob      = "Raise `agents._default.budget.max_retries_per_tool` (or the matched `agents.<name>.budget.max_retries_per_tool`) if repeated identical calls are expected."
	responseScanOperatorKnob               = "For a non-core false-positive response finding, add a top-level `suppress:` entry with `rule:` set to the event's matched pattern and `path:` scoped to the exact request path. Core response floor matches cannot be suppressed; fix the core pattern's precision. `response_scanning.exempt_domains` is broader: it disables injection scanning for every response from that host."
	headerDLPOperatorKnob                  = "For a non-core false-positive header finding, add a top-level `suppress:` entry with `rule:` set to the matched DLP pattern and `path:` scoped to the exact request path. Core DLP matches cannot be suppressed; fix the core pattern's precision. A built-in provider-key pattern additionally checks the destination: the credential is allowed at its declared audience and reported everywhere else. Prefer sending it only to that audience. If a different destination is intentional, such as an internal relay you operate, a path-scoped `suppress:` entry does apply here; it warns at config load and every match stays audited."
	bodyPromptInjectionOperatorKnob        = "Correct the outbound request body. For a verified destination that must receive this content, add only that host to `request_body_scanning.trusted_hosts`; request-body scanning and its configured action still apply, but prompt-injection findings no longer force a block. An explicit `block` action still blocks."
	addressProtectionOperatorKnob          = "After independently verifying the intended destination, add the exact address to `address_protection.allowed_addresses` (or the matched `agents.<name>.allowed_addresses`). Do not weaken similarity thresholds to approve one address."
	chainDetectionOperatorKnob             = "If the event's named chain is expected, set that exact key under `tool_chain_detection.pattern_overrides` to `warn`; for a custom pattern, narrow its `sequence` or `action`. This changes only that named pattern."
	provenanceOperatorKnob                 = "In `pipelock` mode, sign the tool metadata with an Ed25519 key present in `mcp_tool_provenance.trusted_keys`. `mcp_tool_provenance.action: warn` downgrades unsigned tools only; invalid signatures, verification errors, and malformed tools/list responses always fail closed. Sigstore trust fields are not consumed by this verifier, so they are not a remediation path."
	mediaPolicyOperatorKnob                = "Tune the media control identified by the reason under `media_policy`: `strip_audio`, `strip_video`, `strip_images`, `allowed_image_types`, or `max_image_bytes`. Parse/read failures have no exemption; correct the malformed media or upstream response."
	requestPolicyOperatorKnob              = "Edit the exact matched entry under `request_policy.rules` (the event reason names it), narrowing its route/predicate or changing that rule's action. For parser/opaque findings, tune only `request_policy.on_parse_error` or `request_policy.on_opaque_operation`; allowing either is broader and fail-open for matching body predicates."
	agentIdentityOperatorKnob              = "Use a non-reserved self-declared agent identity. Reserved control-actor names are a non-tunable identity boundary; there is no exemption knob."
	taintPolicyOperatorKnob                = "After inspecting the recorded source and action, add a narrow, expiring `taint.trust_overrides` entry matching that source/action, or correct the source classification. Changing `taint.policy` weakens all taint decisions and is broader."
	sessionAnomalyOperatorKnob             = "For a legitimate domain burst, raise the matched `session_profiling.domain_burst` threshold (global or per-agent) or the global-only `session_profiling.window_minutes`. For a behavioral baseline deviation, inspect the profile and explicitly relearn/ratify it with the baseline operator commands; do not auto-ratify an unexplained deviation."
	adaptiveEnforcementOperatorKnob        = "Wait for the event's auto-recovery time, or inspect and reset only the affected identity session with the session operator commands after confirming the traffic is legitimate. Changing `adaptive_enforcement.levels` or thresholds affects every session and is broader."
	mcpSessionBindingOperatorKnob          = "Refresh the MCP session only after verifying the server's current tool inventory. If inventory drift is intentionally non-blocking, change `mcp_session_binding.unknown_tool_action` (or `no_baseline_action` for a missing baseline) to `warn`; that applies to every matching inventory event."
	mcpToolPolicyOperatorKnob              = "Inspect the matched `mcp_tool_policy.rules` entry and change only the intended tool or argument rule. A broad allow rule would admit unrelated calls."
	mcpInputDLPOperatorKnob                = "Remove the matched sensitive value from the MCP request. For a non-core false positive, inspect the exact `dlp.patterns` rule; `mcp_input_scanning.action` controls non-core input findings. Core credentials still hard-block unless redaction fully removes them; URL `exempt_domains` does not apply to MCP arguments."
	mcpInputInjectionOperatorKnob          = "Correct the MCP tool arguments carrying the instruction. `mcp_input_scanning.action` controls this input scan; URL and response suppressions do not apply to MCP arguments."
	mcpInputInspectionOperatorKnob         = "Correct the malformed or uninspectable MCP request and retry. `mcp_input_scanning.on_parse_error` covers only configurable protocol parse errors; malformed JSON, invalid UTF-8, duplicate keys and noncanonical protocol aliases always block."
	mcpHeaderDLPOperatorKnob               = "Remove the matched credential from the MCP listener request header. Header values are checked by text DLP, including Authorization by default and Last-Event-ID, Mcp-Param-*, and Mcp-Session-Id regardless of generic header selection. `request_body_scanning.scan_headers`, `header_mode`, `sensitive_headers`, and `ignore_headers` select other headers; `mcp_input_scanning.action` and URL DLP `exempt_domains` do not govern this gate. Supply upstream credentials with the operator's `--header` option instead of client headers."
	mcpHeaderInjectionOperatorKnob         = "Correct the instruction in the decoded Mcp-Param-* listener request header. Only those decoded parameter values receive response injection scanning; `request_body_scanning` header selection does not disable it. Investigate the matched pattern before changing response scanning globally."
	mcpHeaderInspectionOperatorKnob        = "The decoded MCP parameter header could not be scanned. Correct its encoding or restore scanner health and retry; suppression cannot make it scannable."
	mcpResponseInspectionOperatorKnob      = "The MCP response could not be inspected safely. Correct the malformed upstream response or restore scanner health and retry; no pattern suppression repairs a failed inspection."
	mcpProtocolOperatorKnob                = "Send one JSON-RPC request at a time. MCP batch requests are unsupported; no scanner or policy setting enables them."
	mcpRedirectOperatorKnob                = "Inspect the matched `mcp_tool_policy.rules` redirect rule and its `mcp_tool_policy.redirect_profiles` entry. Use a supported single request and restore the named handler; a missing profile or failed handler blocks locally."
	mcpRedirectOutputDLPOperatorKnob       = "Remove the matched credential from the redirect handler output. Inspect the configured `mcp_tool_policy.redirect_profiles` handler; request-side MCP input settings do not control its response."
	mcpRedirectOutputInjectionOperatorKnob = "Remove the instruction from the redirect handler output. Inspect the configured `mcp_tool_policy.redirect_profiles` handler and the matched response pattern."
	mcpDeferOperatorKnob                   = "Use defer only on MCP stdio or its stdio-to-HTTP bridge with top-level `defer.enabled: true`. Inspect the held action status, expiry, resolver decision, and matched `mcp_tool_policy.rules` action before retrying."
	mcpToolScanningOperatorKnob            = "Inspect the flagged tools/list definition and correct it at the upstream server. Review `mcp_tool_scanning` settings only after confirming the definition is intended."
	sniMismatchOperatorKnob                = "Correct the CONNECT hostname or TLS client so the SNI name matches the requested authority. `forward_proxy.sni_verification: false` disables domain-fronting protection for every tunnel and is not a narrow remediation."
	killSwitchOperatorKnob                 = "Inspect and clear every active kill-switch source. Config, API, remote kill, stale bundle, unresolved policy application, SIGUSR1, and sentinel-file sources are OR-composed, so every active source must clear. HTTP and intercepted-request gates consult `kill_switch.allowlist_ips` except during unresolved Conductor policy application, which requires successful policy recovery. Pipelock health, metrics, and main-listener API endpoints have their own exemption flags. Raw/MCP kill-switch gates do not consult those HTTP exemptions."
	airlockOperatorKnob                    = "Inspect the affected session and wait for its configured `airlock.timers` recovery, or use the authenticated session operator command to lower/reset only that session after confirming the traffic is legitimate. Weakening global triggers or tiers is broader."
	crossRequestEntropyOperatorKnob        = "For a verified high-entropy destination, add only that host to `cross_request_detection.entropy_budget.exempt_domains`, or raise `bits_per_window` if the session-wide volume is expected. Changing `action` to `warn` affects every entropy-budget finding."
	crossRequestFragmentOperatorKnob       = "The fragment reassembly DLP path has no per-host or per-rule exemption. Correct the split secret-like payload; the only config relief is the broad `cross_request_detection.action: warn` (or disabling `fragment_reassembly`), which weakens this detector for every session."
	gitProtectionOperatorKnob              = "Add only the intended owner/repository to `git_protection.allowed_push_repos` after verifying the remote. Disabling `git_protection` permits pushes to every repository and is broader."
	agentBudgetOperatorKnob                = "Raise only the limit named by the reason under the matched `agents.<name>.budget`: `max_requests_per_session`, `max_bytes_per_session`, or `max_unique_domains_per_session`. Zero disables that ceiling and is broader."
	responseSizeOperatorKnob               = "Raise only the exact transport response ceiling named in the reason. A `response_scanning.size_exempt_domains` entry is not a universal override: fetch-handler response-size blocks do not consult it."
	shieldOversizeOperatorKnob             = "Raise `browser_shield.max_shield_bytes` for the expected response size, or add only the trusted host to `browser_shield.exempt_domains`. Changing `browser_shield.oversize_action` to `warn` or `scan_head` permits incompletely shielded content and is broader."
	contractOperatorKnob                   = "Correct the action to match the active contract, or inspect and ratify a narrowly updated contract through the contract operator workflow. Disabling contract enforcement or broadening the manifest without review is not a safe remediation."
	sseStreamOperatorKnob                  = "For a non-core false-positive SSE finding, add a top-level `suppress:` entry for the matched response rule and exact path. Core response floor matches cannot be suppressed; fix the core pattern's precision. For event-size failures, raise `response_scanning.sse_streaming.max_event_bytes`; changing its action to `warn` affects every SSE finding."
	unscannableOperatorKnob                = "Remove or narrow the matching `response_scanning.unscannable_passthrough` entry to restore fail-closed scanning, or make the upstream response scannable. This event records an explicit full-content visibility gap; do not broaden the entry."
	a2aScanOperatorKnob                    = "Correct the flagged A2A content. There is no per-finding suppression, and `a2a_scanning.action` is not a universal override: malformed/uninspectable payloads and hostname-exfiltration findings hard-block without consulting it."
	a2aCardSignatureOperatorKnob           = "Sign the Agent Card with a key whose exact origin is authorized by `a2a_scanning.trusted_agent_card_keys`, or add the verified signer/origin pair there. Disabling signed-card requirements trusts every unsigned card and is broader."
	redactionOperatorKnob                  = "The requested redaction could not be applied safely. Correct the redaction profile or input and retry; there is no exemption knob because forwarding the unredacted payload would leak the protected value."
	scannerUnavailableOperatorKnob         = "Scanner acquisition failed closed during a reload/runtime transition. Restore scanner health or correct the rejected configuration and retry; there is no policy exemption for running without a scanner."
	mediationEnvelopeOperatorKnob          = "The mediation envelope could not be built, injected, signed, or verified safely. Check `mediation_envelope.actor_format` and `trust_domain`, then the configured signing key or inbound trust material as applicable; retry after correcting the failed step."
	receiptEmissionOperatorKnob            = "Required receipt emission failed closed. Restore the configured receipt sink/key and retry; there is no bypass knob while receipt-required enforcement is active."
	reverseSubmitOperatorKnob              = "Correct the submission to the configured `reverse_proxy` submit profile. This admission gate consults only `reverse_proxy.allowed_methods`, `reverse_proxy.allowed_paths`, and the effective minimum of `reverse_proxy.max_body_bytes` and `request_body_scanning.max_body_bytes`. Raw-path canonicality failures have no exemption."
	tlsFailureOperatorKnob                 = "Correct the TLS handshake, certificate, or authority mismatch at the client/upstream and retry. These checks fail closed and have no per-request exemption; disabling TLS interception or SNI verification is a broad loss of visibility."

	decideInjectionOperatorKnob  = "Prompt-injection scanning matched content in the action. Shell/file/tool Decide paths consult `response_scanning.enabled` and `response_scanning.action`; they call `ScanResponse` without the top-level `suppress:` list, so a suppression entry is inert here. MCP Decide input consults `mcp_input_scanning.enabled` and `mcp_input_scanning.action`."
	decidePolicyOperatorKnob     = "Tool policy denied the action. Edit the matching `mcp_tool_policy.rules` entry, or narrow/add a rule for the intended tool call."
	decideStructuralOperatorKnob = "The action could not be evaluated safely (unknown event, malformed tool input, or uninspectable input). There is no allow-path knob for the structural failure; correct the action shape and retry."

	ssrfOperatorKnob = "For an approved internal service, use `destination_grants` for its exact TCP host and port. Broader alternatives are top-level `trusted_domains` (hostname-based) or `ssrf.ip_allowlist` (IP-based). " +
		"Cloud-metadata, link-local, and multicast addresses are a non-overridable deny — neither knob exempts them (config validation rejects such entries). " +
		"This verdict depends on DNS resolution at runtime; explain reports it without resolving."
	ssrfOperatorBroader = "Disabling SSRF entirely (`internal: []`) removes private-range protection for ALL destinations — never do this to fix one host."

	// Cloud metadata endpoints are a credential-theft target and a
	// non-overridable SSRF deny: ssrf.ip_allowlist and trusted_domains cannot
	// exempt them (both config validation and the scanner refuse). There is no
	// allow-path knob by design.
	ssrfMetadataOperatorKnob = "Cloud instance-metadata endpoints are a non-overridable SSRF deny: `ssrf.ip_allowlist` and `trusted_domains` cannot exempt them (config validation rejects such entries and the scanner ignores them). " +
		"There is no allow knob — if an agent legitimately needs instance data, expose it through a dedicated internal service on a different address rather than allowing metadata access."

	// Link-local, multicast, and unspecified addresses share the metadata
	// deny's non-overridable status but are not metadata, so they get their own
	// wording rather than talking about "instance-metadata endpoints".
	ssrfNonOverridableOperatorKnob = "This is a non-overridable SSRF deny (link-local, multicast, or unspecified address): `ssrf.ip_allowlist` and `trusted_domains` cannot exempt it (config validation rejects such entries and the scanner ignores them). " +
		"There is no allow knob — reach the intended service by its ordinary routable or private address instead."

	injectionTraversalOperatorKnob = "This sequence is never legitimate in a normal URL (header injection / directory escape). There is no exemption knob — the URL must be corrected at the source."
	parseContextOperatorKnob       = "This is not a policy block: the request context was unavailable/cancelled, or the URL could not be parsed. Correct the input and retry."

	// Query entropy shares the ScannerEntropy label with path entropy
	// but is a distinct gate with a distinct knob. The table is keyed by label
	// alone, so this variant is selected by GuidanceForResult from the scan
	// Reason. The path-entropy default lives in the table's ScannerEntropy entry.
	queryEntropyOperatorKnob = "For a blocked query value at a stable endpoint path, add the exact scheme+host+path+param tuple to `fetch_proxy.monitoring.query_entropy_param_exclusions`; this skips only query-value entropy for that exact scheme+host+path+param. " +
		"An exact tuple covers only that path, not future paths with new upload UUIDs or other changing segments. If the host legitimately carries opaque query keys or values across changing paths or many endpoints, use `fetch_proxy.monitoring.query_entropy_exclusions` as the broader host-wide fallback. Query entropy is SEPARATE from URL DLP — exempting a DLP pattern does NOT lift an entropy block, and vice versa. " +
		nativeOAuthOperatorKnob
	// nativeOAuthOperatorKnob is static: the blocked query key is chosen by the
	// client, so it must not decide whether an operator is offered a grant.
	nativeOAuthOperatorKnob     = "If this is `state` or `nonce` on a native OAuth authorization-code GET whose `redirect_uri` is a literal loopback or private-use callback, an exact `fetch_proxy.monitoring.oauth_authorization_endpoints` grant covers that request; it accepts the endpoint as a channel for opaque values."
	queryEntropyKeyOperatorKnob = "A high-entropy query key is not covered by `fetch_proxy.monitoring.query_entropy_param_exclusions`, which skips only query-value entropy. " +
		"If the host legitimately carries opaque query keys, add it to `fetch_proxy.monitoring.query_entropy_exclusions`; that skips query-key and query-value entropy for the whole host. Query entropy is SEPARATE from URL DLP — exempting a DLP pattern does NOT lift an entropy block, and vice versa."
	queryEntropyOperatorBroader = "Raising `fetch_proxy.monitoring.entropy_threshold` lowers sensitivity globally for every destination — broader blast radius; prefer the narrowest applicable exclusion above."

	secretAgentReason             = "Request blocked: the destination or content matched a secret/credential pattern."
	highEntropyAgentReason        = "Request blocked: high-entropy content resembling exfiltration was detected."
	protectedAddressAgentReason   = "Request blocked: the destination resolves to protected internal or metadata infrastructure."
	protectiveCeilingAgentReason  = "Request blocked: a protective request ceiling was exceeded."
	denialOfWalletAgentReason     = "Request blocked: the MCP action exceeded its denial-of-wallet budget."
	injectionTraversalAgentReason = "Request blocked: the URL contains an injection/traversal sequence."
	promptInjectionAgentReason    = "Request blocked: the content matched a prompt-injection pattern."
	toolPolicyAgentReason         = "Request blocked: the tool call is not permitted by policy."
	decideStructuralAgentReason   = "Request blocked: the action could not be evaluated."
	auditContentAgentReason       = "Request blocked: protected content or an unsafe instruction pattern was detected."
	auditPolicyAgentReason        = "Request blocked: an operator-defined safety boundary denied the action."
	auditRuntimeAgentReason       = "Request blocked: a required security control could not complete safely."
	auditAnomalyAgentReason       = "Activity was flagged because it crossed an operator-defined safety boundary."
	// destinationNotPermittedAgentReason is shared by the blocklist and allowlist
	// blocks. It deliberately does NOT name which mechanism (blocklist vs strict
	// allowlist) rejected the destination: telling a blocked agent whether it is
	// in blocklist mode or strict-allowlist mode is containment-posture recon that
	// helps it reason about how boxed-in it is. The operator sees the exact
	// mechanism + knob via OperatorKnob; the agent gets only the terse "why".
	destinationNotPermittedAgentReason = "Request blocked: the destination is not permitted."
)

// RemediationGuidance describes how a blocked scan should be explained, split
// by audience. Operator fields name the exact allow-path; AgentReason is terse
// and non-procedural (never teaches the self-unblock knob).
type RemediationGuidance struct {
	OperatorKnob    string // exact narrowest verified config change; "" if none
	OperatorBroader string // broader option + its tradeoff; "" if none
	Immutable       bool   // true = safety floor; not disableable wholesale by config
	AgentReason     string // terse WHY, NO knob/path/how-to-unblock
}

// remediationGuidance is the canonical per-label block-remediation table. Each
// entry pairs the operator's exact allow-path with the terse, non-procedural
// reason shown to the agent. Consumers read it via GuidanceFor; the parity and
// confused-deputy guards in remediation_test.go keep it correct.
var remediationGuidance = map[string]RemediationGuidance{
	ScannerDLP: {
		OperatorKnob: "Add the destination host to that pattern's `dlp.patterns[].exempt_domains`. " +
			"URL DLP does NOT consult the top-level `suppress:` list (that is body-DLP and response-scanning only) — a `suppress:` entry here is inert. " +
			"If the value is a long token in the query string, you may ALSO need `fetch_proxy.monitoring.query_entropy_param_exclusions` for an exact endpoint+parameter, or `fetch_proxy.monitoring.query_entropy_exclusions` as the broader host-wide fallback (a separate gate).",
		OperatorBroader: "`tls_interception.passthrough_domains` exempts the host in one line but blinds Pipelock to ALL inner TLS (method, path, body, response) for that host — only acceptable for can't-scan-by-construction hosts, never as the fix for a single-pattern false positive.",
		AgentReason:     secretAgentReason,
	},
	ScannerCoreDLP: {
		OperatorKnob: "Core DLP is an immutable safety floor for critical credential shapes and cannot be exempted by config. If this is a genuine false positive, the pattern itself must be tightened in a release; there is no per-host carve-out.",
		Immutable:    true,
		AgentReason:  secretAgentReason,
	},
	ScannerEntropy: {
		// ScannerEntropy also has a query-entropy variant; later consumer rewiring
		// can preserve that nuance from Result.Reason. The table default is path
		// entropy because a plain scanner label cannot distinguish the two.
		OperatorKnob: "Add the exact host and path prefix to `fetch_proxy.monitoring.path_entropy_exclusions`; this is the narrowest fix and it lifts ONLY path entropy, leaving subdomain entropy, query entropy, DLP and SSRF enforced for that host. " +
			"The entry defaults to HTTPS; for a cleartext HTTP download, set `scheme: http` explicitly. HTTP leaves the request path visible on the network; the exclusion does not encrypt it. Use separate entries if both schemes are needed. " +
			"For recurring downloads, consider a stable publisher-specific prefix rather than a new filename entry for each release; a wider prefix also relaxes path entropy for every request it matches. " +
			"Before adding a route, confirm an agent cannot place a chosen opaque segment there and later read that value back, because such a route can carry data out. " +
			"This is the path-entropy gate; `fetch_proxy.monitoring.query_entropy_exclusions` does NOT lift path entropy blocks.",
		OperatorBroader: "Two broader options, both costlier than `path_entropy_exclusions`. Adding the host to `fetch_proxy.monitoring.subdomain_entropy_exclusions` covers every path on that host AND disables subdomain entropy for it, because one list drives both gates. Governing the host+path with `request_policy` is precise but requires enabling the whole request-policy rail. Raising `fetch_proxy.monitoring.entropy_threshold` lowers sensitivity for every destination.",
		AgentReason:     highEntropyAgentReason,
	},
	ScannerSubdomainEntropy: {
		OperatorKnob:    "Add the host to `fetch_proxy.monitoring.subdomain_entropy_exclusions` (exact or `*.example.com` wildcard). This is the subdomain-entropy gate (high-entropy DNS labels), distinct from the query-entropy gate.",
		OperatorBroader: "Raising `fetch_proxy.monitoring.subdomain_entropy_threshold` lowers subdomain sensitivity globally — prefer the per-host exclusion.",
		AgentReason:     highEntropyAgentReason,
	},
	ScannerBlocklist: {
		OperatorKnob: "Remove the entry from `fetch_proxy.monitoring.blocklist` (or narrow it) if the domain is legitimate.",
		AgentReason:  destinationNotPermittedAgentReason,
	},
	ScannerAllowlist: {
		OperatorKnob:    "Add the host to `api_allowlist`. In strict mode only allowlisted domains are reachable.",
		OperatorBroader: "Switching `mode` from `strict` to `balanced` permits monitored web browsing for all destinations — much broader; prefer adding the single host to `api_allowlist`.",
		AgentReason:     destinationNotPermittedAgentReason,
	},
	ScannerSSRF: {
		OperatorKnob:    ssrfOperatorKnob,
		OperatorBroader: ssrfOperatorBroader,
		AgentReason:     protectedAddressAgentReason,
	},
	ScannerSSRFMetadata: {
		OperatorKnob: ssrfMetadataOperatorKnob,
		Immutable:    true,
		AgentReason:  protectedAddressAgentReason,
	},
	ScannerCoreSSRF: {
		OperatorKnob: "Core SSRF blocks private/loopback/link-local IP literals as an immutable floor. `ssrf.ip_allowlist` can exempt a specific private or loopback address, but cloud-metadata, link-local, and multicast addresses are non-overridable — no allowlist entry exempts them. There is no way to disable the floor wholesale.",
		Immutable:    true,
		AgentReason:  protectedAddressAgentReason,
	},
	ScannerRateLimit: {
		OperatorKnob: "This is a protective ceiling, not a threat detection. It counts requests per base domain, so every subdomain of a site shares one budget. Raise `fetch_proxy.monitoring.max_requests_per_minute`, retry after the window, or with named agent profiles (Pro) raise it for one agent with `agents.<name>.rate_limit.max_requests_per_minute`; an agent `rate_limit` block replaces both per-minute ceilings, so set `max_data_per_minute` there too if one is configured.",
		AgentReason:  protectiveCeilingAgentReason,
	},
	ScannerLength: {
		OperatorKnob: "Raise `fetch_proxy.monitoring.max_url_length`, or inspect the URL for data stuffing in query parameters.",
		AgentReason:  protectiveCeilingAgentReason,
	},
	ScannerDataBudget: {
		OperatorKnob: "This is the URL scanner's per-domain sliding-window data ceiling, counted per base domain so every subdomain of a site shares it. Raise `fetch_proxy.monitoring.max_data_per_minute` if the response volume is legitimate; zero disables this ceiling for every destination. With named agent profiles (Pro), `agents.<name>.rate_limit.max_data_per_minute` sets it for one agent; that block replaces both per-minute ceilings, so set `max_requests_per_minute` there too.",
		AgentReason:  protectiveCeilingAgentReason,
	},
	ScannerCRLF: {
		OperatorKnob: injectionTraversalOperatorKnob,
		Immutable:    true,
		AgentReason:  injectionTraversalAgentReason,
	},
	ScannerPathTraversal: {
		OperatorKnob: injectionTraversalOperatorKnob,
		Immutable:    true,
		AgentReason:  injectionTraversalAgentReason,
	},
	ScannerScheme: {
		OperatorKnob: "Only `http` and `https` schemes are permitted. There is no knob to allow other schemes — use an http/https URL.",
		Immutable:    true,
		AgentReason:  "Request blocked: the URL scheme is not permitted.",
	},
	ScannerCoreResponse: {
		OperatorKnob: "Core response scanning is an immutable safety floor and cannot be suppressed or disabled by config. If this is a genuine false positive, the pattern itself must be tightened in a release; there is no per-pattern config carve-out.",
		Immutable:    true,
		AgentReason:  "Response blocked: a prompt-injection pattern was detected.",
	},
	ScannerContext: {
		OperatorKnob: parseContextOperatorKnob,
		AgentReason:  "Request blocked: the scan could not complete.",
	},
	ScannerParser: {
		OperatorKnob: parseContextOperatorKnob,
		AgentReason:  "Request blocked: the URL could not be parsed.",
	},
	ScannerBodyDLP: {
		OperatorKnob: bodyDLPOperatorKnob,
		AgentReason:  secretAgentReason,
	},
	AuditBodyEntropy: {
		OperatorKnob:    bodyEntropyOperatorKnob,
		OperatorBroader: bodyEntropyOperatorBroader,
		AgentReason:     highEntropyAgentReason,
	},
	ScannerDenialOfWallet: {
		OperatorKnob: denialOfWalletOperatorKnob,
		AgentReason:  denialOfWalletAgentReason,
	},
	AuditResponseScan:                      {OperatorKnob: responseScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditHeaderDLP:                         {OperatorKnob: headerDLPOperatorKnob, AgentReason: secretAgentReason},
	AuditReverseURLDLP:                     {OperatorKnob: "Remove the credential from the request URL. Reverse-proxy URL text scanning does not consult top-level `suppress:` entries or per-pattern `exempt_domains`. Core DLP matches cannot be exempted; a genuine false positive requires a pattern-precision fix.", AgentReason: secretAgentReason},
	AuditBodyPromptInjection:               {OperatorKnob: bodyPromptInjectionOperatorKnob, AgentReason: auditContentAgentReason},
	AuditAddressProtection:                 {OperatorKnob: addressProtectionOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditChainDetection:                    {OperatorKnob: chainDetectionOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditProvenance:                        {OperatorKnob: provenanceOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditMediaPolicy:                       {OperatorKnob: mediaPolicyOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditRequestPolicy:                     {OperatorKnob: requestPolicyOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditAgentIdentity:                     {OperatorKnob: agentIdentityOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditTaintPolicy:                       {OperatorKnob: taintPolicyOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditSessionAnomaly:                    {OperatorKnob: sessionAnomalyOperatorKnob, AgentReason: auditAnomalyAgentReason},
	AuditAdaptiveEnforcement:               {OperatorKnob: adaptiveEnforcementOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditMCPSessionBinding:                 {OperatorKnob: mcpSessionBindingOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditMCPToolPolicy:                     {OperatorKnob: mcpToolPolicyOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditMCPInputDLP:                       {OperatorKnob: mcpInputDLPOperatorKnob, AgentReason: secretAgentReason},
	AuditMCPInputInjection:                 {OperatorKnob: mcpInputInjectionOperatorKnob, AgentReason: auditContentAgentReason},
	AuditMCPInputInspection:                {OperatorKnob: mcpInputInspectionOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditMCPHeaderDLP:                      {OperatorKnob: mcpHeaderDLPOperatorKnob, AgentReason: secretAgentReason},
	AuditMCPHeaderInjection:                {OperatorKnob: mcpHeaderInjectionOperatorKnob, AgentReason: auditContentAgentReason},
	AuditMCPHeaderInspection:               {OperatorKnob: mcpHeaderInspectionOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditMCPResponseInspection:             {OperatorKnob: mcpResponseInspectionOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditMCPProtocol:                       {OperatorKnob: mcpProtocolOperatorKnob, Immutable: true, AgentReason: auditRuntimeAgentReason},
	AuditMCPRedirect:                       {OperatorKnob: mcpRedirectOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditMCPRedirectOutputDLP:              {OperatorKnob: mcpRedirectOutputDLPOperatorKnob, AgentReason: secretAgentReason},
	AuditMCPRedirectOutputInjection:        {OperatorKnob: mcpRedirectOutputInjectionOperatorKnob, AgentReason: auditContentAgentReason},
	AuditMCPDefer:                          {OperatorKnob: mcpDeferOperatorKnob, AgentReason: auditRuntimeAgentReason},
	ScannerMCPToolScanning:                 {OperatorKnob: mcpToolScanningOperatorKnob, AgentReason: auditContentAgentReason},
	AuditToolScanning:                      {OperatorKnob: mcpToolScanningOperatorKnob, AgentReason: auditContentAgentReason},
	AuditSNIMismatch:                       {OperatorKnob: sniMismatchOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditKillSwitch:                        {OperatorKnob: killSwitchOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditAirlock:                           {OperatorKnob: airlockOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditCrossRequestEntropy:               {OperatorKnob: crossRequestEntropyOperatorKnob, AgentReason: auditAnomalyAgentReason},
	AuditCrossRequestFragmentOwnerMismatch: {OperatorKnob: "The fragment stream belongs to another identity. Retry in the correct authenticated session; no configuration permits joining two identities' fragments.", AgentReason: auditRuntimeAgentReason},
	AuditCrossRequestFragmentCapacity:      {OperatorKnob: "Fragment inspection state is full. Increase cross_request_detection.fragment_reassembly.max_sessions or reduce active sessions before retrying.", AgentReason: auditRuntimeAgentReason},
	AuditCrossRequestFragment:              {OperatorKnob: crossRequestFragmentOperatorKnob, AgentReason: auditContentAgentReason},
	AuditGitProtection:                     {OperatorKnob: gitProtectionOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditAgentBudget:                       {OperatorKnob: agentBudgetOperatorKnob, AgentReason: protectiveCeilingAgentReason},
	AuditResponseSize:                      {OperatorKnob: responseSizeOperatorKnob, AgentReason: protectiveCeilingAgentReason},
	AuditShieldOversize:                    {OperatorKnob: shieldOversizeOperatorKnob, AgentReason: protectiveCeilingAgentReason},
	AuditContract:                          {OperatorKnob: contractOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditSSEStream:                         {OperatorKnob: sseStreamOperatorKnob, AgentReason: auditContentAgentReason},
	AuditUnscannable:                       {OperatorKnob: unscannableOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditA2AScan:                           {OperatorKnob: a2aScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditA2ACardSignature:                  {OperatorKnob: a2aCardSignatureOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditRedaction:                         {OperatorKnob: redactionOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditScannerUnavailable:                {OperatorKnob: scannerUnavailableOperatorKnob, Immutable: true, AgentReason: auditRuntimeAgentReason},
	AuditMediationEnvelope:                 {OperatorKnob: mediationEnvelopeOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditReceiptEmission:                   {OperatorKnob: receiptEmissionOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditReverseSubmit:                     {OperatorKnob: reverseSubmitOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditFrozenTool:                        {OperatorKnob: airlockOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditA2AHeader:                         {OperatorKnob: a2aScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditA2AResponse:                       {OperatorKnob: a2aScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditBudgetTruncated:                   {OperatorKnob: agentBudgetOperatorKnob, AgentReason: protectiveCeilingAgentReason},
	AuditTLSResponseBlocked:                {OperatorKnob: responseScanOperatorKnob, AgentReason: auditContentAgentReason},
	AuditSessionDeny:                       {OperatorKnob: adaptiveEnforcementOperatorKnob, AgentReason: auditPolicyAgentReason},
	AuditTLSHandshakeError:                 {OperatorKnob: tlsFailureOperatorKnob, AgentReason: auditRuntimeAgentReason},
	AuditTLSAuthorityMismatch:              {OperatorKnob: tlsFailureOperatorKnob, AgentReason: auditRuntimeAgentReason},
	DecideInjectionLabel: {
		OperatorKnob: decideInjectionOperatorKnob,
		AgentReason:  promptInjectionAgentReason,
	},
	DecidePolicyLabel: {
		OperatorKnob: decidePolicyOperatorKnob,
		AgentReason:  toolPolicyAgentReason,
	},
	DecideStructuralLabel: {
		OperatorKnob: decideStructuralOperatorKnob,
		Immutable:    true,
		AgentReason:  decideStructuralAgentReason,
	},
}

// GuidanceFor returns the remediation guidance for a scanner/block label. The
// second return is false for an unknown label — callers get no guidance rather
// than a wrong one (fail-safe).
func GuidanceFor(label string) (RemediationGuidance, bool) {
	g, ok := remediationGuidance[label]
	return g, ok
}

// OperatorHintFor returns the operator allow-path (OperatorKnob) for a label, or
// "" when the label has no guidance. Convenience for string-valued operator
// surfaces such as the audit remediation_hint field. Never use it for an
// agent-facing surface — that is what AgentReason (via GuidanceFor) is for.
//
// Prefer OperatorHintForResult when the scan Reason is available: a label alone
// cannot distinguish same-label variants (query vs path entropy), so this can
// return the wrong knob for a query-entropy block.
func OperatorHintFor(label string) string {
	g, _ := GuidanceFor(label)
	return g.OperatorKnob
}

// GuidanceForResult returns guidance using the scan Reason to disambiguate
// same-label variants. ScannerEntropy distinguishes query from path
// entropy, while ScannerDenialOfWallet distinguishes budget-limit reasons.
// Every other label falls through to the label-keyed table. This is the single
// place that disambiguation lives, so explain, audit, and future consumers agree.
// stripNestedURLReasonPrefix removes the "nested URL in query parameter %q: "
// prefix so guidance routes on the INNER scanner reason. The parameter key is
// attacker-chosen, and the SSRF routing below matches substrings such as
// "metadata"; without this, a request naming its parameter "metadata" would be
// explained with the immutable cloud-metadata guidance no matter what the
// nested destination actually was.
func stripNestedURLReasonPrefix(reason string) string {
	open := nestedURLReasonPrefix + " \""
	if !strings.HasPrefix(reason, open) {
		return reason
	}
	rest := reason[len(open):]
	// The key is %q-quoted, so the terminating quote is the first one not
	// preceded by an odd number of backslashes.
	for i := 0; i < len(rest); i++ {
		if rest[i] != '"' {
			continue
		}
		slashes := 0
		for j := i - 1; j >= 0 && rest[j] == '\\'; j-- {
			slashes++
		}
		if slashes%2 == 1 {
			continue
		}
		if strings.HasPrefix(rest[i:], "\": ") {
			return rest[i+3:]
		}
		return reason
	}
	return reason
}

// IsQueryEntropyResult reports whether an entropy finding came from a query
// key or value. ScannerEntropy intentionally remains the shared audit/metrics
// layer; this predicate gives public reason-code and remediation consumers the
// narrower gate identity without parsing broad prose fragments independently.
func IsQueryEntropyResult(result Result) bool {
	return result.Scanner == ScannerEntropy && isQueryEntropyReason(stripNestedURLReasonPrefix(result.Reason))
}

func isQueryEntropyReason(reason string) bool {
	return strings.HasPrefix(reason, queryEntropyKeyReasonPrefix) ||
		strings.HasPrefix(reason, queryEntropyParamReasonPrefix)
}

// GuidanceForResultWithPatterns uses exact structured finding names when the
// caller has them, without interpreting display text as a pattern identifier.
func GuidanceForResultWithPatterns(label, reason string, patterns []string) (RemediationGuidance, bool) {
	structured := false
	for _, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			continue
		}
		structured = true
		if (TextDLPMatch{PatternName: pattern}).IsInspectionLimit() {
			return jsonInspectionLimitGuidance(), true
		}
	}
	if structured {
		return guidanceForResult(label, reason)
	}
	return GuidanceForResult(label, reason)
}

func jsonInspectionLimitGuidance() RemediationGuidance {
	return RemediationGuidance{
		OperatorKnob: "Reduce nesting or number size in the JSON payload at its source. Typed JSON number and depth limits are fixed; incomplete inspection is refused.",
		Immutable:    true,
		AgentReason:  "Request blocked: the JSON payload exceeds a fixed inspection limit.",
	}
}

// These formats are emitted by the URL scanner, HTTP body gates, A2A scanning,
// and HTTP/MCP fragment reassembly. Other reason text is not a pattern-name
// authority.
func isJSONInspectionLimitReason(label, reason string) bool {
	switch label {
	case AuditA2AScan, AuditA2AHeader, AuditA2AResponse:
		// A2A joins generated finding parts with "; " after "a2a: "; only the
		// DLP part lists pattern names.
		if parts, ok := strings.CutPrefix(reason, "a2a: "); ok {
			for part := range strings.SplitSeq(parts, "; ") {
				if names, ok := strings.CutPrefix(part, "DLP: "); ok {
					return jsonInspectionLimitInNames(names)
				}
				// Only generated URL counts and injection pattern names can
				// precede DLP in buildA2AReason. Parser errors can quote a
				// client-chosen key containing the same part delimiter.
				if strings.HasPrefix(part, "injection: ") {
					continue
				}
				if count, ok := strings.CutSuffix(part, " URL/SSRF finding(s)"); ok {
					if n, err := strconv.Atoi(count); err == nil && n > 0 {
						continue
					}
				}
				return false
			}
		}
	case ScannerBodyDLP:
		if names, ok := strings.CutPrefix(reason, "request body contains secret: "); ok {
			return jsonInspectionLimitInNames(names)
		}
	case ScannerDLP, ScannerCoreDLP:
		for _, prefix := range []string{"DLP match: ", "core DLP match: ", "DLP: "} {
			if names, ok := strings.CutPrefix(reason, prefix); ok {
				// URL DLP emits severity; WebSocket DLP emits names only,
				// optionally followed by its adaptive-enforcement annotation.
				names = strings.TrimSuffix(names, " (high)")
				names = strings.TrimSuffix(names, " (escalated)")
				return jsonInspectionLimitInNames(names)
			}
		}
	case AuditCrossRequestFragment:
		return reason == "cross-request fragment inspection limit exceeded" || reason == "fragment reassembly DLP match: "+UninspectableJSONNumberPattern ||
			reason == "cross-request fragment refused: "+UninspectableJSONNumberPattern+"; reduce nesting or number size in the JSON tool arguments at their source (typed JSON number and depth limits are fixed)"
	}
	return false
}

func jsonInspectionLimitInNames(names string) bool {
	for name := range strings.SplitSeq(names, ", ") {
		if name == UninspectableJSONNumberPattern {
			return true
		}
	}
	return false
}

func GuidanceForResult(label, reason string) (RemediationGuidance, bool) {
	// Generic events retain only the emitted reason. Strip client-chosen query
	// keys before recognizing the closed set of inspection-refusal formats.
	if isJSONInspectionLimitReason(label, stripNestedURLReasonPrefix(reason)) {
		return jsonInspectionLimitGuidance(), true
	}
	return guidanceForResult(label, reason)
}

// hasQueryGrantValidityNote recognizes only a terminal annotation emitted by
// queryGrantValidityNote. Pattern names precede the severity and audience
// explanations end in a closing parenthesis, so neither supplies this suffix.
func hasQueryGrantValidityNote(reason string) bool {
	if !strings.HasPrefix(reason, "DLP match: ") {
		return false
	}
	for _, note := range []string{
		githubDownloadGrantValidityNote,
		githubDownloadSASValidityNote,
		githubAttestationValidityNote,
		githubActionsValidityNote,
	} {
		if strings.HasSuffix(reason, "; "+note) {
			return true
		}
	}
	return false
}

func guidanceForResult(label, reason string) (g RemediationGuidance, ok bool) {
	nested := reason
	reason = stripNestedURLReasonPrefix(reason)
	if label == AuditContract && reason == "MCP contract evaluation failed" {
		return RemediationGuidance{
			OperatorKnob: "The live-lock contract could not be evaluated. Restore the active contract loader or correct the invalid contract state and retry; changing a rule's allow/block action does not repair an evaluation failure.",
			AgentReason:  auditRuntimeAgentReason,
		}, true
	}
	if label == AuditA2AScan {
		switch reason {
		case "A2A input could not be inspected":
			return RemediationGuidance{OperatorKnob: "Restore A2A input inspection or correct the uninspectable payload and retry; `a2a_scanning.action` does not override a failed inspection.", AgentReason: auditRuntimeAgentReason}, true
		case "A2A input URL check refused":
			return RemediationGuidance{OperatorKnob: "Check the underlying URL rule or resolver before retrying. Non-critical URL refusals follow `a2a_scanning.action`; cloud metadata and core-critical destination blocks remain enforced.", AgentReason: auditRuntimeAgentReason}, true
		case "A2A input inspection budget exceeded":
			return RemediationGuidance{OperatorKnob: "Reduce the A2A payload complexity or inspect `a2a_scanning.action`, which governs this budget-only refusal after fallback scanning.", AgentReason: auditRuntimeAgentReason}, true
		case "A2A input configuration mismatch":
			return RemediationGuidance{OperatorKnob: "Check the A2A input configuration and the underlying URL or SSRF rule before retrying. Changing `a2a_scanning.action` does not repair a configuration mismatch.", AgentReason: auditRuntimeAgentReason}, true
		}
	}
	// MCP listener admission, protocol and capacity refusals and upstream batch
	// responses share this label with batch requests. Sending one request at a
	// time repairs only a batch request, so each other refusal names its own
	// inputs. The batch-request reason keeps the label's table entry.
	if label == AuditMCPProtocol {
		switch reason {
		case "MCP batch responses are unsupported":
			return RemediationGuidance{OperatorKnob: "The upstream MCP server answered with a JSON-RPC batch. Batch responses are unsupported and no scanner or policy setting enables them; correct the upstream server.", Immutable: true, AgentReason: auditRuntimeAgentReason}, true
		case "MCP listener admission refused":
			return RemediationGuidance{OperatorKnob: "The MCP listener refused the exchange. Check the client's Origin, Host, listener credential, HTTP method and Pipelock session token against the listener configuration, including `mcp_session_binding.listener_require_state_token`.", Immutable: true, AgentReason: auditRuntimeAgentReason}, true
		case "MCP listener protocol refused":
			return RemediationGuidance{OperatorKnob: "The MCP listener refused a malformed or inconsistent request. Correct the client's MCP headers, protocol version or JSON-RPC body; no scanner or policy setting relaxes protocol validation.", Immutable: true, AgentReason: auditRuntimeAgentReason}, true
		case "MCP listener client-registry capacity exhausted (4096 clients); wait for listener idle expiry (24h) or session end":
			return RemediationGuidance{OperatorKnob: "The MCP listener reached its fixed 4,096-client registry limit. Retained clients free a slot on listener idle expiry (24h) or session end; increasing `session_profiling.max_sessions` does not raise this registry limit. Configure authenticated principal state to bind one principal to one slot.", Immutable: true, AgentReason: auditRuntimeAgentReason}, true
		case "MCP listener state capacity exhausted":
			return RemediationGuidance{OperatorKnob: "Listener client state is at capacity. Retry after an existing state expires; when the session store is full, increase `session_profiling.max_sessions` or clear the restriction that keeps a session from being dropped.", Immutable: true, AgentReason: auditRuntimeAgentReason}, true
		case "session capacity exhausted; wait for session recovery or increase max_sessions":
			return RemediationGuidance{OperatorKnob: "Session capacity is exhausted and every retained session carries airlock, adaptive escalation, `block_all` or policy taint. Increase `session_profiling.max_sessions` or clear the restriction; reset and terminate keep taint, which a new task boundary clears.", Immutable: true, AgentReason: auditRuntimeAgentReason}, true
		}
	}
	if (label == ScannerMCPToolScanning || label == AuditToolScanning) && strings.HasPrefix(reason, "tools/list cannot be safely inspected:") {
		return RemediationGuidance{
			OperatorKnob: "The tools/list inventory cannot be safely inspected or admitted into the current baseline. Correct or reduce the upstream inventory and retry; `mcp_tool_scanning.action` does not override this refusal.",
			AgentReason:  auditRuntimeAgentReason,
		}, true
	}
	if label == ScannerDLP && hasQueryGrantValidityNote(reason) {
		return RemediationGuidance{
			OperatorKnob: "Check the host clock and obtain a current GitHub URL. The grant validity window is required and is not extended by a DLP pattern exemption.",
			Immutable:    true,
			AgentReason:  "Request blocked: the GitHub grant is outside its validity window.",
		}, true
	}
	defer func() {
		if ok {
			g = annotateNestedURLGuidance(g, label, nested, reason)
		}
	}()
	// Some transports retain historical audit labels for the same enforcing
	// family. Normalize them before reason routing so alternate labels cannot
	// drift to a less accurate hint.
	switch label {
	case AuditTLSResponseBlocked:
		label = AuditResponseScan
	case AuditBudgetTruncated:
		label = AuditAgentBudget
	case AuditSessionDeny:
		label = AuditAdaptiveEnforcement
	case AuditA2AHeader, AuditA2AResponse:
		label = AuditA2AScan
	}

	// Most scanner labels have static guidance. Return before normalizing the
	// reason so hot-path blocks such as URL length do not allocate a lowercase
	// copy that no branch will inspect.
	switch label {
	case AuditKillSwitch:
		if reason == "conductor_apply_failure" {
			return RemediationGuidance{
				OperatorKnob: "Restore the failed policy-application prerequisite and retry a valid Conductor policy, or restart to re-verify cached policy. `kill_switch.allowlist_ips` doesn't exempt unresolved policy application.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		}
		return GuidanceFor(label)
	case AuditCrossRequestEntropy,
		AuditResponseScan,
		AuditMediaPolicy,
		AuditRequestPolicy,
		AuditReverseSubmit,
		AuditRedaction,
		AuditA2AScan,
		AuditAgentBudget,
		AuditSessionAnomaly,
		ScannerEntropy,
		ScannerDenialOfWallet,
		ScannerSSRF,
		ScannerSSRFMetadata,
		ScannerCoreSSRF:
		// These labels route on reason below.
	default:
		return GuidanceFor(label)
	}

	lowerReason := strings.ToLower(reason)
	if label == AuditCrossRequestEntropy && strings.Contains(lowerReason, "cross-request entropy") {
		return RemediationGuidance{
			OperatorKnob: "For MCP cross-request entropy, raise `cross_request_detection.entropy_budget.bits_per_window` if the session-wide volume is expected. Changing `cross_request_detection.entropy_budget.action` to `warn` affects every MCP entropy-budget finding. The MCP gate does not consult `entropy_budget.exempt_domains`.",
			AgentReason:  auditAnomalyAgentReason,
		}, true
	}
	if label == AuditResponseScan {
		switch {
		case reason == "response scan parse error in MCP parameter header":
			return RemediationGuidance{
				OperatorKnob: "The decoded MCP parameter header could not be scanned. Inspect scanner health and retry; a `suppress:` entry cannot make the header scannable.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		case reason == "response scan cannot be scanned: response scanner unavailable":
			return RemediationGuidance{
				OperatorKnob: "The MCP response scanner is unavailable. Investigate scanner initialization and retry only when it is operational; policy suppression cannot provide the missing scan.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		case reason == "response scan returned an incomplete verdict":
			return RemediationGuidance{
				OperatorKnob: "The MCP response scan returned a non-clean verdict without a pattern finding. Investigate the scan result before retrying; a pattern suppression has no identified match to change.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		case strings.Contains(lowerReason, "compressed"),
			strings.Contains(lowerReason, "read error"),
			strings.Contains(lowerReason, "read_error"),
			strings.Contains(lowerReason, "cannot be scanned"),
			strings.Contains(lowerReason, "parse error"),
			strings.Contains(lowerReason, "parse_error"):
			return RemediationGuidance{
				OperatorKnob: "This is a scan-integrity failure, not a pattern false positive: correct the compressed, unreadable, or malformed upstream response and retry. A `suppress:` entry cannot make content scannable; `response_scanning.exempt_domains` would disable scanning for every response from the host and is not a narrow fix.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		case strings.Contains(lowerReason, "size-exempt response scan") && strings.Contains(lowerReason, "inflight"):
			return RemediationGuidance{
				OperatorKnob: "Raise `response_scanning.size_exempt_scan_max_inflight_bytes` only if this proxy instance has enough memory for the larger aggregate reservation. The in-flight admission gate reads that field directly.",
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		case strings.Contains(lowerReason, "size-exempt response"):
			return RemediationGuidance{
				OperatorKnob: "Use `response_scanning.size_exempt_scan_limits` for an expiring exact-host scanned ceiling. Raising `response_scanning.size_exempt_scan_max_bytes` changes every size-exempt host. `response_scanning.unscannable_passthrough` is a broader, explicit visibility gap for deliberately opaque content.",
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		case strings.Contains(lowerReason, "response size"),
			strings.Contains(lowerReason, "scan ceiling"),
			strings.Contains(lowerReason, "oversized"):
			return RemediationGuidance{
				OperatorKnob: responseSizeOperatorKnob,
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		}
	}
	if label == AuditMediaPolicy {
		operatorKnob := ""
		switch {
		case strings.Contains(lowerReason, "audio stripped"):
			operatorKnob = "If this agent intentionally consumes audio, set `media_policy.strip_audio: false`. This permits all otherwise-allowed audio types because Pipelock cannot inspect instructions embedded in audio."
		case strings.Contains(lowerReason, "video stripped"):
			operatorKnob = "If this agent intentionally consumes video, set `media_policy.strip_video: false`. This permits all otherwise-allowed video types because Pipelock cannot inspect instructions embedded in video."
		case strings.Contains(lowerReason, "images stripped"):
			operatorKnob = "If this agent intentionally consumes images, set `media_policy.strip_images: false`; keep `allowed_image_types`, metadata stripping, and `max_image_bytes` constrained."
		case strings.Contains(lowerReason, "not in allowed list"):
			operatorKnob = "After verifying the format is required and non-active, add only that exact image media type to `media_policy.allowed_image_types`. SVG remains unsupported because it is active content."
		case strings.Contains(lowerReason, "exceeds limit"):
			operatorKnob = "Raise `media_policy.max_image_bytes` only to the largest verified image size the agent needs; the limit is the decompression-bomb and memory ceiling."
		case strings.Contains(lowerReason, "parse error"),
			strings.Contains(lowerReason, "re-marshal"),
			strings.Contains(lowerReason, "read error"):
			operatorKnob = "The media could not be parsed or transported safely. Correct the malformed media/upstream response and retry; there is no exemption knob for forwarding an unvalidated media payload."
		}
		if operatorKnob != "" {
			return RemediationGuidance{OperatorKnob: operatorKnob, AgentReason: auditPolicyAgentReason}, true
		}
	}
	if label == AuditRequestPolicy {
		switch {
		case strings.Contains(lowerReason, "exceeds max_body_bytes"):
			return RemediationGuidance{
				OperatorKnob: "Raise `request_body_scanning.max_body_bytes` only to the largest verified request body this route needs; request-policy body predicates consume that same bounded-read ceiling.",
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		case strings.Contains(lowerReason, "could not be inspected"):
			return RemediationGuidance{
				OperatorKnob: "The request body could not be read and therefore cannot be forwarded intact. Correct the client/body stream and retry; `request_policy.on_parse_error` does not control read failures and no exemption can restore consumed bytes.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		}
	}
	if label == AuditReverseSubmit {
		switch {
		case strings.Contains(lowerReason, "not in allowed_methods"):
			return RemediationGuidance{
				OperatorKnob: "If this method is intentionally accepted by the submit listener, add only that method to `reverse_proxy.allowed_methods`; this gate reads that list before any scanner work.",
				AgentReason:  auditPolicyAgentReason,
			}, true
		case strings.Contains(lowerReason, "not in allowed_paths"):
			return RemediationGuidance{
				OperatorKnob: "If this exact canonical path is intentional, add only it under `reverse_proxy.allowed_paths[].exact`; prefix and regex exemptions are not supported.",
				AgentReason:  auditPolicyAgentReason,
			}, true
		case strings.Contains(lowerReason, "body exceeds"), strings.Contains(lowerReason, "body cap"):
			return RemediationGuidance{
				OperatorKnob: "Raise the smaller active body ceiling: `reverse_proxy.max_body_bytes` or `request_body_scanning.max_body_bytes`. The submit gate enforces their minimum before forwarding.",
				AgentReason:  protectiveCeilingAgentReason,
			}, true
		case strings.Contains(lowerReason, "raw path"), strings.Contains(lowerReason, "path is not canonical"):
			return RemediationGuidance{
				OperatorKnob: "Send the canonical decoded path without encoded traversal, encoded separators, semicolon parameters, or dot segments. This fail-closed path check has no exemption knob.",
				AgentReason:  auditPolicyAgentReason,
			}, true
		}
	}
	if label == AuditRedaction && strings.Contains(lowerReason, "non_json_body") {
		return RemediationGuidance{
			OperatorKnob: "If this exact non-JSON route is intentionally safe to forward without redaction, add the narrow host/path match to `redaction.allowlist_unparseable_routes`. `redaction.allowlist_unparseable` is the broader host-wide fallback. Both paths forward the body unredacted, so verify it cannot carry the protected value first.",
			AgentReason:  auditRuntimeAgentReason,
		}, true
	}
	if label == AuditA2AScan {
		switch {
		case strings.Contains(lowerReason, "invalid json"),
			strings.Contains(lowerReason, "duplicate json"),
			strings.Contains(lowerReason, "maximum inspectable nesting"),
			strings.Contains(lowerReason, "could not be read"),
			strings.Contains(lowerReason, "request body exceeds"):
			return RemediationGuidance{
				OperatorKnob: "Correct the malformed, unreadable, oversized, or uninspectable A2A payload and retry. This structural fail-closed path does not consult `a2a_scanning.action` and has no exemption knob.",
				AgentReason:  auditRuntimeAgentReason,
			}, true
		case strings.Contains(lowerReason, "hostname exfiltration"):
			return RemediationGuidance{
				OperatorKnob: "Remove the secret-like hostname payload. A2A hostname-exfiltration is a hard block and does not consult `a2a_scanning.action`; there is no A2A suppression knob.",
				AgentReason:  auditContentAgentReason,
			}, true
		case strings.Contains(lowerReason, "url/ssrf finding"):
			return RemediationGuidance{
				OperatorKnob: "Correct the embedded URL or remediate the underlying URL/SSRF scanner finding. Do not rely on `a2a_scanning.action`: hostname-exfiltration URL findings hard-block before that field is consulted.",
				AgentReason:  auditContentAgentReason,
			}, true
		case strings.Contains(lowerReason, "payload exceeded node budget"),
			strings.Contains(lowerReason, "a2a-extensions header"),
			strings.Contains(lowerReason, "injection:"),
			strings.Contains(lowerReason, "dlp:"),
			strings.Contains(lowerReason, "agent card drift"):
			return RemediationGuidance{
				OperatorKnob: "Correct the flagged A2A content. If this non-structural finding is intentionally audit-only, set `a2a_scanning.action: warn`; this path derives its effective action from that field.",
				AgentReason:  auditContentAgentReason,
			}, true
		}
	}
	if label == AuditAgentBudget {
		operatorKnob := ""
		switch {
		case strings.Contains(lowerReason, "request budget"):
			operatorKnob = "Raise only `agents.<name>.budget.max_requests_per_session` if the session's request count is expected."
		case strings.Contains(lowerReason, "domain budget"):
			operatorKnob = "Raise only `agents.<name>.budget.max_unique_domains_per_session` if the session's destination diversity is expected."
		case strings.Contains(lowerReason, "byte budget"):
			operatorKnob = "Raise only `agents.<name>.budget.max_bytes_per_session` if the session's response volume is expected."
		}
		if operatorKnob != "" {
			return RemediationGuidance{OperatorKnob: operatorKnob, AgentReason: protectiveCeilingAgentReason}, true
		}
	}
	if label == AuditSessionAnomaly {
		switch {
		case strings.Contains(lowerReason, "baseline_deviation"):
			return RemediationGuidance{
				OperatorKnob: "Inspect the behavioral profile with `pipelock baseline show <agent>`. If the new behavior is legitimate, deliberately relearn and ratify it with the baseline operator commands; do not enable `behavioral_baseline.auto_ratify` to silence an unexplained deviation.",
				AgentReason:  auditAnomalyAgentReason,
			}, true
		case strings.Contains(lowerReason, "domain_burst"):
			return RemediationGuidance{
				OperatorKnob: "Raise the matched `session_profiling.domain_burst` threshold (global or `agents.<name>.session_profiling.domain_burst`) or adjust the global-only `session_profiling.window_minutes` if this destination burst is expected.",
				AgentReason:  auditAnomalyAgentReason,
			}, true
		}
	}
	if label == ScannerEntropy && isQueryEntropyReason(reason) {
		knob := queryEntropyOperatorKnob
		if strings.HasPrefix(reason, queryEntropyKeyReasonPrefix) {
			// Parameter exclusions skip only value entropy, so a key finding
			// needs the host-wide exclusion.
			knob = queryEntropyKeyOperatorKnob
		}
		return RemediationGuidance{
			OperatorKnob:    knob,
			OperatorBroader: queryEntropyOperatorBroader,
			AgentReason:     highEntropyAgentReason,
		}, true
	}
	if label == ScannerDenialOfWallet {
		operatorKnob := ""
		switch {
		case strings.Contains(reason, "tool call limit exceeded"):
			operatorKnob = denialOfWalletToolCallsOperatorKnob
		case strings.Contains(reason, "wall clock budget exceeded"):
			operatorKnob = denialOfWalletWallClockOperatorKnob
		case strings.Contains(reason, "loop detected"):
			operatorKnob = denialOfWalletRetriesOperatorKnob
		}
		if operatorKnob != "" {
			return RemediationGuidance{
				OperatorKnob: operatorKnob,
				AgentReason:  denialOfWalletAgentReason,
			}, true
		}
	}
	// The dial-time SSRF guard logs metadata blocks under the generic
	// ScannerSSRF label (the metadata classification lives in the reason
	// string), and non-metadata link-local/multicast blocks use the same generic
	// label with "non-overridable" in the reason. A label-only lookup would hand
	// back the ssrfOperatorKnob that names ssrf.ip_allowlist/trusted_domains -
	// knobs that cannot exempt these targets. Route those reason-specific SSRF
	// blocks to the non-overridable guidance regardless of which SSRF label
	// carried them.
	// A nested-destination timeout is an availability condition wearing an SSRF
	// label. Route it before the SSRF knobs below, which would otherwise offer
	// ssrf.ip_allowlist and trusted_domains for a block no allowlist can lift.
	if strings.Contains(reason, nestedURLBudgetReason) {
		return RemediationGuidance{
			OperatorKnob: nestedURLBudgetOperatorKnob,
			AgentReason:  nestedURLBudgetAgentReason,
		}, true
	}
	if label == ScannerSSRF || label == ScannerSSRFMetadata || label == ScannerCoreSSRF {
		if strings.Contains(reason, "metadata") {
			return RemediationGuidance{
				OperatorKnob: ssrfMetadataOperatorKnob,
				Immutable:    true,
				AgentReason:  protectedAddressAgentReason,
			}, true
		}
		if strings.Contains(reason, "non-overridable") {
			return RemediationGuidance{
				OperatorKnob: ssrfNonOverridableOperatorKnob,
				Immutable:    true,
				AgentReason:  protectedAddressAgentReason,
			}, true
		}
	}
	return GuidanceFor(label)
}

// nestedURLBudgetReason is the substring that identifies a nested-destination
// resolution timeout. Guidance for it must never name an allowlist: no allowlist
// entry makes a resolver answer faster, and naming one teaches an operator that
// policy changed when nothing did.
const nestedURLBudgetReason = "shared resolution budget"

const nestedURLBudgetOperatorKnob = "Nested query destinations could not be resolved within the shared resolution budget, so the request was refused with a destination left unverified. This is resolver availability, not detection: check resolver health and latency for the hostnames named in the request. To stop evaluating query-parameter destinations entirely, set `fetch_proxy.monitoring.scan_nested_urls` to false."

const nestedURLBudgetAgentReason = "a destination named inside this request could not be verified in time"

func annotateNestedURLGuidance(g RemediationGuidance, label, reason, stripped string) RemediationGuidance {
	// A resolution timeout already carries its own guidance and must not be
	// annotated with the destination-knob sentence: no allowlist lifts a timeout.
	// Test the STRIPPED reason, never the raw one. The raw reason still carries
	// the query key, which the client chooses, so matching on it let a parameter
	// named after the budget suppress the sentence on a genuine destination block.
	if !containsLowerASCII(reason, "nested url in query parameter") {
		return g
	}
	if containsLowerASCII(stripped, nestedURLBudgetReason) {
		return g
	}
	nestedKnob := " Nested query destinations are evaluated because `fetch_proxy.monitoring.scan_nested_urls` is enabled (nil/true). Set it false only for an endpoint whose contract legitimately carries private or blocklisted URLs in query strings." +
		" For a literal loopback `redirect_uri` on a native OAuth authorization-code GET, an exact `fetch_proxy.monitoring.oauth_authorization_endpoints` grant is narrower than disabling nested URL scanning."
	switch label {
	case ScannerSSRF, ScannerCoreSSRF:
		if !g.Immutable {
			nestedKnob += " The nested host consults `ssrf.ip_allowlist`, `trusted_domains`, and `dns.host_overrides` because it reuses the same destination checks as the outer host."
		}
	}
	g.OperatorKnob += nestedKnob
	return g
}

// containsLowerASCII matches a lowercase ASCII phrase without allocating a
// lowercase copy of ordinary diagnostic text. Non-ASCII input retains the
// strings.ToLower mapping used by guidance, including Unicode case mappings.
func containsLowerASCII(text, phrase string) bool {
	if phrase == "" {
		return true
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 0x80 {
			return strings.Contains(strings.ToLower(text), phrase)
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != phrase[0] || len(text)-i < len(phrase) {
			continue
		}
		matched := true
		for j := 1; j < len(phrase); j++ {
			c = text[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != phrase[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// OperatorHintForResult is OperatorHintFor with Reason-based disambiguation. Use
// it wherever the scan Reason is in hand (audit, block responses) so a
// query-entropy block gets the query-entropy knob rather than the path default.
func OperatorHintForResult(label, reason string) string {
	g, _ := GuidanceForResult(label, reason)
	return g.OperatorKnob
}

// OperatorHintForPatterns preserves structured pattern identity for audit callers.
func OperatorHintForPatterns(label string, patterns []string) string {
	g, _ := GuidanceForResultWithPatterns(label, strings.Join(patterns, ", "), patterns)
	return g.OperatorKnob
}
