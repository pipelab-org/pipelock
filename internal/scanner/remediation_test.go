// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMCPHeaderGuidanceNamesActualScanControls(t *testing.T) {
	dlp, ok := guidanceForResult(AuditMCPHeaderDLP, "test credential")
	if !ok {
		t.Fatal("MCP header DLP guidance missing")
	}
	for _, want := range []string{
		"listener request header", "text DLP", "Authorization", "Last-Event-ID", "Mcp-Param-*", "Mcp-Session-Id",
		"request_body_scanning.scan_headers", "header_mode", "sensitive_headers", "ignore_headers",
	} {
		if !strings.Contains(dlp.OperatorKnob, want) {
			t.Errorf("MCP header DLP guidance omitted %q: %s", want, dlp.OperatorKnob)
		}
	}
	injection, ok := guidanceForResult(AuditMCPHeaderInjection, "test instruction")
	if !ok || !strings.Contains(injection.OperatorKnob, "decoded Mcp-Param-*") ||
		!strings.Contains(injection.OperatorKnob, "response injection scanning") {
		t.Fatalf("MCP header injection guidance describes the wrong scan: %+v", injection)
	}
}

func TestGuidanceForResultPatternNameEndingInValidityNote(t *testing.T) {
	for _, note := range []string{githubDownloadGrantValidityNote, githubDownloadSASValidityNote, githubAttestationValidityNote, githubActionsValidityNote} {
		t.Run(note, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.Patterns = []config.DLPPattern{{
				Name: "Provider Key; " + note, Regex: `testcredential[a-z]{12}`, Severity: config.SeverityHigh,
				CredentialAudienceHosts: []string{"audience.example"},
			}}
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			result := sc.Scan(t.Context(), "https://api.vendor.example/?key=testcredential"+strings.Repeat("a", 12))
			if result.Allowed || result.Scanner != ScannerDLP || !strings.Contains(result.Reason, note) {
				t.Fatalf("expected the named DLP block, got %+v", result)
			}
			got, ok := GuidanceForResult(result.Scanner, result.Reason)
			if !ok || strings.Contains(got.OperatorKnob, "host clock") || strings.Contains(result.Hint, "validity window") {
				t.Fatalf("pattern name selected validity guidance: result=%+v guidance=%+v", result, got)
			}
		})
	}
}

func TestGuidanceForResultAudienceMetadataIsNotGrantValidity(t *testing.T) {
	for _, name := range []string{
		"Provider Key; GitHub grant outside its validity window",
		"Provider Key; GitHub download grant outside its validity window; check the host clock or obtain a current download URL",
	} {
		mismatches := []CredentialAudienceMismatch{{
			PatternName: name,
			Surface:     "url",
			Destination: "api.vendor.example",
		}}
		reason := "DLP match: " + name + " (high); " + CredentialAudienceMismatchExplanation(mismatches)
		for _, reason := range []string{reason, "DLP match: " + name + " (high)", "DLP: " + name} {
			got, ok := GuidanceForResult(ScannerDLP, reason)
			want, wantOK := GuidanceFor(ScannerDLP)
			if !ok || !wantOK || got != want {
				t.Fatalf("metadata changed guidance: got=%+v want=%+v", got, want)
			}
		}
	}
}

func TestGuidanceForResultGrantValidityAnnotation(t *testing.T) {
	for _, note := range []string{
		"GitHub download grant outside its validity window; check the host clock or obtain a current download URL",
		"GitHub download SAS outside its validity window; check the host clock or obtain a current download URL",
		"GitHub attestation SAS outside its validity window; check the host clock or obtain a current bundle URL",
		"GitHub Actions results SAS outside its validity window; check the host clock or obtain a current log or artifact URL",
	} {
		reason := "DLP match: JWT Token (high); credential audience mismatch (pattern JWT Token, surface url, canonical destination api.vendor.example); " + note
		got, ok := GuidanceForResult(ScannerDLP, reason)
		if !ok || !got.Immutable || !strings.Contains(got.OperatorKnob, "host clock") {
			t.Fatalf("validity annotation lost guidance: reason=%q got=%+v", reason, got)
		}
		for _, invalid := range []string{"DLP: " + note, reason + ")", reason + " trailing metadata"} {
			got, ok := GuidanceForResult(ScannerDLP, invalid)
			if !ok || strings.Contains(got.OperatorKnob, "host clock") {
				t.Fatalf("non-annotation changed guidance: reason=%q got=%+v", invalid, got)
			}
		}
	}
}

func TestRemediationGuidanceCoversAllLabels(t *testing.T) {
	// The canonical set of block labels a scanner emits. Every one must have
	// guidance, and the guidance table must not carry a label outside this set,
	// so a new scanner label without guidance (or a stray table entry) fails CI.
	labels := []string{
		ScannerBlocklist,
		ScannerDLP,
		ScannerEntropy,
		ScannerSubdomainEntropy,
		ScannerSSRF,
		ScannerSSRFMetadata,
		ScannerRateLimit,
		ScannerLength,
		ScannerDataBudget,
		ScannerScheme,
		ScannerAllowlist,
		ScannerParser,
		ScannerContext,
		ScannerCRLF,
		ScannerPathTraversal,
		ScannerCoreDLP,
		ScannerCoreSSRF,
		ScannerCoreResponse,
		ScannerBodyDLP,
		AuditBodyEntropy,
		ScannerDenialOfWallet,
		AuditResponseScan,
		AuditHeaderDLP,
		AuditReverseURLDLP,
		AuditBodyPromptInjection,
		AuditAddressProtection,
		AuditChainDetection,
		AuditProvenance,
		AuditMediaPolicy,
		AuditRequestPolicy,
		AuditAgentIdentity,
		AuditTaintPolicy,
		AuditSessionAnomaly,
		AuditAdaptiveEnforcement,
		AuditMCPSessionBinding,
		AuditMCPToolPolicy,
		ScannerMCPToolScanning,
		AuditToolScanning,
		AuditMCPInputDLP,
		AuditMCPInputInjection,
		AuditMCPInputInspection,
		AuditMCPHeaderDLP,
		AuditMCPHeaderInjection,
		AuditMCPHeaderInspection,
		AuditMCPResponseInspection,
		AuditMCPProtocol,
		AuditMCPRedirect,
		AuditMCPRedirectOutputDLP,
		AuditMCPRedirectOutputInjection,
		AuditMCPDefer,
		AuditFrozenTool,
		AuditSNIMismatch,
		AuditKillSwitch,
		AuditAirlock,
		AuditCrossRequestEntropy,
		AuditCrossRequestFragment,
		AuditCrossRequestFragmentOwnerMismatch,
		AuditCrossRequestFragmentCapacity,
		AuditGitProtection,
		AuditAgentBudget,
		AuditResponseSize,
		AuditShieldOversize,
		AuditContract,
		AuditSSEStream,
		AuditUnscannable,
		AuditA2AScan,
		AuditA2ACardSignature,
		AuditRedaction,
		AuditScannerUnavailable,
		AuditMediationEnvelope,
		AuditReceiptEmission,
		AuditReverseSubmit,
		AuditA2AHeader,
		AuditA2AResponse,
		AuditBudgetTruncated,
		AuditTLSResponseBlocked,
		AuditSessionDeny,
		AuditTLSHandshakeError,
		AuditTLSAuthorityMismatch,
		DecideInjectionLabel,
		DecidePolicyLabel,
		DecideStructuralLabel,
	}

	labelSet := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		labelSet[label] = struct{}{}
		t.Run(label, func(t *testing.T) {
			if _, ok := remediationGuidance[label]; !ok {
				t.Fatalf("remediationGuidance missing label %q", label)
			}
		})
	}

	for label := range remediationGuidance {
		if _, ok := labelSet[label]; !ok {
			t.Errorf("remediationGuidance has label %q not enumerated in the canonical block-label set", label)
		}
	}

	routed := []struct {
		name      string
		label     string
		reason    string
		want      string
		immutable bool
	}{
		{"cross-request entropy", AuditCrossRequestEntropy, "cross-request entropy exceeded", "bits_per_window", false},
		{"response integrity", AuditResponseScan, "compressed response cannot be scanned", "scan-integrity failure", false},
		{"media policy", AuditMediaPolicy, "image exceeds limit", "decompression-bomb", false},
		{"request policy", AuditRequestPolicy, "body exceeds max_body_bytes", "request_body_scanning.max_body_bytes", false},
		{"reverse submit", AuditReverseSubmit, "method not in allowed_methods", "add only that method", false},
		{"redaction", AuditRedaction, "non_json_body", "allowlist_unparseable_routes", false},
		{"a2a", AuditA2AScan, "invalid JSON", "no exemption knob", false},
		{"agent budget", AuditAgentBudget, "request budget exceeded", "request count is expected", false},
		{"session anomaly", AuditSessionAnomaly, "baseline_deviation", "baseline show", false},
		{"query entropy", ScannerEntropy, `high entropy query param "sig"`, "query_entropy_param_exclusions", false},
		{"denial of wallet", ScannerDenialOfWallet, "tool call limit exceeded", "max_tool_calls_per_session", false},
		{"ssrf metadata", ScannerSSRF, "metadata endpoint blocked", "non-overridable SSRF deny", true},
		{"ssrf metadata label", ScannerSSRFMetadata, "metadata endpoint blocked", "non-overridable SSRF deny", true},
		{"core ssrf metadata", ScannerCoreSSRF, "metadata endpoint blocked", "non-overridable SSRF deny", true},
		{"static dlp", ScannerDLP, "reason is irrelevant", "dlp.patterns[].exempt_domains", false},
	}
	for _, tt := range routed {
		t.Run("routing/"+tt.name, func(t *testing.T) {
			got, ok := GuidanceForResult(tt.label, tt.reason)
			if !ok {
				t.Fatalf("GuidanceForResult(%q) not found", tt.label)
			}
			if !strings.Contains(got.OperatorKnob, tt.want) || got.Immutable != tt.immutable {
				t.Fatalf("GuidanceForResult(%q, %q) = %#v, want knob containing %q immutable=%v", tt.label, tt.reason, got, tt.want, tt.immutable)
			}
		})
	}
}

func TestRemediationGuidanceAgentReasonsAreNonProcedural(t *testing.T) {
	forbidden := []string{
		// Procedural verbs — an AgentReason must state WHY, never HOW to change
		// policy (that is the operator's job and teaches self-unblock).
		"add",
		"set",
		"disable",
		"exempt",
		"suppress",
		"remove",
		"raise",
		"lower",
		"edit",
		"change",
		"modify",
		"tune",
		"adjust",
		"enable",
		"threshold",
		// Config knobs / paths — naming any of these hands the agent a self-unblock lever.
		"allowlist",
		"exempt_domains",
		"passthrough",
		".yaml",
		"dlp.patterns",
		"api_allowlist",
		"config",
		"trusted_domains",
		"ip_allowlist",
		"fetch_proxy",
		"monitoring.",
		"suppress:",
		// Containment-posture mechanism names — telling a blocked agent whether it
		// is in blocklist mode or strict-allowlist mode is recon about how boxed-in
		// it is. The operator learns the mechanism via OperatorKnob, not the agent.
		"blocklist",
		"strict",
		" mode",
	}

	for label, guidance := range remediationGuidance {
		t.Run(label, func(t *testing.T) {
			if guidance.AgentReason == "" {
				t.Fatal("AgentReason is empty")
			}
			if len(guidance.AgentReason) > 140 {
				t.Fatalf("AgentReason length = %d, want <= 140: %q", len(guidance.AgentReason), guidance.AgentReason)
			}

			lowerReason := strings.ToLower(guidance.AgentReason)
			for _, bad := range forbidden {
				if strings.Contains(lowerReason, bad) {
					t.Fatalf("AgentReason %q contains forbidden substring %q", guidance.AgentReason, bad)
				}
			}
		})
	}
}

func TestRemediationGuidanceOperatorFieldsPresent(t *testing.T) {
	for label, guidance := range remediationGuidance {
		t.Run(label, func(t *testing.T) {
			if guidance.OperatorKnob == "" {
				t.Fatal("OperatorKnob is empty")
			}
			if guidance.Immutable && guidance.OperatorBroader != "" {
				t.Fatalf("immutable guidance has OperatorBroader = %q, want empty", guidance.OperatorBroader)
			}
		})
	}
}

func TestGuidanceFor(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  RemediationGuidance
		ok    bool
	}{
		{
			name:  "known",
			label: ScannerDLP,
			want:  remediationGuidance[ScannerDLP],
			ok:    true,
		},
		{
			name:  "unknown",
			label: "nonexistent",
			want:  RemediationGuidance{},
			ok:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := GuidanceFor(tt.label)
			if ok != tt.ok {
				t.Fatalf("GuidanceFor(%q) ok = %v, want %v", tt.label, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("GuidanceFor(%q) = %#v, want %#v", tt.label, got, tt.want)
			}
		})
	}
}

func TestGuidanceForResultDisambiguatesEntropy(t *testing.T) {
	t.Run("query entropy uses the query knob", func(t *testing.T) {
		g, ok := GuidanceForResult(ScannerEntropy, `high entropy query param "sig"`)
		if !ok {
			t.Fatal("GuidanceForResult(entropy, query reason) not ok")
		}
		if !strings.Contains(g.OperatorKnob, "query_entropy_exclusions") {
			t.Fatalf("query-entropy knob = %q, want query_entropy_exclusions fallback", g.OperatorKnob)
		}
		if !strings.Contains(g.OperatorKnob, "query_entropy_param_exclusions") {
			t.Fatalf("query-entropy knob = %q, want query_entropy_param_exclusions first", g.OperatorKnob)
		}
		if OperatorHintForResult(ScannerEntropy, `high entropy query param "sig"`) != queryEntropyOperatorKnob {
			t.Fatal("OperatorHintForResult should return the query knob for a query value reason")
		}
		if OperatorHintForResult(ScannerEntropy, `high entropy query key "sig"`) != queryEntropyKeyOperatorKnob {
			t.Fatal("OperatorHintForResult should return the key knob for a query key reason")
		}
	})

	t.Run("classifier is exact and strips nested prefix", func(t *testing.T) {
		cases := []struct {
			reason string
			want   bool
		}{
			{`high entropy query param "sig" (4.50 > 4.00 threshold)`, true},
			{`high entropy query key "opaque" (4.50 > 4.00 threshold)`, true},
			{`high entropy path segment (4.50 > 4.00 threshold)`, false},
			{`nested URL in query parameter "redirect": high entropy query param "sig"`, true},
			{`nested URL in query parameter "query trap": high entropy path segment`, false},
			{`future query entropy prose`, false},
		}
		for _, tc := range cases {
			got := IsQueryEntropyResult(Result{Scanner: ScannerEntropy, Reason: tc.reason})
			if got != tc.want {
				t.Errorf("IsQueryEntropyResult(%q) = %v, want %v", tc.reason, got, tc.want)
			}
		}
	})

	t.Run("path entropy falls through to the table entry", func(t *testing.T) {
		g, _ := GuidanceForResult(ScannerEntropy, "high entropy path segment")
		if g != remediationGuidance[ScannerEntropy] {
			t.Fatalf("path-entropy guidance = %#v, want the table entry", g)
		}
	})

	t.Run("non-entropy label ignores the reason", func(t *testing.T) {
		g, _ := GuidanceForResult(ScannerDLP, "high entropy query param")
		if g != remediationGuidance[ScannerDLP] {
			t.Fatal("a non-entropy label must be reason-independent")
		}
	})

	t.Run("unknown label is fail-safe", func(t *testing.T) {
		if _, ok := GuidanceForResult("nonexistent", "query"); ok {
			t.Fatal("unknown label must return ok=false")
		}
	})
}

func TestOperatorHintForResultResolvesDenialOfWalletReasons(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		wantKnob string
	}{
		{
			name:     "tool call budget",
			reason:   "tool call limit exceeded: 11/10",
			wantKnob: "max_tool_calls_per_session",
		},
		{
			name:     "wall clock budget",
			reason:   "wall clock budget exceeded: 31m0s/30m0s",
			wantKnob: "max_wall_clock_minutes",
		},
		{
			name:     "identical call loop",
			reason:   "loop detected: expensive_tool called 6 times with same args (limit 5)",
			wantKnob: "max_retries_per_tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, ok := GuidanceForResult(ScannerDenialOfWallet, tt.reason)
			if !ok {
				t.Fatal("GuidanceForResult(denial_of_wallet) not ok")
			}
			if !strings.Contains(g.OperatorKnob, "agents._default.budget."+tt.wantKnob) {
				t.Fatalf("operator knob = %q, want agents._default.budget.%s", g.OperatorKnob, tt.wantKnob)
			}
			if hint := OperatorHintForResult(ScannerDenialOfWallet, tt.reason); hint != g.OperatorKnob {
				t.Fatalf("OperatorHintForResult() = %q, want %q", hint, g.OperatorKnob)
			}
		})
	}

	for _, reason := range []string{
		"cycle detected: a -> b -> a -> b",
		"runaway expansion: 5.2x growth per turn",
	} {
		t.Run(reason, func(t *testing.T) {
			guidance, ok := GuidanceForResult(ScannerDenialOfWallet, reason)
			if !ok {
				t.Fatal("GuidanceForResult(denial_of_wallet) not ok")
			}
			if guidance != remediationGuidance[ScannerDenialOfWallet] {
				t.Fatalf("guidance = %#v, want family fallback %#v", guidance, remediationGuidance[ScannerDenialOfWallet])
			}
			hint := guidance.OperatorKnob
			if !strings.Contains(hint, "fixed detector thresholds") {
				t.Fatalf("fallback hint = %q, want fixed-threshold disclosure", hint)
			}
			if !strings.Contains(hint, "dow_action") {
				t.Fatalf("fallback hint = %q, want the verified enforcement knob", hint)
			}
			for _, inert := range []string{"max_retries_per_tool", "loop_detection_window"} {
				if strings.Contains(hint, inert) {
					t.Fatalf("fallback hint = %q, must not present %s as a detector limit", hint, inert)
				}
			}
		})
	}
}

func TestOperatorHintForResultResolvesAuditReasons(t *testing.T) {
	tests := []struct {
		name   string
		label  string
		reason string
		want   string
	}{
		{"media image size", AuditMediaPolicy, "media_policy: image size 2048 exceeds limit 1024", "media_policy.max_image_bytes"},
		{"media audio", AuditMediaPolicy, "media_policy: audio stripped", "media_policy.strip_audio"},
		{"media video", AuditMediaPolicy, "media_policy: video stripped", "media_policy.strip_video"},
		{"media images", AuditMediaPolicy, "media_policy: images stripped", "media_policy.strip_images"},
		{"media type", AuditMediaPolicy, `media_policy: image type "image/webp" not in allowed list`, "media_policy.allowed_image_types"},
		{"media parse failure", AuditMediaPolicy, "media_policy: image parse error", "no exemption knob"},
		{"response integrity", AuditResponseScan, "compressed response cannot be scanned", "scan-integrity failure"},
		{"response size", AuditResponseScan, "response scan ceiling exceeded", "exact transport response ceiling"},
		{"size-exempt response", AuditResponseScan, "size-exempt response from api.vendor.example is too large", "response_scanning.size_exempt_scan_max_bytes"},
		{"size-exempt inflight", AuditResponseScan, "size-exempt response scan would exceed size_exempt_scan_max_inflight_bytes", "response_scanning.size_exempt_scan_max_inflight_bytes"},
		{"request budget", AuditAgentBudget, "request budget exceeded: 11/10 requests", "max_requests_per_session"},
		{"domain budget", AuditAgentBudget, "domain budget exceeded: 6/5 unique domains", "max_unique_domains_per_session"},
		{"truncated byte budget alias", AuditBudgetTruncated, "response truncated at byte budget", "max_bytes_per_session"},
		{"TLS response integrity alias", AuditTLSResponseBlocked, "compressed response cannot be scanned", "scan-integrity failure"},
		{"request policy body ceiling", AuditRequestPolicy, "request body exceeds max_body_bytes (1024)", "request_body_scanning.max_body_bytes"},
		{"request policy unreadable body", AuditRequestPolicy, "request body could not be inspected: read failed", "no exemption"},
		{"baseline deviation", AuditSessionAnomaly, "baseline_deviation", "pipelock baseline show"},
		{"domain burst", AuditSessionAnomaly, "ip_domain_burst", "session_profiling.domain_burst"},
		{"frozen tool is airlock", AuditFrozenTool, "tool not in frozen inventory", "airlock.timers"},
		{"released tool scanning inspection", AuditToolScanning, "tools/list cannot be safely inspected: tool_inventory_capacity", "does not override this refusal"},
		{"URL tool scanning inspection", ScannerMCPToolScanning, "tools/list cannot be safely inspected: tool_inventory_capacity", "does not override this refusal"},
		{"session deny alias", AuditSessionDeny, "critical", "affected identity session"},
		{"A2A header alias", AuditA2AHeader, "a2a: A2A-Extensions header contains blocked URI", "a2a_scanning.action"},
		{"redaction non JSON route", AuditRedaction, "redaction blocked request: non_json_body", "redaction.allowlist_unparseable_routes"},
		{"MCP cross-request entropy", AuditCrossRequestEntropy, "cross-request entropy budget exceeded: 900/800 bits", "entropy_budget.bits_per_window"},
		{"submit method", AuditReverseSubmit, "submit profile: method GET not in allowed_methods", "reverse_proxy.allowed_methods"},
		{"submit path", AuditReverseSubmit, "submit profile: path /v2 not in allowed_paths", "reverse_proxy.allowed_paths[].exact"},
		{"submit body", AuditReverseSubmit, "submit profile: body exceeds effective cap", "request_body_scanning.max_body_bytes"},
		{"submit raw path", AuditReverseSubmit, "submit profile: raw path rejected", "no exemption knob"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := OperatorHintForResult(tt.label, tt.reason)
			if !strings.Contains(hint, tt.want) {
				t.Fatalf("OperatorHintForResult(%q, %q) = %q, want substring %q", tt.label, tt.reason, hint, tt.want)
			}
		})
	}

	if hint := OperatorHintForResult(AuditFrozenTool, "tool not in frozen inventory"); strings.Contains(hint, "mcp_session_binding") {
		t.Fatalf("frozen-tool hint points at inert session-binding config: %q", hint)
	}
}

func TestRemediationHintsDoNotRecommendInertKnobs(t *testing.T) {
	t.Run("request body prompt injection omits response exemptions", func(t *testing.T) {
		hint := OperatorHintForResult(AuditBodyPromptInjection, "request body contains prompt injection")
		if !strings.Contains(hint, "request_body_scanning.trusted_hosts") {
			t.Fatalf("request-body prompt-injection hint = %q, want trusted-host control", hint)
		}
		if strings.Contains(hint, "response_scanning.exempt_domains") {
			t.Fatalf("request-body prompt-injection hint = %q, recommends an unconsulted response exemption", hint)
		}
		if !strings.Contains(hint, "configured action") || !strings.Contains(hint, "`block` action") {
			t.Fatalf("request-body prompt-injection hint = %q, must preserve the configured action", hint)
		}
	})

	t.Run("core response rejects inert suppression advice", func(t *testing.T) {
		hint := OperatorHintForResult(ScannerCoreResponse, "core response pattern: role_override")
		if strings.Contains(hint, "top-level `suppress:`") {
			t.Fatalf("core-response hint = %q, recommends forbidden suppression", hint)
		}
		if !strings.Contains(hint, "cannot be suppressed") || !strings.Contains(hint, "pattern itself must be tightened") {
			t.Fatalf("core-response hint = %q, want immutable precision-fix guidance", hint)
		}
	})

	t.Run("provenance omits inert sigstore trust fields", func(t *testing.T) {
		hint := OperatorHintForResult(AuditProvenance, "provenance verification failed")
		for _, inert := range []string{"trusted_issuers", "trusted_subjects"} {
			if strings.Contains(hint, "`mcp_tool_provenance."+inert+"`") {
				t.Fatalf("provenance hint = %q, presents inert %s as a config path", hint, inert)
			}
		}
		if !strings.Contains(hint, "trusted_keys") || !strings.Contains(hint, "unsigned tools only") {
			t.Fatalf("provenance hint = %q, want consumed key and exact action scope", hint)
		}
	})

	t.Run("MCP entropy omits HTTP-only host exemption", func(t *testing.T) {
		hint := OperatorHintForResult(AuditCrossRequestEntropy, "cross-request entropy budget exceeded: 900/800 bits")
		if strings.Contains(hint, "add only that host") {
			t.Fatalf("MCP entropy hint = %q, presents HTTP-only exemption as remediation", hint)
		}
		if !strings.Contains(hint, "does not consult `entropy_budget.exempt_domains`") {
			t.Fatalf("MCP entropy hint = %q, want explicit non-consultation warning", hint)
		}
	})

	t.Run("fetch response size omits transport-only exemption", func(t *testing.T) {
		hint := OperatorHintForResult(AuditResponseSize, "response exceeds fetch_proxy.max_response_mb")
		if strings.Contains(hint, "add the trusted host") {
			t.Fatalf("fetch response-size hint = %q, presents an unconsulted host exemption", hint)
		}
		if !strings.Contains(hint, "fetch-handler response-size blocks do not consult") {
			t.Fatalf("fetch response-size hint = %q, want transport limitation", hint)
		}
	})

	t.Run("redaction distinguishes non-JSON passthrough", func(t *testing.T) {
		nonJSON := OperatorHintForResult(AuditRedaction, "redaction blocked request: non_json_body")
		if !strings.Contains(nonJSON, "allowlist_unparseable_routes") || !strings.Contains(nonJSON, "forward the body unredacted") {
			t.Fatalf("non-JSON redaction hint = %q, want consulted route carve-out and consequence", nonJSON)
		}
		generic := OperatorHintForResult(AuditRedaction, "redaction blocked request: invalid profile")
		if !strings.Contains(generic, "no exemption knob") {
			t.Fatalf("generic redaction hint = %q, want fail-closed guidance", generic)
		}
	})

	t.Run("A2A hard floors omit configurable action", func(t *testing.T) {
		for _, reason := range []string{
			"a2a: input exceeds maximum inspectable nesting depth",
			"a2a: DLP: Hostname Exfiltration",
		} {
			hint := OperatorHintForResult(AuditA2AScan, reason)
			if strings.Contains(hint, "set `a2a_scanning.action") {
				t.Fatalf("hard-floor A2A hint = %q, presents action as remediation", hint)
			}
			if !strings.Contains(hint, "does not consult `a2a_scanning.action`") {
				t.Fatalf("hard-floor A2A hint = %q, want explicit non-consultation", hint)
			}
		}
		tunable := OperatorHintForResult(AuditA2AScan, "a2a: injection: prompt_override")
		if !strings.Contains(tunable, "set `a2a_scanning.action: warn`") {
			t.Fatalf("tunable A2A hint = %q, want consulted action", tunable)
		}
	})

	t.Run("Decide injection omits suppression remediation", func(t *testing.T) {
		hint := OperatorHintForResult(DecideInjectionLabel, "prompt override")
		if strings.Contains(hint, "for example suppress") {
			t.Fatalf("Decide injection hint = %q, presents unconsulted suppression", hint)
		}
		if !strings.Contains(hint, "suppression entry is inert here") {
			t.Fatalf("Decide injection hint = %q, want explicit non-consultation", hint)
		}
	})

	t.Run("URL data budget names the consumed field", func(t *testing.T) {
		hint := OperatorHintForResult(ScannerDataBudget, "data budget exceeded")
		if !strings.Contains(hint, "fetch_proxy.monitoring.max_data_per_minute") {
			t.Fatalf("data-budget hint = %q, want consumed scanner field", hint)
		}
	})

	t.Run("kill switch distinguishes transport exemptions", func(t *testing.T) {
		hint := OperatorHintForResult(AuditKillSwitch, "sentinel")
		if !strings.Contains(hint, "kill_switch.allowlist_ips") || !strings.Contains(hint, "Raw/MCP") || !strings.Contains(hint, "except during unresolved") {
			t.Fatalf("kill-switch hint = %q, want exact HTTP carve-out scope", hint)
		}
	})

	t.Run("uncertain policy requires recovery instead of an IP exemption", func(t *testing.T) {
		hint := OperatorHintForResult(AuditKillSwitch, "conductor_apply_failure")
		// Pin the complete advice so an added contradictory exemption cannot
		// pass merely because the recovery and non-exemption fragments remain.
		const want = "Restore the failed policy-application prerequisite and retry a valid Conductor policy, or restart to re-verify cached policy. `kill_switch.allowlist_ips` doesn't exempt unresolved policy application."
		if hint != want {
			t.Fatalf("uncertain-policy hint = %q, want only policy recovery and the explicit exemption limit", hint)
		}
	})

	t.Run("reverse submit omits non-admission fields", func(t *testing.T) {
		hint := OperatorHintForResult(AuditReverseSubmit, "submit profile: method GET not in allowed_methods")
		for _, inert := range []string{"trusted_upstream", "request_timeout_seconds"} {
			if strings.Contains(hint, inert) {
				t.Fatalf("reverse-submit hint = %q, presents non-admission field %s", hint, inert)
			}
		}
	})
}

func TestOperatorHintForResultResolvesDialTimeSSRFReasons(t *testing.T) {
	tests := []struct {
		name   string
		label  string
		reason string
	}{
		{
			name:   "dial private ip",
			label:  ScannerSSRF,
			reason: "ssrf_private_ip: SSRF blocked: api.vendor.example resolves to internal IP 10.0.0.42",
		},
		{
			name:   "dial dns rebind",
			label:  ScannerSSRF,
			reason: "ssrf_dns_rebind: SSRF blocked: api.vendor.example resolves to internal IP 10.0.0.43",
		},
		{
			name:   "url scan audit mode",
			label:  ScannerSSRF,
			reason: "destination resolves to a private IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := OperatorHintForResult(tt.label, tt.reason)
			if !strings.Contains(hint, "trusted_domains") {
				t.Fatalf("hint = %q, want trusted_domains", hint)
			}
			if !strings.Contains(hint, "ssrf.ip_allowlist") {
				t.Fatalf("hint = %q, want ssrf.ip_allowlist", hint)
			}
		})
	}
}

// A non-overridable SSRF block must NEVER hand back ssrf.ip_allowlist as the
// remediation, regardless of which SSRF label carried it. The dial-time guard
// can use the generic ScannerSSRF label with the non-overridable classification
// only in the reason string, so reason-based routing must still hold.
func TestOperatorHintForNonOverridableSSRFReasonNeverSuggestsAllowlist(t *testing.T) {
	reasons := []struct {
		name       string
		label      string
		reason     string
		isMetadata bool // want metadata-specific wording vs generic non-overridable
	}{
		{"dial generic label", ScannerSSRF, "ssrf_metadata: SSRF blocked: api.vendor.example resolves to cloud metadata endpoint 169.254.169.254", true},
		{"metadata label", ScannerSSRFMetadata, "SSRF blocked: api.vendor.example resolves to cloud metadata endpoint 169.254.169.254", true},
		{"core ssrf metadata", ScannerCoreSSRF, "core SSRF: 169.254.169.254 resolves to cloud metadata endpoint", true},
		{"non metadata non-overridable", ScannerSSRF, "SSRF blocked: api.vendor.example resolves to non-overridable internal IP 224.0.0.1", false},
	}
	for _, tt := range reasons {
		t.Run(tt.name, func(t *testing.T) {
			hint := OperatorHintForResult(tt.label, tt.reason)
			// The hint may NAME ssrf.ip_allowlist/trusted_domains to say they do
			// NOT work, but must never present either as the fix, and must state
			// the deny is non-overridable with no allow knob.
			if !strings.Contains(hint, "non-overridable") {
				t.Fatalf("hint should state it is non-overridable, got %q", hint)
			}
			if !strings.Contains(hint, "cannot exempt") {
				t.Fatalf("hint should state the knobs cannot exempt the target, got %q", hint)
			}
			if !strings.Contains(hint, "no allow knob") {
				t.Fatalf("hint should state there is no allow knob, got %q", hint)
			}
			// A non-metadata non-overridable target must not be described as an
			// instance-metadata endpoint (distinct guidance per target class).
			mentionsMetadata := strings.Contains(hint, "instance-metadata")
			if tt.isMetadata && !mentionsMetadata {
				t.Fatalf("metadata block should use metadata-specific wording, got %q", hint)
			}
			if !tt.isMetadata && mentionsMetadata {
				t.Fatalf("non-metadata non-overridable block must not claim it is an instance-metadata endpoint, got %q", hint)
			}
		})
	}
}

func TestOperatorHintForKnownAndUnknown(t *testing.T) {
	t.Parallel()

	got := OperatorHintFor(ScannerBodyDLP)
	if got == "" || !strings.Contains(got, "suppress:") {
		t.Fatalf("OperatorHintFor(body_dlp) = %q, want suppress: knob", got)
	}
	if OperatorHintFor("nonexistent") != "" {
		t.Fatal("unknown label must return empty operator hint")
	}
}

func TestGuidanceForResultRemainingReasonRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		label  string
		reason string
		want   string
	}{
		{"reverse allowed paths", AuditReverseSubmit, "path not in allowed_paths", "allowed_paths[].exact"},
		{"reverse body cap", AuditReverseSubmit, "body exceeds submit limit", "submit gate enforces their minimum"},
		{"reverse raw path", AuditReverseSubmit, "raw path is not canonical", "encoded traversal"},
		{"response inflight", AuditResponseScan, "size-exempt response scan inflight limit", "size_exempt_scan_max_inflight_bytes"},
		{"response size-exempt", AuditResponseScan, "size-exempt response too large", "size_exempt_scan_max_bytes"},
		{"response oversized", AuditResponseScan, "oversized upstream body", "transport response ceiling"},
		{"media audio", AuditMediaPolicy, "audio stripped from request", "strip_audio: false"},
		{"media video", AuditMediaPolicy, "video stripped from request", "strip_video: false"},
		{"media images", AuditMediaPolicy, "images stripped from request", "strip_images: false"},
		{"media type", AuditMediaPolicy, "image/webp not in allowed list", "SVG remains unsupported"},
		{"media parse", AuditMediaPolicy, "media parse error", "unvalidated media payload"},
		{"request unreadable", AuditRequestPolicy, "request body could not be inspected", "cannot be forwarded intact"},
		{"a2a hostname", AuditA2AScan, "hostname exfiltration in card", "no A2A suppression knob"},
		{"a2a url ssrf", AuditA2AScan, "url/ssrf finding in message", "before that field is consulted"},
		{"a2a injection", AuditA2AScan, "injection: ignore previous", "intentionally audit-only"},
		{"agent domain budget", AuditAgentBudget, "domain budget exceeded", "destination diversity"},
		{"agent byte budget", AuditAgentBudget, "byte budget exceeded", "response volume"},
		{"session domain burst", AuditSessionAnomaly, "domain_burst over window", "destination burst is expected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := GuidanceForResult(tt.label, tt.reason)
			if !ok {
				t.Fatalf("GuidanceForResult(%q, %q) not found", tt.label, tt.reason)
			}
			if got == remediationGuidance[tt.label] {
				t.Fatalf("GuidanceForResult(%q, %q) fell through to label-only guidance", tt.label, tt.reason)
			}
			if !strings.Contains(got.OperatorKnob, tt.want) {
				t.Fatalf("OperatorKnob = %q, want substring %q", got.OperatorKnob, tt.want)
			}
		})
	}
}

func TestDecideLabelGuidanceNamesOperatorKnobsOnlyToOperator(t *testing.T) {
	tests := []struct {
		label       string
		wantKnob    string
		forbidAgent string
	}{
		{DecideInjectionLabel, "response_scanning", "response_scanning"},
		{DecidePolicyLabel, "mcp_tool_policy", "mcp_tool_policy"},
		{DecideStructuralLabel, "could not be evaluated safely", "correct the action shape"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			g, ok := GuidanceFor(tt.label)
			if !ok {
				t.Fatalf("GuidanceFor(%q) not ok", tt.label)
			}
			if !strings.Contains(g.OperatorKnob, tt.wantKnob) {
				t.Fatalf("OperatorKnob = %q, want substring %q", g.OperatorKnob, tt.wantKnob)
			}
			if strings.Contains(g.AgentReason, tt.forbidAgent) {
				t.Fatalf("AgentReason %q contains operator knob substring %q", g.AgentReason, tt.forbidAgent)
			}
		})
	}
}

func TestJSONInspectionRemediationHint(t *testing.T) {
	for label := range remediationGuidance {
		t.Run(label, func(t *testing.T) {
			for _, reason := range []string{
				UninspectableJSONNumberPattern,
				"request body contains secret: " + UninspectableJSONNumberPattern,
				"other pattern, " + UninspectableJSONNumberPattern,
			} {
				g, ok := GuidanceForResultWithPatterns(label, reason, []string{"other pattern", UninspectableJSONNumberPattern})
				if !ok || !g.Immutable || g.OperatorBroader != "" {
					t.Fatalf("inspection guidance = %+v, mapped = %v", g, ok)
				}
				hint := OperatorHintForPatterns(label, []string{"other pattern", UninspectableJSONNumberPattern})
				for _, want := range []string{"Reduce nesting or number size", "payload at its source", "limits are fixed"} {
					if !strings.Contains(hint, want) {
						t.Errorf("hint = %q, want %q", hint, want)
					}
				}
				if strings.Contains(strings.ToLower(hint), "suppress") {
					t.Fatalf("inspection hint offers suppression: %q", hint)
				}
			}
			ordinary, ok := GuidanceForResult(label, "ordinary finding")
			if baseline, mapped := GuidanceFor(label); mapped && ok && ordinary.OperatorKnob != baseline.OperatorKnob {
				// Reason-specific families have their own existing regression tests.
				if label == ScannerBodyDLP || label == ScannerDLP || label == AuditResponseScan {
					t.Fatalf("ordinary guidance changed: %+v, want %+v", ordinary, baseline)
				}
			}
		})
	}
}

func TestJSONInspectionRemediationReasonFormats(t *testing.T) {
	for _, tt := range []struct{ label, reason string }{
		{ScannerBodyDLP, "request body contains secret: " + UninspectableJSONNumberPattern},
		{ScannerBodyDLP, "request body contains secret: ordinary, " + UninspectableJSONNumberPattern},
		{ScannerDLP, "DLP match: " + UninspectableJSONNumberPattern + " (high)"},
		{ScannerCoreDLP, "core DLP match: " + UninspectableJSONNumberPattern + " (high)"},
		{ScannerDLP, "DLP match: ordinary, " + UninspectableJSONNumberPattern},
		{ScannerDLP, "DLP match: " + UninspectableJSONNumberPattern + " (escalated)"},
		{ScannerDLP, "DLP: " + UninspectableJSONNumberPattern},
		{AuditCrossRequestFragment, "fragment reassembly DLP match: " + UninspectableJSONNumberPattern},
		{AuditCrossRequestFragment, "cross-request fragment inspection limit exceeded"},
		{AuditCrossRequestFragment, "cross-request fragment refused: " + UninspectableJSONNumberPattern + "; reduce nesting or number size in the JSON tool arguments at their source (typed JSON number and depth limits are fixed)"},
		{AuditA2AResponse, "a2a: DLP: " + UninspectableJSONNumberPattern},
		{AuditA2AResponse, "a2a: 2 URL/SSRF finding(s); injection: ordinary; DLP: " + UninspectableJSONNumberPattern},
		{AuditA2AScan, "a2a: injection: ordinary; DLP: ordinary, " + UninspectableJSONNumberPattern + "; payload exceeded node budget"},
	} {
		t.Run(tt.reason, func(t *testing.T) {
			got, ok := GuidanceForResult(tt.label, tt.reason)
			if !ok || !got.Immutable || !strings.Contains(got.OperatorKnob, "limits are fixed") {
				t.Fatalf("genuine refusal lost: %+v, %v", got, ok)
			}
		})
	}
}

func TestJSONInspectionRemediationRequiresPatternIdentity(t *testing.T) {
	for _, pattern := range []string{"prefix " + UninspectableJSONNumberPattern, UninspectableJSONNumberPattern + " suffix", "ordinary, " + UninspectableJSONNumberPattern, "request body contains secret: " + UninspectableJSONNumberPattern, " " + UninspectableJSONNumberPattern + " "} {
		got, ok := GuidanceForResultWithPatterns(ScannerBodyDLP, pattern, []string{pattern})
		baseline, _ := GuidanceFor(ScannerBodyDLP)
		if !ok || got != baseline {
			t.Fatalf("display text %q changed guidance: %+v", pattern, got)
		}
	}
	for _, label := range []string{ScannerSSRF, ScannerDLP, AuditResponseScan, ScannerBodyDLP, AuditCrossRequestFragment, AuditA2AScan, AuditA2AResponse} {
		for _, patterns := range [][]string{nil, {""}, {"", " \t\r\n", "\u00a0"}} {
			got, ok := GuidanceForResultWithPatterns(label, "client text mentions "+UninspectableJSONNumberPattern, patterns)
			baseline, _ := GuidanceFor(label)
			if !ok || got != baseline {
				t.Fatalf("free text changed %q guidance with patterns %q: %+v", label, patterns, got)
			}
		}
	}
}

func TestJSONInspectionRemediationIgnoresBlankPatterns(t *testing.T) {
	for _, tt := range []struct{ label, reason string }{
		{ScannerBodyDLP, "request body contains secret: " + UninspectableJSONNumberPattern},
		{ScannerDLP, "DLP match: " + UninspectableJSONNumberPattern + " (high)"},
		{ScannerCoreDLP, "core DLP match: " + UninspectableJSONNumberPattern + " (high)"},
		{AuditA2AResponse, "a2a: DLP: " + UninspectableJSONNumberPattern},
		{AuditCrossRequestFragment, "fragment reassembly DLP match: " + UninspectableJSONNumberPattern},
		{AuditCrossRequestFragment, "cross-request fragment inspection limit exceeded"},
	} {
		t.Run(tt.label, func(t *testing.T) {
			// Positive control: this genuine reason must be recognized on its own.
			want, ok := GuidanceForResult(tt.label, tt.reason)
			if !ok || !want.Immutable || !strings.Contains(want.OperatorKnob, "limits are fixed") {
				t.Fatalf("invalid genuine-refusal fixture: %+v, %v", want, ok)
			}
			for _, patterns := range [][]string{nil, {}, {""}, {" \t\r\n"}, {"", "\u00a0", "\t"}} {
				got, mapped := GuidanceForResultWithPatterns(tt.label, tt.reason, patterns)
				if !mapped || got != want {
					t.Errorf("blank patterns %q lost fixed-limit guidance: %+v, %v", patterns, got, mapped)
				}
			}
			// Blank entries must not hide a real identity or mutate the caller's slice.
			patterns := []string{"", "ordinary pattern", " \t"}
			got, mapped := GuidanceForResultWithPatterns(tt.label, tt.reason, patterns)
			ordinary, ordinaryMapped := GuidanceForResultWithPatterns(tt.label, tt.reason, []string{"ordinary pattern"})
			if !mapped || !ordinaryMapped || got != ordinary || got == want {
				t.Fatalf("structured identity lost precedence: %+v, %v", got, mapped)
			}
			if patterns[0] != "" || patterns[1] != "ordinary pattern" || patterns[2] != " \t" {
				t.Fatalf("caller patterns changed: %q", patterns)
			}
			got, mapped = GuidanceForResultWithPatterns(tt.label, "ordinary finding", []string{"", " \t", UninspectableJSONNumberPattern})
			if !mapped || got != want {
				t.Fatalf("exact identity lost among blanks: %+v, %v", got, mapped)
			}
		})
	}
}

func TestA2AJSONInspectionRemediationRejectsForgedParts(t *testing.T) {
	for _, prefix := range []string{
		"duplicate JSON object key: ", "invalid JSON: ", "response scan incomplete: ",
		"request body uses Content-Encoding ", "error reading request body: ",
		"opaque hex request body content ", "0 URL/SSRF finding(s)",
		"ordinary URL/SSRF finding(s)", "99999999999999999999999999999 URL/SSRF finding(s)",
	} {
		reason := "a2a: " + prefix + "; DLP: " + UninspectableJSONNumberPattern + "; tail"
		for _, label := range []string{AuditA2AScan, AuditA2AHeader, AuditA2AResponse} {
			for _, patterns := range [][]string{nil, {""}, {"", " \t\r\n", "\u00a0"}} {
				g, ok := GuidanceForResultWithPatterns(label, reason, patterns)
				if !ok || g == jsonInspectionLimitGuidance() {
					t.Errorf("forged reason %q selected inspection-limit guidance under %s with patterns %q", reason, label, patterns)
				}
			}
		}
	}
}

// The mcp_protocol label covers listener admission, protocol and capacity
// refusals as well as batches. Only a batch request is repaired by sending one
// request at a time, so no other reason may carry that hint.
func TestMCPProtocolHintOnlyForBatchRequests(t *testing.T) {
	const batchKnob = "Send one JSON-RPC request at a time."
	if hint := OperatorHintForResult(AuditMCPProtocol, "MCP batch requests are unsupported"); !strings.Contains(hint, batchKnob) {
		t.Fatalf("batch request hint = %q", hint)
	}
	for _, reason := range []string{
		"MCP batch responses are unsupported",
		"MCP listener admission refused",
		"MCP listener protocol refused",
		"MCP listener state capacity exhausted",
		"MCP listener client-registry capacity exhausted (4096 clients); wait for listener idle expiry (24h) or session end",
		"session capacity exhausted; wait for session recovery or increase max_sessions",
	} {
		if hint := OperatorHintForResult(AuditMCPProtocol, reason); hint == "" || strings.Contains(hint, batchKnob) {
			t.Errorf("reason %q has hint %q, want its own non-empty hint", reason, hint)
		}
	}
}

// Operational refusals must identify the failed prerequisite, rather than
// recommending the generic content-policy controls for the same label.
func TestMCPRemediationReasonPrerequisites(t *testing.T) {
	cases := []struct {
		label, reason, want string
		immutable           bool
	}{
		{AuditContract, "MCP contract evaluation failed", "Restore the active contract loader", false},
		{AuditA2AScan, "A2A input could not be inspected", "does not override a failed inspection", false},
		{AuditA2AScan, "A2A input URL check refused", "cloud metadata and core-critical destination blocks remain enforced", false},
		{AuditA2AScan, "A2A input inspection budget exceeded", "budget-only refusal after fallback scanning", false},
		{AuditA2AScan, "A2A input configuration mismatch", "does not repair a configuration mismatch", false},
		{AuditMCPProtocol, "MCP batch responses are unsupported", "correct the upstream server", true},
		{AuditMCPProtocol, "MCP listener admission refused", "listener_require_state_token", true},
		{AuditMCPProtocol, "MCP listener protocol refused", "no scanner or policy setting relaxes protocol validation", true},
		{AuditMCPProtocol, "MCP listener state capacity exhausted", "Retry after an existing state expires", true},
		{AuditMCPProtocol, "MCP listener client-registry capacity exhausted (4096 clients); wait for listener idle expiry (24h) or session end", "does not raise this registry limit", true},
		{AuditMCPProtocol, "session capacity exhausted; wait for session recovery or increase max_sessions", "session_profiling.max_sessions", true},
		{ScannerMCPToolScanning, "tools/list cannot be safely inspected: oversized inventory", "does not override this refusal", false},
		{AuditToolScanning, "tools/list cannot be safely inspected: malformed inventory", "does not override this refusal", false},
		{AuditResponseScan, "response scan parse error in MCP parameter header", "cannot make the header scannable", false},
		{AuditResponseScan, "response scan cannot be scanned: response scanner unavailable", "policy suppression cannot provide the missing scan", false},
		{AuditResponseScan, "response scan returned an incomplete verdict", "a pattern suppression has no identified match to change", false},
	}
	for _, tc := range cases {
		t.Run(tc.label+"/"+tc.reason, func(t *testing.T) {
			guidance, ok := GuidanceForResult(tc.label, tc.reason)
			if !ok || !strings.Contains(guidance.OperatorKnob, tc.want) || guidance.Immutable != tc.immutable || guidance.AgentReason != auditRuntimeAgentReason {
				t.Fatalf("guidance = %+v, ok=%v; want prerequisite %q, immutable=%v and runtime refusal", guidance, ok, tc.want, tc.immutable)
			}
			if hint := OperatorHintForResult(tc.label, tc.reason); !strings.Contains(hint, tc.want) {
				t.Fatalf("operator hint lost prerequisite: %q", hint)
			}
		})
	}
}

func TestQueryEntropyHintChangingPaths(t *testing.T) {
	for _, reason := range []string{
		`high entropy query param "_state" (5.58 > 4.50 threshold)`,
		`nested URL in query parameter "next": high entropy query param "_state"`,
	} {
		t.Run(reason, func(t *testing.T) {
			hint := OperatorHintForResult(ScannerEntropy, reason)
			for _, want := range []string{
				"For a blocked query value at a stable endpoint path",
				"query_entropy_param_exclusions",
				"not future paths with new upload UUIDs or other changing segments",
				"query_entropy_exclusions",
				"broader host-wide fallback",
			} {
				if !strings.Contains(hint, want) {
					t.Errorf("hint %q missing %q", hint, want)
				}
			}
		})
	}
}

// A parameter exclusion skips only query-value entropy, so a query-key block
// must point at the host-wide exclusion and never suggest the inert tuple.
func TestQueryEntropyKeyHint(t *testing.T) {
	for _, reason := range []string{
		`high entropy query key "opaque" (4.50 > 4.00 threshold)`,
		`nested URL in query parameter "next": high entropy query key "opaque"`,
	} {
		t.Run(reason, func(t *testing.T) {
			hint := OperatorHintForResult(ScannerEntropy, reason)
			if !strings.HasPrefix(hint, queryEntropyKeyOperatorKnob) {
				t.Fatalf("hint = %q, want key knob", hint)
			}
			if !strings.Contains(hint, "`fetch_proxy.monitoring.query_entropy_exclusions`") {
				t.Errorf("hint %q missing host-wide exclusion", hint)
			}
			if strings.Contains(hint, "add the exact scheme+host+path+param tuple") {
				t.Errorf("hint %q recommends a parameter exclusion that cannot lift a key block", hint)
			}
		})
	}
}
