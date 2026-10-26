// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"slices"
	"strings"
)

// HostileFindingKind records why an existing hostile observation was made.
// These labels describe evidence; policy still uses the existing taint level.
type HostileFindingKind string

const (
	// FindingWording comes from scanner.ResponseScanResult.Matches.
	FindingWording HostileFindingKind = "prompt_injection_wording"
	// FindingDLP comes from jsonrpc.ScanVerdict.DLPMatches or A2A DLPFindings.
	FindingDLP HostileFindingKind = "dlp"
	// FindingToolPoisoning comes from the MCP tools/list poisoning scanner.
	FindingToolPoisoning HostileFindingKind = "tool_poisoning"
	// FindingToolDrift comes from tools.ToolScanMatch.DriftDetected.
	FindingToolDrift HostileFindingKind = "tool_definition_drift"
	// FindingToolAcknowledgment comes from tools.ToolScanResult.CredentialAckApplied.
	FindingToolAcknowledgment HostileFindingKind = "tool_acknowledgment"
	// FindingURL comes from A2AScanResult.URLFindings.
	FindingURL HostileFindingKind = "url"
	// FindingEntropy comes from A2AScanResult.EntropyFinding.
	FindingEntropy HostileFindingKind = "content_entropy"
	// FindingToolProvenance comes from ProvenanceVerdictToScanVerdict.
	FindingToolProvenance HostileFindingKind = "tool_provenance"
	// FindingAgentCard comes from AgentCardScanResult drift or baseline capacity.
	FindingAgentCard HostileFindingKind = "agent_card"
	// FindingInspectionIncomplete comes from A2A inspection bounds.
	FindingInspectionIncomplete HostileFindingKind = "inspection_incomplete"
	// FindingScanError comes from an already hostile ResponseScanResult.ScanError.
	FindingScanError HostileFindingKind = "scan_error"
	// FindingSSEEventTooLarge comes from mcp.ErrSSEEventTooLarge.
	FindingSSEEventTooLarge HostileFindingKind = "sse_event_too_large"
	// FindingSSEInvalidUTF8 comes from mcp.ErrSSEInvalidUTF8.
	FindingSSEInvalidUTF8 HostileFindingKind = "sse_invalid_utf8"
	// FindingUnattributed preserves legacy or aggregate hostile evidence.
	FindingUnattributed HostileFindingKind = "unattributed"
)

// MergeFindingKinds returns a bounded, canonical union. Unknown labels retain
// the fact that evidence exists without pretending its cause is understood.
func MergeFindingKinds(sets ...[]HostileFindingKind) []HostileFindingKind {
	var out []HostileFindingKind
	for _, set := range sets {
		for _, kind := range set {
			switch kind {
			case FindingWording, FindingDLP, FindingToolPoisoning, FindingToolDrift, FindingToolAcknowledgment,
				FindingURL, FindingEntropy, FindingToolProvenance, FindingAgentCard,
				FindingInspectionIncomplete, FindingScanError, FindingSSEEventTooLarge, FindingSSEInvalidUTF8, FindingUnattributed:
			default:
				kind = FindingUnattributed
			}
			if !slices.Contains(out, kind) {
				out = append(out, kind)
			}
		}
	}
	slices.Sort(out)
	return out
}

// HostileFindingKinds returns recorded causes, including conservative recovery
// for in-memory states that predate cause attribution.
func (sr SessionRisk) HostileFindingKinds() []HostileFindingKind {
	kinds := MergeFindingKinds(sr.FindingKinds)
	if len(kinds) == 0 && (sr.PromptHit || sr.Level >= TaintExternalHostile) {
		return []HostileFindingKind{FindingUnattributed}
	}
	return kinds
}

// DescribeFindingKinds names evidence without making a live-session claim.
func DescribeFindingKinds(kinds []HostileFindingKind) string {
	kinds = MergeFindingKinds(kinds)
	if len(kinds) == 0 {
		return ""
	}
	if len(kinds) == 1 && kinds[0] == FindingWording {
		return "prompt-injection wording only"
	}
	labels := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		switch kind {
		case FindingWording:
			labels = append(labels, "prompt-injection wording")
		case FindingDLP:
			labels = append(labels, "DLP")
		case FindingSSEEventTooLarge:
			labels = append(labels, "oversize streaming event")
		case FindingSSEInvalidUTF8:
			labels = append(labels, "invalid UTF-8 in streaming event")
		case FindingUnattributed:
			labels = append(labels, "cause not recorded (older state or aggregate finding)")
		default:
			labels = append(labels, strings.ReplaceAll(string(kind), "_", " "))
		}
	}
	return strings.Join(labels, ", ")
}

// HostileCause explains existing hostile history without predicting a verdict.
func (sr SessionRisk) HostileCause() string {
	kinds := sr.HostileFindingKinds()
	cause := DescribeFindingKinds(kinds)
	if cause == "" {
		return ""
	}
	if len(kinds) == 1 && kinds[0] == FindingUnattributed {
		return "hostile: " + cause
	}
	return "hostile because of " + cause
}

// UnmarshalJSON retains hostile legacy snapshots whose PromptHit did not record
// a cause. It never reconstructs a wording-only cause from the old boolean.
func (sr *SessionRisk) UnmarshalJSON(data []byte) error {
	type plain SessionRisk
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*sr = SessionRisk(decoded)
	sr.FindingKinds = sr.HostileFindingKinds()
	if sr.PromptHit {
		sr.Level = maxTaintLevel(sr.Level, TaintExternalHostile)
		sr.Contaminated = true
	}
	return nil
}
