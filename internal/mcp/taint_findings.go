// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// sseFindingCause adds runtime attribution without changing the error text or
// the sentinel that controls streaming enforcement.
func sseFindingCause(err error, kinds ...session.HostileFindingKind) error {
	causes := []error{err}
	for _, kind := range session.MergeFindingKinds(kinds) {
		if marker := sseFindingMarkers[kind]; marker != nil {
			causes = append(causes, marker)
		}
	}
	return &sseFindingCauseError{error: err, causes: causes}
}

type sseFindingCauseError struct {
	error
	causes []error
}

func (e *sseFindingCauseError) Unwrap() []error { return e.causes }

// These are the causes produced by A2ATaintFindingKinds and the generic SSE
// wording/DLP scans. Framing findings retain their existing public sentinels.
var sseFindingMarkers = map[session.HostileFindingKind]error{
	session.FindingWording:              errors.New(string(session.FindingWording)),
	session.FindingDLP:                  errors.New(string(session.FindingDLP)),
	session.FindingURL:                  errors.New(string(session.FindingURL)),
	session.FindingEntropy:              errors.New(string(session.FindingEntropy)),
	session.FindingInspectionIncomplete: errors.New(string(session.FindingInspectionIncomplete)),
	session.FindingUnattributed:         errors.New(string(session.FindingUnattributed)),
}

// SSETaintFindingKinds reads structured causes from stream findings, including
// joined warn callbacks. It never derives a cause from error text.
func SSETaintFindingKinds(err error) []session.HostileFindingKind {
	var kinds []session.HostileFindingKind
	for kind, marker := range sseFindingMarkers {
		if errors.Is(err, marker) {
			kinds = append(kinds, kind)
		}
	}
	if errors.Is(err, ErrSSEEventTooLarge) {
		kinds = session.MergeFindingKinds(kinds, []session.HostileFindingKind{session.FindingSSEEventTooLarge})
	}
	if errors.Is(err, ErrSSEInvalidUTF8) {
		kinds = session.MergeFindingKinds(kinds, []session.HostileFindingKind{session.FindingSSEInvalidUTF8})
	}
	return session.MergeFindingKinds(kinds)
}

// ResponseTaintFindingKinds preserves the scanner's cause fields. Synthetic
// A2A matches carry explicit metadata rather than masquerading as wording.
func ResponseTaintFindingKinds(verdict jsonrpc.ScanVerdict) []session.HostileFindingKind {
	var kinds []session.HostileFindingKind
	if len(verdict.TaintFindingKinds) > 0 {
		for _, kind := range verdict.TaintFindingKinds {
			kinds = append(kinds, session.HostileFindingKind(kind))
		}
	} else if len(verdict.Matches) > 0 {
		kinds = append(kinds, session.FindingWording)
	}
	if len(verdict.DLPMatches) > 0 {
		kinds = append(kinds, session.FindingDLP)
	}
	for _, finding := range verdict.ToolFindings {
		if len(finding.Matches) > 0 {
			kinds = append(kinds, session.FindingWording)
		}
		if len(finding.ToolPoison) > 0 {
			kinds = append(kinds, session.FindingToolPoisoning)
		}
		if len(finding.Matches) == 0 && len(finding.ToolPoison) == 0 && len(verdict.TaintFindingKinds) == 0 {
			kinds = append(kinds, session.FindingUnattributed)
		}
	}
	if !verdict.Clean && len(kinds) == 0 {
		kinds = append(kinds, session.FindingUnattributed)
	}
	return session.MergeFindingKinds(kinds)
}

// A2ATaintFindingKinds uses the independent A2A finding fields, never Reason text.
func A2ATaintFindingKinds(result A2AScanResult) []session.HostileFindingKind {
	var kinds []session.HostileFindingKind
	if len(result.InjectFindings) > 0 {
		kinds = append(kinds, session.FindingWording)
	}
	if len(result.DLPFindings) > 0 {
		kinds = append(kinds, session.FindingDLP)
	}
	if len(result.URLFindings) > 0 {
		kinds = append(kinds, session.FindingURL)
	}
	if result.EntropyFinding != nil {
		kinds = append(kinds, session.FindingEntropy)
	}
	if result.BudgetExceeded || result.InspectionIncomplete {
		kinds = append(kinds, session.FindingInspectionIncomplete)
	}
	if !result.Clean && len(kinds) == 0 {
		kinds = append(kinds, session.FindingUnattributed)
	}
	return session.MergeFindingKinds(kinds)
}

func taintFindingLabels(kinds []session.HostileFindingKind) []string {
	var labels []string
	for _, kind := range kinds {
		labels = append(labels, string(kind))
	}
	return labels
}

func toolTaintFindingKinds(result tools.ToolScanResult, poisoned, acknowledged bool) []session.HostileFindingKind {
	var kinds []session.HostileFindingKind
	if poisoned {
		for _, finding := range result.Matches {
			if len(finding.Injection) > 0 {
				kinds = append(kinds, session.FindingWording)
			}
			if len(finding.ToolPoison) > 0 {
				kinds = append(kinds, session.FindingToolPoisoning)
			}
			if finding.DriftDetected {
				kinds = append(kinds, session.FindingToolDrift)
			}
		}
		if len(kinds) == 0 {
			kinds = append(kinds, session.FindingUnattributed)
		}
	}
	if acknowledged {
		kinds = append(kinds, session.FindingToolAcknowledgment)
	}
	return session.MergeFindingKinds(kinds)
}
