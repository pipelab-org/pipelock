// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// IsBlankInjectionView uses the wording checker's matching normalization to
// identify views with no wording. Blankness alone never establishes a benign
// assessment: callers must preserve findings, failures and disabled coverage.
//
// A letter or digit survives matching normalization, so the full pass runs only
// for text made of spaces, marks, symbols and invisible characters. A wrong
// early "not blank" can only withhold credit, never grant it.
func IsBlankInjectionView(content string) bool {
	for _, r := range content {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
	}
	return strings.TrimSpace(normalize.ForMatching(content)) == ""
}

// BlankViewAddsNoCoverage reports whether a view can be skipped when merging
// assessments: it is blank under matching normalization and its scan produced
// no failure, match, steganography signal or assessment of its own. Any of
// those must still reach the merge so it can withhold clean credit.
func BlankViewAddsNoCoverage(view string, result ResponseScanResult) bool {
	return result.Clean && !result.Failed() && !result.StegoDetected &&
		len(result.Matches)+len(result.WarnedMatches)+len(result.SuppressedMatches)+len(result.ObservedCoreMatches) == 0 &&
		result.Assessment.Status == AssessmentNotAssessed && IsBlankInjectionView(view)
}

// AssessmentStatus describes wording coverage, independently of delivery policy.
type AssessmentStatus string

const (
	// AssessmentNotAssessed means no wording view was evaluated.
	AssessmentNotAssessed AssessmentStatus = "not_assessed"
	// AssessmentOff means the operator disabled wording assessment.
	AssessmentOff AssessmentStatus = "off"
	// AssessmentBenign means the basic checker completed without wording findings.
	AssessmentBenign AssessmentStatus = "benign"
	// AssessmentPartial means only the immutable core wording floor ran because
	// the configurable response scanning layer is disabled; it is not benign.
	AssessmentPartial AssessmentStatus = "partial"
	// AssessmentFinding includes enforcing, warned, observed and suppressed findings.
	AssessmentFinding AssessmentStatus = "finding"
	// AssessmentIncomplete means inspection failed; it is not a content finding.
	AssessmentIncomplete AssessmentStatus = "incomplete"

	// InjectionCheckerBasic identifies the built-in wording checker.
	InjectionCheckerBasic = "basic"
)

// InjectionAssessment reports checker identity and coverage. It does not grant
// permission, override independent controls or describe whole-stream coverage.
type InjectionAssessment struct {
	Checker string           `json:"checker"`
	Status  AssessmentStatus `json:"status"`
}

// IsBenign requires an explicit assessment from the selected checker. Empty,
// unknown and partial statuses never authorize clean-request recovery.
func (a InjectionAssessment) IsBenign() bool {
	return a.Checker != "" && a.Status == AssessmentBenign
}

// Merge combines assessments of required views or items from one checker.
// An absent assessment is not an identity element: it is missing evidence.
// Callers initialize an aggregate from its first actual view.
func (a InjectionAssessment) Merge(b InjectionAssessment) InjectionAssessment {
	if a.Checker == "" || a.Checker != b.Checker {
		return InjectionAssessment{Status: AssessmentNotAssessed}
	}
	for _, status := range []AssessmentStatus{AssessmentIncomplete, AssessmentFinding, AssessmentOff, AssessmentPartial} {
		if a.Status == status || b.Status == status {
			return InjectionAssessment{Checker: a.Checker, Status: status}
		}
	}
	if a.IsBenign() && b.IsBenign() {
		return a
	}
	return InjectionAssessment{Checker: a.Checker, Status: AssessmentNotAssessed}
}

// RecoveryAssessment excludes delivery-only success and retained findings,
// including findings accepted by warn, suppression or observe policy.
func (r ResponseScanResult) RecoveryAssessment() InjectionAssessment {
	if !r.Clean || r.Failed() || len(r.Matches)+len(r.WarnedMatches)+len(r.SuppressedMatches)+len(r.ObservedCoreMatches) != 0 || r.StegoDetected {
		return InjectionAssessment{Checker: r.Assessment.Checker, Status: AssessmentNotAssessed}
	}
	return r.Assessment
}

func (s *Scanner) setInjectionAssessment(result *ResponseScanResult, assessed bool) {
	status := AssessmentNotAssessed
	switch {
	case result.Failed():
		status = AssessmentIncomplete
	case s.PromptInjectionMode() == config.ActionAllow:
		status = AssessmentOff
	case len(result.Matches)+len(result.WarnedMatches)+len(result.ObservedCoreMatches)+len(result.SuppressedMatches) > 0:
		status = AssessmentFinding
	case assessed || result.Assessment.Status == AssessmentBenign || result.Assessment.Status == AssessmentFinding ||
		result.Assessment.Status == AssessmentPartial:
		status = AssessmentBenign
		if !s.responseEnabled {
			status = AssessmentPartial
		}
	}
	result.Assessment = InjectionAssessment{Checker: InjectionCheckerBasic, Status: status}
}
