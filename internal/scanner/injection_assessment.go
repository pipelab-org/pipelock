// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "github.com/luckyPipewrench/pipelock/internal/config"

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
