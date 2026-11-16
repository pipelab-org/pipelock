// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// toolsListRecoveryAssessment combines the envelope assessment of a tools/list
// response with the assessment of its tool descriptions. Descriptions are a
// separately selectable surface, so an envelope assessed benign must not earn
// clean credit for descriptions that were off, warned or unassessed. A list
// with no definitions earns nothing either.
func toolsListRecoveryAssessment(envelope scanner.InjectionAssessment, result tools.ToolScanResult) scanner.InjectionAssessment {
	if !result.IsToolsList {
		return envelope
	}
	if len(result.ToolDefs) == 0 && result.Assessment.Status == scanner.AssessmentNotAssessed {
		// An empty inventory has no descriptions to vouch for it. Its
		// envelope can reach here assessed (header-contract-only scanning
		// sends tools/list through the general response path), but a
		// tools/list never earns clean credit.
		return scanner.InjectionAssessment{Status: scanner.AssessmentNotAssessed}
	}
	return envelope.Merge(result.Assessment)
}
