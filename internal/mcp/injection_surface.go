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
// with no definitions has no description text and adds nothing.
func toolsListRecoveryAssessment(envelope scanner.InjectionAssessment, result tools.ToolScanResult) scanner.InjectionAssessment {
	if !result.IsToolsList || (len(result.ToolDefs) == 0 && result.Assessment.Status == scanner.AssessmentNotAssessed) {
		return envelope
	}
	return envelope.Merge(result.Assessment)
}
