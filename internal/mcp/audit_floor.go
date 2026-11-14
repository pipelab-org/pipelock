// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// auditObservedAction turns a configured block or ask into warn while audit
// mode is observing that contributor. Redirect, defer, and every other action
// pass through. Callers pass only a contributor they have already classified
// as liftable.
func auditObservedAction(audit bool, action string) string {
	if audit && (action == config.ActionBlock || action == config.ActionAsk) {
		return config.ActionWarn
	}
	return action
}

// policyAuditAction observes a matched rule's block or ask. Only a verdict
// the policy marks as a rule decision is observed; one raised because the
// arguments could not be inspected keeps its action.
func policyAuditAction(audit bool, verdict policy.Verdict) string {
	if !verdict.RuleDecision {
		return verdict.Action
	}
	return auditObservedAction(audit, verdict.Action)
}

// chainAuditAction observes a matched pattern's action. A verdict that is
// not a pattern match, such as a call the matcher could not track, keeps its
// block.
func chainAuditAction(audit bool, verdict chains.Verdict) string {
	if !verdict.PatternMatch {
		return verdict.Action
	}
	return auditObservedAction(audit, verdict.Action)
}

// auditContentAction is the content contributor's action after the audit
// lift. A verdict is lifted only when every finding in it is configured
// policy; one floor finding keeps the effective action.
func auditContentAction(audit bool, verdict InputVerdict, configuredAction string) string {
	action := inputVerdictEffectiveAction(verdict, configuredAction)
	if !audit || !contentVerdictLiftable(verdict) {
		return action
	}
	return auditObservedAction(true, action)
}

// contentVerdictLiftable reports whether every finding in verdict is
// configured policy. A URL finding is never observed: the URL scan stops at
// its first failing stage, so an allowlist or blocklist finding says nothing
// about the private-address, metadata and credential checks that run after
// it, and a tool-supplied URL is never dialed here where a later check could
// refuse it.
func contentVerdictLiftable(verdict InputVerdict) bool {
	if verdict.Error != "" || len(verdict.URLFindings) > 0 {
		return false
	}
	if scanner.ContainsCoreCriticalMatch(verdict.Matches) ||
		scanner.ContainsHostnameExfilMatch(verdict.Matches) ||
		scanner.HasInspectionLimit(verdict.Matches) {
		return false
	}
	for _, match := range verdict.Matches {
		if match.PatternName == uninspectableSplitSecretFieldsReason {
			return false
		}
	}
	return len(verdict.Matches) > 0 || len(verdict.Inject) > 0 || len(verdict.AddressFindings) > 0
}

// a2aAuditAction observes a completed A2A content block. Inspection, config,
// budget, infrastructure, and core findings stay blocked. Ask is unchanged.
func a2aAuditAction(audit bool, result A2AScanResult, action string) string {
	if !audit || action != config.ActionBlock || !a2aContentLiftable(result) {
		return action
	}
	return config.ActionWarn
}

func a2aContentLiftable(result A2AScanResult) bool {
	// A URL finding is never observed, for the reason given on
	// contentVerdictLiftable.
	if result.InspectionIncomplete || result.ScanError != "" || result.IsConfigMismatch() || len(result.URLFindings) > 0 {
		return false
	}
	if result.BudgetExceeded {
		return false
	}
	if mcpA2AOperationalURLFindingsOnly(result) {
		return false
	}
	if scanner.ContainsCoreCriticalMatch(result.DLPFindings) ||
		scanner.ContainsHostnameExfilMatch(result.DLPFindings) ||
		scanner.HasInspectionLimit(result.DLPFindings) {
		return false
	}
	for _, match := range result.DLPFindings {
		if match.PatternName == uninspectableSplitSecretFieldsReason {
			return false
		}
	}
	return len(result.DLPFindings) > 0 || len(result.InjectFindings) > 0 || result.EntropyFinding != nil
}

// observeBaselineAudit lifts a deviation found by a completed check. A
// decision without that mark, such as a failed check, keeps its block.
func observeBaselineAudit(opts MCPProxyOpts, decision session.BaselineDecision) session.BaselineDecision {
	if !decision.Deviation {
		return decision
	}
	lifted := auditObservedAction(opts.auditMode(), decision.Action)
	if lifted == decision.Action {
		return decision
	}
	decision.Action = lifted
	decision.Blocked = false
	return decision
}
