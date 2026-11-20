// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// SetAttribution copies optional attribution from the decision's receipt options.
func (a *Action) SetAttribution(opts receipt.EmitOpts) {
	a.Session = sessionAttribution(opts)
	a.Taint = taintAttribution(opts)
	a.Contract = contractAttribution(opts)
	a.Redaction = redactionAttribution(opts)
	a.Shield = shieldAttribution(opts.Shield)
}

func sessionAttribution(opts receipt.EmitOpts) *Session {
	value := Session{
		ID: opts.SessionID, OriginalID: opts.SessionIDOriginal, TaskID: opts.SessionTaskID,
		TaskLabel: opts.SessionTaskLabel, TaintLevel: opts.SessionTaintLevel,
	}
	if opts.SessionTaintLevel != "" || opts.SessionContaminated {
		value.Contaminated = &opts.SessionContaminated
	}
	for _, src := range opts.RecentTaintSources {
		if src.URL == "" {
			continue
		}
		value.TaintSources = append(value.TaintSources, TaintSource{
			Kind: src.Kind, Level: int64(src.Level), Timestamp: src.Timestamp.UTC().Format(time.RFC3339Nano),
			URL: receipt.SanitizeSignedTarget(src.URL, nil), ReceiptID: src.ReceiptID, MatchReason: src.MatchReason,
		})
	}
	if value.ID == "" && value.OriginalID == "" && value.TaskID == "" && value.TaskLabel == "" &&
		value.TaintLevel == "" && value.Contaminated == nil && len(value.TaintSources) == 0 {
		return nil
	}
	return &value
}

func taintAttribution(opts receipt.EmitOpts) *Taint {
	if opts.AuthorityKind == "" && opts.TaintDecision == "" && opts.TaintDecisionReason == "" && !opts.TaskOverrideApplied {
		return nil
	}
	return &Taint{
		AuthorityKind: opts.AuthorityKind, Decision: opts.TaintDecision,
		Reason: opts.TaintDecisionReason, TaskOverrideApplied: &opts.TaskOverrideApplied,
	}
}

func contractAttribution(opts receipt.EmitOpts) *Contract {
	if opts.ContractHash == "" && opts.ActiveManifestHash == "" && opts.ContractSelectorID == "" &&
		opts.ContractRuleID == "" && opts.ContractWinningSource == "" && opts.ContractLiveVerdict == "" &&
		len(opts.ContractPolicySources) == 0 && opts.ContractGeneration == 0 {
		return nil
	}
	value := Contract{
		Hash: opts.ContractHash, ManifestHash: opts.ActiveManifestHash,
		SelectorID: opts.ContractSelectorID, RuleID: opts.ContractRuleID,
		WinningSource: opts.ContractWinningSource, LiveVerdict: opts.ContractLiveVerdict,
		PolicySources: opts.ContractPolicySources,
	}
	switch generation := opts.ContractGeneration; {
	case generation > maxInteger:
		// Preserve rejection by the writer's unsigned field validation.
		invalid := int64(-1)
		value.Generation = &invalid
	case generation != 0:
		signed := int64(generation)
		value.Generation = &signed
	}
	return &value
}

func redactionAttribution(opts receipt.EmitOpts) *Redaction {
	report := opts.RedactionReport
	if report == nil || !report.Applied || report.TotalRedactions == 0 {
		return nil
	}
	total := int64(report.TotalRedactions)
	value := Redaction{
		Profile: opts.RedactionProfile, Provider: report.Provider, Parser: report.Parser, TotalRedactions: &total,
	}
	for class, count := range report.ByClass {
		value.Classes = append(value.Classes, RedactionClass{Class: string(class), Count: int64(count)})
	}
	slices.SortFunc(value.Classes, func(a, b RedactionClass) int { return strings.Compare(a.Class, b.Class) })
	return &value
}

func shieldAttribution(summary *receipt.ShieldSummary) *Shield {
	if summary == nil {
		return nil
	}
	count := func(value int) *int64 {
		if value == 0 {
			return nil
		}
		return new(int64(value))
	}
	shield := &Shield{
		Pipeline: summary.Pipeline, TotalRewrites: count(summary.TotalRewrites),
		ExtensionProbes: count(summary.ExtensionProbes), TrackingBeacons: count(summary.TrackingBeacons),
		AgentTraps: count(summary.AgentTraps), SVGForeignObjects: count(summary.SVGForeignObjects),
		SVGEventHandlers: count(summary.SVGEventHandlers), SVGExternalReferences: count(summary.SVGExternalReferences),
		SVGHiddenText: count(summary.SVGHiddenText), SVGAnimationInjections: count(summary.SVGAnimationInjections),
		BodyBytes: count(summary.BodyBytes), ScannedBytes: count(summary.ScannedBytes),
		AdaptiveSignalsRecorded: count(summary.AdaptiveSignalsRecorded), AdaptiveSignalMaxPerBody: count(summary.AdaptiveSignalMaxPerBody),
	}
	if summary.FingerprintShimInjected {
		shield.FingerprintShimInjected = new(true)
	}
	if summary.Partial {
		shield.Partial = new(true)
	}
	return shield
}
