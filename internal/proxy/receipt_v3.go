// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

const (
	boundaryUpstreamSend       = "upstream_send"
	boundaryTunnelOpen         = "tunnel_open"
	boundaryDownstreamDelivery = "downstream_delivery"
)

type v3TransportReceipt struct {
	action v3.Action
	policy v3.PolicySnapshot
}

func (p *Proxy) confirmTransportReceipt(ctx context.Context, cfg *config.Config, opts receipt.EmitOpts, boundary string) (*v3TransportReceipt, error) {
	attempt := int64(1)
	actor := opts.Agent
	if actor == "" {
		actor = "pipelock"
	}
	action := v3.Action{
		ActionID: opts.ActionID, ParentActionID: opts.ParentActionID,
		ActionType: string(receipt.ClassifyHTTP(opts.Method)), Actor: actor, Principal: "local",
		Attempt: &attempt, Caller: v3.Caller{Authn: "none"},
		Data: v3.Data{
			SideEffectClass: string(receipt.SideEffectFromMethod(opts.Method)),
			Reversibility:   string(receipt.ReversibilityFromMethod(opts.Method)),
		},
		EffectBoundary: boundary, EffectRelation: "before", Phase: "intent",
		Layer: opts.Layer, Method: opts.Method, Pattern: opts.Pattern,
		RequestID: opts.RequestID, Severity: opts.Severity,
		Target: receipt.SanitizeSignedTarget(opts.Target, nil), Transport: opts.Transport, Verdict: opts.Verdict,
		Session: v3HTTPSession(opts), Taint: v3HTTPTaint(opts), Contract: v3HTTPContract(opts),
		Redaction: v3HTTPRedaction(opts),
	}
	// cfg is the request snapshot retained by the effect producer.
	digest := cfg.CanonicalPolicyHash()
	if digest != "" && !strings.HasPrefix(digest, "sha256:") {
		digest = "sha256:" + digest
	}
	policy := v3.CapturePolicy(digest)
	if err := p.receiptV3.WriteAction(ctx, action, policy); err != nil {
		p.recordRequiredReceiptBlock(err, opts.Transport)
		p.logReceiptEmissionFailure(opts, err)
		return nil, err
	}
	return &v3TransportReceipt{action: action, policy: policy}, nil
}

func (p *Proxy) recordTransportOutcome(ctx context.Context, opts receipt.EmitOpts, entry *v3TransportReceipt, completed bool) {
	if entry == nil {
		return
	}
	action := entry.action
	action.Phase = "outcome"
	if completed {
		action.OutcomeClass, action.EffectRelation = "completed", "after"
	} else {
		action.OutcomeClass, action.EffectRelation = "attempt_unknown", "unknown"
	}
	if err := p.receiptV3.WriteAction(context.WithoutCancel(ctx), action, entry.policy); err != nil {
		p.logReceiptEmissionFailure(opts, err)
	}
}

func v3HTTPSession(opts receipt.EmitOpts) *v3.Session {
	value := v3.Session{
		ID: opts.SessionID, OriginalID: opts.SessionIDOriginal, TaskID: opts.SessionTaskID,
		TaskLabel: opts.SessionTaskLabel, TaintLevel: opts.SessionTaintLevel,
	}
	if opts.SessionTaintLevel != "" || opts.SessionContaminated {
		value.Contaminated = &opts.SessionContaminated
	}
	for _, src := range opts.RecentTaintSources {
		value.TaintSources = append(value.TaintSources, v3.TaintSource{
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

func v3HTTPTaint(opts receipt.EmitOpts) *v3.Taint {
	if opts.AuthorityKind == "" && opts.TaintDecision == "" && opts.TaintDecisionReason == "" && !opts.TaskOverrideApplied {
		return nil
	}
	return &v3.Taint{
		AuthorityKind: opts.AuthorityKind, Decision: opts.TaintDecision,
		Reason: opts.TaintDecisionReason, TaskOverrideApplied: &opts.TaskOverrideApplied,
	}
}

func v3HTTPContract(opts receipt.EmitOpts) *v3.Contract {
	if !hasContractContext(opts) {
		return nil
	}
	value := v3.Contract{
		Hash: opts.ContractHash, ManifestHash: opts.ActiveManifestHash,
		SelectorID: opts.ContractSelectorID, RuleID: opts.ContractRuleID,
		WinningSource: opts.ContractWinningSource, LiveVerdict: opts.ContractLiveVerdict,
		PolicySources: opts.ContractPolicySources,
	}
	if opts.ContractGeneration > 0 {
		generation := int64(opts.ContractGeneration) //nolint:gosec // The writer rejects negative and out-of-range generations.
		value.Generation = &generation
	}
	return &value
}

func v3HTTPRedaction(opts receipt.EmitOpts) *v3.Redaction {
	report := opts.RedactionReport
	if report == nil || !report.Applied || report.TotalRedactions == 0 {
		return nil
	}
	total := int64(report.TotalRedactions)
	value := v3.Redaction{
		Profile: opts.RedactionProfile, Provider: report.Provider, Parser: report.Parser, TotalRedactions: &total,
	}
	for class, count := range report.ByClass {
		value.Classes = append(value.Classes, v3.RedactionClass{Class: string(class), Count: int64(count)})
	}
	slices.SortFunc(value.Classes, func(a, b v3.RedactionClass) int { return strings.Compare(a.Class, b.Class) })
	return &value
}
