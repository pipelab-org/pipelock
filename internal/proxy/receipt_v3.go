// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"strings"

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
	}
	action.SetAttribution(opts)
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
	p.writeV3TransportOutcome(ctx, opts, action, entry.policy)
}

func (p *Proxy) recordTransportNotReleased(ctx context.Context, opts receipt.EmitOpts, entry *v3TransportReceipt) {
	action := entry.action
	action.Phase, action.OutcomeClass = "outcome", "not_released"
	action.Verdict, action.EffectRelation = config.ActionBlock, "not_attempted"
	p.writeV3TransportOutcome(ctx, opts, action, entry.policy)
}

func (p *Proxy) writeV3TransportOutcome(ctx context.Context, opts receipt.EmitOpts, action v3.Action, policy v3.PolicySnapshot) {
	if err := p.receiptV3.WriteAction(context.WithoutCancel(ctx), action, policy); err != nil {
		p.logReceiptEmissionFailure(opts, err)
	}
}
