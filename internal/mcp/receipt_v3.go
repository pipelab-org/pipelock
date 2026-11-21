// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

const (
	mcpUpstreamSendBoundary       = "upstream_send"
	mcpDownstreamDeliveryBoundary = "downstream_delivery"
)

type mcpReceiptEffects struct {
	gate    v3.EffectGate
	enabled bool
}

// WithV3ReceiptWriter supplies the effect receipt stream for a proxy invocation.
// The caller owns the stream lifecycle.
func (o MCPProxyOpts) WithV3ReceiptWriter(writer *v3.StreamWriter) MCPProxyOpts {
	o.receiptEffects = mcpReceiptEffects{gate: v3.NewEffectGate(writer), enabled: writer != nil}
	return o
}

func (o MCPProxyOpts) v3EffectAction(opts receipt.EmitOpts, boundary string) (v3.Action, v3.PolicySnapshot) {
	actor := opts.Agent
	if actor == "" {
		actor = "pipelock"
	}
	actionType := receipt.ClassifyMCPTool("", opts.Method)
	action := v3.Action{
		ActionID: opts.ActionID, ParentActionID: opts.ParentActionID, EffectBoundary: boundary,
		ActionType: string(actionType), Actor: actor, Principal: "local", Caller: v3.Caller{Authn: "none"},
		Data: v3.Data{
			SideEffectClass: string(receipt.SideEffectNone),
			Reversibility:   string(receipt.ReversibilityUnknown),
		},
		Layer: opts.Layer, Method: opts.Method, Pattern: opts.Pattern, RequestID: opts.RequestID,
		Severity: opts.Severity, Target: receipt.SanitizeSignedTarget(opts.Target, nil),
		Transport: opts.Transport, Verdict: opts.Verdict,
	}
	action.SetAttribution(opts)
	digest := opts.PolicyHash
	if digest == "" {
		digest = o.receiptPolicyHash()
	}
	if digest != "" && !strings.HasPrefix(digest, "sha256:") {
		digest = "sha256:" + digest
	}
	return action, v3.CapturePolicy(digest)
}

func (o MCPProxyOpts) admitV3Effect(ctx context.Context, evidence receipt.EmitOpts, boundary string) (*v3.EffectToken, error) {
	if !o.receiptEffects.enabled {
		return nil, nil
	}
	action, policy := o.v3EffectAction(evidence, boundary)
	return o.receiptEffects.gate.Admit(ctx, action, policy)
}

func (o MCPProxyOpts) refuseV3Effect(ctx context.Context, evidence receipt.EmitOpts, boundary string) error {
	if !o.receiptEffects.enabled {
		return nil
	}
	action, policy := o.v3EffectAction(evidence, boundary)
	return o.receiptEffects.gate.Refuse(ctx, action, policy)
}

func mcpV3ReplyEvidence(request receipt.EmitOpts) receipt.EmitOpts {
	return receipt.EmitOpts{
		ActionID: receipt.NewActionID(), ParentActionID: request.ActionID, RequestID: request.RequestID,
		Transport: request.Transport, Method: request.Method, PolicyHash: request.PolicyHash,
		Agent: request.Agent, Target: "mcp://response", Verdict: config.ActionAllow,
	}
}

func confirmMCPV3Effect(ctx context.Context, token *v3.EffectToken, observed bool) error {
	return token.ConfirmDelivery(ctx, func() (bool, error) { return observed, nil })
}
