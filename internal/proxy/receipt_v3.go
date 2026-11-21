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
	transportInterceptReceipt  = "intercept"
	boundaryUpstreamSend       = "upstream_send"
	boundaryTunnelOpen         = "tunnel_open"
	boundaryDownstreamDelivery = "downstream_delivery"
)

type proxyReceiptEffects struct {
	gate    v3.EffectGate
	enabled bool
}

// WithV3ReceiptWriter supplies the receipt stream used at proxy effect
// boundaries. The caller retains responsibility for the stream lifecycle.
func WithV3ReceiptWriter(writer *v3.StreamWriter) Option {
	return func(p *Proxy) {
		p.receiptEffects = proxyReceiptEffects{gate: v3.NewEffectGate(writer), enabled: writer != nil}
	}
}

type proxyEffectToken = v3.EffectToken

func (p *Proxy) admitEffect(ctx context.Context, cfg *config.Config, opts receipt.EmitOpts, boundary string) (*proxyEffectToken, error) {
	if p == nil || !p.receiptEffects.enabled {
		return nil, nil
	}
	action, policy := prepareV3TransportReceipt(cfg, opts, boundary)
	token, err := p.receiptEffects.gate.Admit(ctx, action, policy)
	if err != nil {
		p.logReceiptEmissionFailure(opts, err)
	}
	return token, err
}

func (p *Proxy) refuseEffect(ctx context.Context, cfg *config.Config, opts receipt.EmitOpts, boundary string) {
	if p == nil || !p.receiptEffects.enabled {
		return
	}
	action, policy := prepareV3TransportReceipt(cfg, opts, boundary)
	if err := p.receiptEffects.gate.Refuse(ctx, action, policy); err != nil {
		p.logReceiptEmissionFailure(opts, err)
	}
}

func prepareV3TransportReceipt(cfg *config.Config, opts receipt.EmitOpts, boundary string) (v3.Action, v3.PolicySnapshot) {
	actor := opts.Agent
	if actor == "" {
		actor = "pipelock"
	}
	action := v3.Action{
		ActionID: opts.ActionID, ParentActionID: opts.ParentActionID, EffectBoundary: boundary,
		ActionType: string(receipt.ClassifyHTTP(opts.Method)), Actor: actor, Principal: "local",
		Caller: v3.Caller{Authn: "none"},
		Data: v3.Data{
			SideEffectClass: string(receipt.SideEffectFromMethod(opts.Method)),
			Reversibility:   string(receipt.ReversibilityFromMethod(opts.Method)),
		},
		Layer: opts.Layer, Method: opts.Method, Pattern: opts.Pattern,
		RequestID: opts.RequestID, Severity: opts.Severity,
		Target: receipt.SanitizeSignedTarget(opts.Target, nil), Transport: opts.Transport, Verdict: opts.Verdict,
	}
	action.SetAttribution(opts)
	// Prefer the producer's decision-time policy, which can be newer than cfg.
	digest := opts.PolicyHash
	if digest == "" && cfg != nil {
		digest = cfg.CanonicalPolicyHash()
	}
	if digest != "" && !strings.HasPrefix(digest, "sha256:") {
		digest = "sha256:" + digest
	}
	return action, v3.CapturePolicy(digest)
}
