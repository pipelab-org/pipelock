// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"

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
	if p == nil || !p.receiptEffects.enabled || opts.Verdict != config.ActionBlock {
		return
	}
	opts.ActionID = receipt.NewActionID()
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

func writeReceiptEffectRefusal(w http.ResponseWriter, requestID string) {
	writeBlockedError(w, blockInfoFor(blockreason.ReceiptEmissionFailed, "receipt").WithRequestID(requestID),
		"blocked: receipt admission failed", http.StatusForbidden)
}

func (p *Proxy) confirmObservedEffect(ctx context.Context, opts receipt.EmitOpts, token *proxyEffectToken, observed bool) {
	if token != nil && observed {
		if err := token.ConfirmDelivery(ctx, func() (bool, error) { return true, nil }); err != nil {
			p.logReceiptEmissionFailure(opts, err)
		}
	}
}

func (p *Proxy) settleEffect(ctx context.Context, opts receipt.EmitOpts, token *proxyEffectToken) {
	if err := token.SettleOnExit(ctx); err != nil {
		p.logReceiptEmissionFailure(opts, err)
	}
}

type reverseReceiptEffectKey struct{}

type reverseReceiptEffect struct {
	owner   *Proxy
	cfg     *config.Config
	options receipt.EmitOpts
}

func roundTripReceiptEffect(base http.RoundTripper, req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	effect, ok := ctx.Value(reverseReceiptEffectKey{}).(reverseReceiptEffect)
	if !ok || effect.owner == nil || !effect.owner.receiptEffects.enabled {
		return base.RoundTrip(req)
	}
	token, err := effect.owner.admitEffect(ctx, effect.cfg, effect.options, boundaryUpstreamSend)
	if err != nil {
		return nil, newReceiptEmissionBlockedRequest(err)
	}
	defer effect.owner.settleEffect(ctx, effect.options, token)
	resp, err := base.RoundTrip(req)
	effect.owner.confirmObservedEffect(ctx, effect.options, token, resp != nil)
	return resp, err
}

type fetchReceiptEffectKey struct{}

type fetchReceiptEffect struct {
	p    *Proxy
	cfg  *config.Config
	opts receipt.EmitOpts
}

func (s *fetchReceiptEffect) redirect(req *http.Request, cfg *config.Config, gate ContractGateOutput) {
	s.opts = withContractReceipt(gate, receipt.EmitOpts{
		ActionID: receipt.NewActionID(), ParentActionID: s.opts.ActionID,
		Transport: s.opts.Transport, RequestID: s.opts.RequestID, Agent: s.opts.Agent,
		Target: req.URL.String(), Method: req.Method, Verdict: gate.Verdict,
	})
	s.cfg = cfg
}

type fetchReceiptTransport struct {
	base http.RoundTripper
}

func (t fetchReceiptTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	s, ok := ctx.Value(fetchReceiptEffectKey{}).(*fetchReceiptEffect)
	if !ok {
		return t.base.RoundTrip(req)
	}
	opts := s.opts
	token, err := s.p.admitEffect(ctx, s.cfg, opts, boundaryUpstreamSend)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, newReceiptEmissionBlockedRequest(err)
	}
	defer s.p.settleEffect(ctx, opts, token)
	resp, err := t.base.RoundTrip(req)
	s.p.confirmObservedEffect(ctx, opts, token, resp != nil)
	return resp, err
}

func (p *Proxy) startFetchReceiptEffects(req *http.Request, cfg *config.Config, opts receipt.EmitOpts) (*http.Request, *fetchReceiptEffect) {
	if !p.receiptEffects.enabled {
		return req, nil
	}
	state := &fetchReceiptEffect{p: p, cfg: cfg, opts: opts}
	return req.WithContext(context.WithValue(req.Context(), fetchReceiptEffectKey{}, state)), state
}

func receiptEffectContext(opts receipt.EmitOpts) context.Context {
	if opts.ContentScanContext != nil {
		return opts.ContentScanContext
	}
	return context.Background()
}

func boundaryForProxyDecision(transport string) string {
	if transport == TransportConnect {
		return boundaryTunnelOpen
	}
	return boundaryUpstreamSend
}

func (r *wsRelay) writeReceiptFrame(ctx context.Context, boundary string, write func() error) error {
	if !r.proxy.receiptEffects.enabled {
		return write()
	}
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), ParentActionID: r.requestActionID,
		Verdict: config.ActionAllow, Transport: TransportWS, Method: "WS",
		Target: r.targetURL, RequestID: r.requestID, Agent: r.agent,
	}
	token, err := r.proxy.admitEffect(ctx, r.cfg, opts, boundary)
	if err != nil {
		return err
	}
	defer r.proxy.settleEffect(ctx, opts, token)
	err = write()
	r.proxy.confirmObservedEffect(ctx, opts, token, err == nil)
	return err
}
