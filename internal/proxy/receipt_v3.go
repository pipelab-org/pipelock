// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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
	actions := receiptActionBatch(ctx, cfg, opts, boundary)
	var token *proxyEffectToken
	var err error
	if len(actions) == 0 {
		token, err = p.receiptEffects.gate.Admit(ctx, action, policy)
	} else {
		token, err = p.receiptEffects.gate.AdmitBatch(ctx, append([]v3.Action{action}, actions...), policy)
	}
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
	owner    *Proxy
	cfg      *config.Config
	options  receipt.EmitOpts
	delivery *v3DeliveryWriter
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

type proxyEffectEvidenceKey struct{}

type proxyEffectEvidence struct {
	mu       sync.Mutex
	allows   []scanner.CredentialAudienceAllow
	upstream []receipt.EmitOpts
	response []receipt.EmitOpts
}

func (p *Proxy) withReceiptEvidence(r *http.Request) *http.Request {
	if p == nil || !p.receiptEffects.enabled {
		return r
	}
	return r.WithContext(withReceiptEvidenceContext(r.Context()))
}

func withReceiptEvidenceContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, proxyEffectEvidenceKey{}, &proxyEffectEvidence{})
}

func withReceiptCredentialContext(opts receipt.EmitOpts, ctx context.Context) receipt.EmitOpts {
	if _, ok := ctx.Value(proxyEffectEvidenceKey{}).(*proxyEffectEvidence); ok {
		opts.ContentScanContext = ctx
	}
	return opts
}

func collectReceiptCredentialEvidence(ctx context.Context, allows []scanner.CredentialAudienceAllow) {
	if evidence, ok := ctx.Value(proxyEffectEvidenceKey{}).(*proxyEffectEvidence); ok && len(allows) != 0 {
		evidence.mu.Lock()
		evidence.allows = append(evidence.allows, allows...)
		evidence.mu.Unlock()
	}
}

func receiptActionBatch(ctx context.Context, cfg *config.Config, opts receipt.EmitOpts, boundary string) []v3.Action {
	evidence, ok := ctx.Value(proxyEffectEvidenceKey{}).(*proxyEffectEvidence)
	if !ok {
		return nil
	}
	if boundary == boundaryDownstreamDelivery {
		return receiptResponseBatch(evidence, cfg, opts)
	}
	allows, supporting := evidence.takeUpstream()
	for _, allow := range uniqueCredentialAudienceAllows(allows) {
		decision := opts
		decision.Verdict, decision.Layer = config.ActionAllow, credentialAudienceReceiptExtensionKey
		decision.Pattern = allow.PatternName
		supporting = append(supporting, decision)
	}
	return receiptSupportingActions(cfg, opts, boundary, supporting)
}

func resetReceiptCredentialEvidence(ctx context.Context) {
	if evidence, ok := ctx.Value(proxyEffectEvidenceKey{}).(*proxyEffectEvidence); ok {
		evidence.takeUpstream()
	}
}

func (e *proxyEffectEvidence) takeUpstream() ([]scanner.CredentialAudienceAllow, []receipt.EmitOpts) {
	e.mu.Lock()
	defer e.mu.Unlock()
	allows, upstream := e.allows, e.upstream
	e.allows, e.upstream = nil, nil
	return allows, upstream
}

func (p *Proxy) refuseAdmittedEffect(ctx context.Context, opts receipt.EmitOpts, token *proxyEffectToken) {
	if err := token.Refuse(ctx); err != nil {
		p.logReceiptEmissionFailure(opts, err)
	}
}

func collectReceiptResponseEvidence(opts receipt.EmitOpts, request []context.Context) {
	if len(request) == 0 {
		return
	}
	switch opts.Verdict {
	case config.ActionAllow, config.ActionWarn, config.ActionStrip, config.ActionForward, config.ActionRedirect:
	default:
		return
	}
	if evidence, ok := request[0].Value(proxyEffectEvidenceKey{}).(*proxyEffectEvidence); ok {
		evidence.mu.Lock()
		evidence.response = append(evidence.response, opts)
		evidence.mu.Unlock()
	}
}

func receiptResponseBatch(evidence *proxyEffectEvidence, cfg *config.Config, opts receipt.EmitOpts) []v3.Action {
	evidence.mu.Lock()
	supporting := evidence.response
	evidence.response = nil
	evidence.mu.Unlock()
	return receiptSupportingActions(cfg, opts, boundaryDownstreamDelivery, supporting)
}

func collectReceiptUpstreamEvidence(ctx context.Context, opts receipt.EmitOpts) {
	if evidence, ok := ctx.Value(proxyEffectEvidenceKey{}).(*proxyEffectEvidence); ok {
		evidence.mu.Lock()
		evidence.upstream = append(evidence.upstream, opts)
		evidence.mu.Unlock()
	}
}

func receiptSupportingActions(cfg *config.Config, opts receipt.EmitOpts, boundary string, supporting []receipt.EmitOpts) []v3.Action {
	actions := make([]v3.Action, 0, len(supporting))
	for _, decision := range supporting {
		decision.ActionID, decision.ParentActionID = receipt.NewActionID(), opts.ActionID
		decision.Transport, decision.Method = opts.Transport, opts.Method
		if decision.Target == "" {
			decision.Target = opts.Target
		}
		action, _ := prepareV3TransportReceipt(cfg, decision, boundary)
		actions = append(actions, action)
	}
	return actions
}
