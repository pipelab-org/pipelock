// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
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
	actionType := receipt.ClassifyMCPTool(opts.Target, opts.Method)
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

type mcpV3Exchange struct {
	request receipt.EmitOpts
	token   *v3.EffectToken
}

type mcpV3Session struct {
	mu      sync.Mutex
	pending map[string]*mcpV3Exchange
	closed  bool
}

func (o MCPProxyOpts) withV3Session() MCPProxyOpts {
	if o.receiptEffects.enabled {
		o.v3Session = &mcpV3Session{pending: make(map[string]*mcpV3Exchange)}
	}
	return o
}

func (o MCPProxyOpts) startV3Send(ctx context.Context, frame MCPFrame, actionID string) (*mcpV3Exchange, error) {
	if !o.receiptEffects.enabled {
		return nil, nil
	}
	if actionID == "" {
		actionID = receipt.NewActionID()
	}
	request := receipt.EmitOpts{
		ActionID: actionID, RequestID: canonicalID(frame.ID), Method: frame.Method,
		Transport: o.Transport, Target: firstNonEmpty(frame.ToolCallName, frame.Method),
		Verdict: config.ActionAllow, PolicyHash: o.receiptPolicyHash(),
	}
	token, err := o.admitV3Effect(ctx, request, mcpUpstreamSendBoundary)
	if err != nil {
		return nil, err
	}

	return &mcpV3Exchange{request: request, token: token}, nil
}

// bindV3Send only mutates request correlation. It runs within the send claim,
// immediately before the transport can expose the request.
func (o MCPProxyOpts) bindV3Send(x *mcpV3Exchange) error {
	if x == nil || x.request.RequestID == "" {
		return nil
	}
	s := o.v3Session
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return context.Canceled
	}
	if _, occupied := s.pending[x.request.RequestID]; occupied {
		return errors.New("request ID already awaiting a v3 receipt outcome")
	}
	s.pending[x.request.RequestID] = x
	return nil
}

func (o MCPProxyOpts) finishV3Send(ctx context.Context, log io.Writer, x *mcpV3Exchange, attempted bool) {
	if x == nil {
		return
	}
	s := o.v3Session
	s.mu.Lock()
	if s.pending[x.request.RequestID] == x {
		delete(s.pending, x.request.RequestID)
	}
	s.mu.Unlock()
	if attempted {
		logMCPV3Error(log, x.token.SettleOnExit(ctx))
	} else {
		logMCPV3Error(log, x.token.Refuse(ctx))
	}
}

func (o MCPProxyOpts) settleV3Session(ctx context.Context, log io.Writer) {
	if o.v3Session == nil {
		return
	}
	s := o.v3Session
	s.mu.Lock()
	pending := s.pending
	s.pending = nil
	s.closed = true
	s.mu.Unlock()
	for _, x := range pending {
		logMCPV3Error(log, x.token.SettleOnExit(ctx))
	}
}

func (o MCPProxyOpts) v3ResponseWriter(ctx context.Context, log io.Writer, writer transport.MessageWriter, line []byte, id json.RawMessage) transport.MessageWriter {
	if o.v3Session == nil || isRequest(line) {
		return writer
	}
	if !isResponse(line) || canonicalID(id) == "" {
		return mcpV3WithheldWriter{}
	}
	s := o.v3Session
	key := canonicalID(id)
	s.mu.Lock()
	x := s.pending[key]
	delete(s.pending, key)
	s.mu.Unlock()
	if x == nil {
		return mcpV3WithheldWriter{}
	}
	logMCPV3Error(log, confirmMCPV3Effect(ctx, x.token, true))
	return &mcpV3ReplyWriter{base: writer, opts: o, log: log, request: x.request}
}

// Unpaired local errors have no upstream action to link to.
type mcpV3WithheldWriter struct{}

func (mcpV3WithheldWriter) WriteMessage([]byte) error { return nil }

func (o MCPProxyOpts) localV3ReplyWriter(writer transport.MessageWriter) transport.MessageWriter {
	if o.v3Session != nil {
		return mcpV3WithheldWriter{}
	}
	return writer
}

type mcpV3ReplyWriter struct {
	base     transport.MessageWriter
	opts     MCPProxyOpts
	log      io.Writer
	request  receipt.EmitOpts
	finished bool
}

func (w *mcpV3ReplyWriter) WriteMessage(msg []byte) error {
	if w.finished {
		return nil
	}
	w.finished = true
	ctx := w.opts.warnContext()
	evidence := mcpV3ReplyEvidence(w.request)
	token, err := w.opts.admitV3Effect(ctx, evidence, mcpDownstreamDeliveryBoundary)
	if err != nil {
		return fmt.Errorf("MCP reply receipt admission: %w", err)
	}
	if err := ctx.Err(); err != nil {
		logMCPV3Error(w.log, token.Refuse(ctx))
		return err
	}
	err = w.base.WriteMessage(msg)
	logMCPV3Error(w.log, confirmMCPV3Effect(ctx, token, err == nil))
	return err
}

func (w *mcpV3ReplyWriter) writeDeniedMessage([]byte) error {
	if w.finished {
		return nil
	}
	w.finished = true
	return w.opts.refuseV3Effect(w.opts.warnContext(), mcpV3ReplyEvidence(w.request), mcpDownstreamDeliveryBoundary)
}

func logMCPV3Error(log io.Writer, err error) {
	if err != nil {
		_, _ = fmt.Fprintf(log, "pipelock: MCP v3 receipt: %v\n", err)
	}
}

func (o MCPProxyOpts) v3OnlyHold() bool {
	return o.v3Session != nil && o.receiptEmitter() == nil && o.v2ReceiptEmitter() == nil && o.ReceiptGroup == nil
}

func (o MCPProxyOpts) confirmV3Hold(held *deferred.HeldAction, frame MCPFrame) {
	if o.v3Session == nil {
		return
	}
	const approvalBoundary = "approval_prompt"
	evidence := receipt.EmitOpts{
		ActionID: held.ActionID, RequestID: canonicalID(frame.ID), Method: held.Method,
		Transport: o.Transport, Target: held.Target, PolicyHash: o.receiptPolicyHash(),
	}
	act, policy := o.v3EffectAction(evidence, approvalBoundary)
	held.ConfirmHold = func(ctx context.Context, h deferred.HeldAction) error {
		hold := act
		hold.Phase, hold.Verdict, hold.EffectRelation = "hold", config.ActionDefer, "before"
		hold.Hold = &v3.Hold{ID: h.DeferID, Policy: deferred.ReceiptPolicyString(h.Policy, h.RulePolicy)}
		return o.receiptEffects.gate.RecordApproval(ctx, hold, policy)
	}
	held.ConfirmResolution = func(ctx context.Context, res deferred.Resolution) error {
		resolution := act
		resolution.Phase, resolution.Verdict, resolution.EffectRelation = "resolution", res.FinalDecision, "after"
		if res.FinalDecision == config.ActionStepUp {
			resolution.Verdict = config.ActionAsk
		}
		resolution.Hold = &v3.Hold{
			ID: res.DeferID, ResolutionSource: res.ResolutionSource,
			ResolutionPolicy: deferred.ReceiptPolicyStringFor(deferred.ReceiptPolicyOptions{Bounds: res.Policy}),
		}
		return o.receiptEffects.gate.RecordApproval(ctx, resolution, policy)
	}
}

func (o MCPProxyOpts) claimV3DeferredSend(ctx context.Context, log io.Writer, frame MCPFrame, res deferred.Resolution, mu sync.Locker, generation uint64) (*mcpV3Exchange, func(), string) {
	effect, err := o.startV3Send(ctx, frame, res.ParentActionID)
	if err != nil {
		logMCPV3Error(log, err)
		return nil, nil, "receipt admission failed"
	}
	prepared, finish := lockAndClaimDeferredRelease(mu, o, generation, res)
	if finish != nil && prepared.FinalDecision == config.ActionAllow && ctx.Err() == nil {
		return effect, sync.OnceFunc(finish), ""
	}
	if finish != nil {
		finish()
	}
	o.finishV3Send(ctx, log, effect, false)
	return nil, nil, firstNonEmpty(prepared.Reason, "request cancelled")
}

// mcpV3StreamDelivery admits the first event before acquiring the underlying
// writer's lock. The final framing is unproven even after successful events.
type mcpV3StreamDelivery struct {
	base     transport.MessageWriter
	opts     MCPProxyOpts
	log      io.Writer
	evidence receipt.EmitOpts
	token    *v3.EffectToken
	started  bool
}

func (w *mcpV3StreamDelivery) WriteMessage(msg []byte) error {
	ctx := w.opts.warnContext()
	if !w.started {
		token, err := w.opts.admitV3Effect(ctx, w.evidence, mcpDownstreamDeliveryBoundary)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			logMCPV3Error(w.log, token.Refuse(ctx))
			return err
		}
		w.token, w.started = token, true
	}
	return w.base.WriteMessage(msg)
}

func (w *mcpV3StreamDelivery) writeDeniedMessage([]byte) error {
	evidence := w.evidence
	evidence.ActionID = receipt.NewActionID()
	return w.opts.refuseV3Effect(w.opts.warnContext(), evidence, mcpDownstreamDeliveryBoundary)
}

func (w *mcpV3StreamDelivery) finish() {
	logMCPV3Error(w.log, w.token.SettleOnExit(w.opts.warnContext()))
}
