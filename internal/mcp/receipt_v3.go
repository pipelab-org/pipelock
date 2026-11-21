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

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

const (
	mcpV3RedirectRefusal          = "pipelock: policy redirect is not available while v3 receipts are enabled"
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
	o.receiptEffects = mcpReceiptEffects{
		gate:    v3.NewEffectGate(writer).WithFinalizationTimeout(o.shutdownGrace()),
		enabled: writer != nil,
	}
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

func (o MCPProxyOpts) refuseV3Reply(ctx context.Context, evidence receipt.EmitOpts) error {
	if !o.receiptEffects.enabled {
		return nil
	}
	action, policy := o.v3EffectAction(evidence, mcpDownstreamDeliveryBoundary)
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
	if err != nil && !errors.Is(err, v3.ErrActionVisible) {
		return nil, err
	}
	return &mcpV3Exchange{request: request, token: token}, err
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

func (o MCPProxyOpts) v3ResponseWriter(ctx context.Context, log io.Writer, writer transport.MessageWriter, line []byte, frame MCPFrame) transport.MessageWriter {
	if o.v3Session == nil {
		return writer
	}
	if isRequest(line) {
		if o.Transport != deferred.SurfaceMCPWS {
			return writer
		}
		// Server-initiated messages have their own delivery effect, with no
		// matching client request to use as a parent.
		request := receipt.EmitOpts{RequestID: canonicalID(frame.ID), Method: frame.Method, Transport: o.Transport}
		return &mcpV3ReplyWriter{base: writer, opts: o, log: log, request: request}
	}
	if !isResponse(line) || canonicalID(frame.ID) == "" {
		return mcpV3WithheldWriter{}
	}
	s := o.v3Session
	key := canonicalID(frame.ID)
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

// Unpaired upstream responses have no authorized client delivery.
type mcpV3WithheldWriter struct{}

func (mcpV3WithheldWriter) WriteMessage([]byte) error { return nil }

func (o MCPProxyOpts) pendingV3Send(id json.RawMessage) *mcpV3Exchange {
	if o.v3Session == nil {
		return nil
	}
	o.v3Session.mu.Lock()
	defer o.v3Session.mu.Unlock()
	return o.v3Session.pending[canonicalID(id)]
}

func mcpV3SendDenial(frame MCPFrame, send *mcpV3Exchange) BlockedRequest {
	return BlockedRequest{
		ID: frame.ID, IsNotification: frame.Method == "" || isRPCNotification(frame.ID),
		LogMessage: "receipt emission failed", ErrorCode: -32007,
		ErrorMessage: requiredReceiptFailureMessage(nil), ErrorData: mcpBlockReasonData(blockreason.ReceiptEmissionFailed),
		v3ReplyParent: send, v3SendDenied: true,
	}
}

func (o MCPProxyOpts) writeV3SendDenial(log io.Writer, writer transport.MessageWriter, frame MCPFrame, send *mcpV3Exchange) {
	br := mcpV3SendDenial(frame, send)
	inputMCPDenial(o, mcpReceiptMcpInputDenialAudit(), &br)
	logMCPV3Error(log, deliverMCPInputResult(o, br, o.v3SendDenialWriter(writer, log, br)))
}

func (o MCPProxyOpts) v3SendDenialWriter(writer transport.MessageWriter, log io.Writer, br BlockedRequest) transport.MessageWriter {
	if !o.receiptEffects.enabled || !br.v3SendDenied {
		return o.localV3ReplyWriter(writer, log, nil)
	}
	return &mcpV3LocalWriter{base: writer, opts: o, log: log, send: br.v3ReplyParent, sendDenied: true}
}

func (o MCPProxyOpts) localV3ReplyWriter(writer transport.MessageWriter, log io.Writer, x *mcpV3Exchange) transport.MessageWriter {
	if !o.receiptEffects.enabled {
		return writer
	}
	return &mcpV3LocalWriter{base: writer, opts: o, log: log, send: x}
}

type mcpV3LocalWriter struct {
	base       transport.MessageWriter
	opts       MCPProxyOpts
	log        io.Writer
	send       *mcpV3Exchange
	sendDenied bool
}

func (w *mcpV3LocalWriter) WriteMessage(msg []byte) error {
	request := receipt.EmitOpts{RequestID: canonicalID(ParseMCPFrame(msg).ID), Transport: w.opts.Transport}
	if w.send != nil {
		request = w.send.request
	}
	reply := mcpV3ReplyWriter{base: w.base, opts: w.opts, log: w.log, request: request, sendDenied: w.sendDenied}
	return writeMCPForwardedMessage(&reply, msg)
}

type mcpV3ReplyWriter struct {
	base       transport.MessageWriter
	opts       MCPProxyOpts
	log        io.Writer
	request    receipt.EmitOpts
	finished   bool
	sendDenied bool
}

var errMCPV3ReplyAdmission = errors.New("MCP reply receipt admission")

func (w *mcpV3ReplyWriter) WriteMessage(msg []byte) error {
	if w.finished {
		return nil
	}
	w.finished = true
	ctx := w.opts.warnContext()
	evidence := mcpV3ReplyEvidence(w.request)
	action, policy := w.opts.v3EffectAction(evidence, mcpDownstreamDeliveryBoundary)
	admit := w.opts.receiptEffects.gate.Admit
	if w.sendDenied {
		admit = w.opts.receiptEffects.gate.AdmitDenialDelivery
	}
	token, err := admit(ctx, action, policy)
	if err != nil {
		return fmt.Errorf("%w: %w", errMCPV3ReplyAdmission, err)
	}
	if err := ctx.Err(); err != nil {
		logMCPV3Error(w.log, token.Refuse(ctx))
		return err
	}
	err = writeMCPForwardedMessage(w.base, msg)
	logMCPV3Error(w.log, confirmMCPV3Effect(ctx, token, err == nil))
	return err
}

func (w *mcpV3ReplyWriter) writeDeniedMessage([]byte) error {
	if w.finished {
		return nil
	}
	w.finished = true
	return w.opts.refuseV3Reply(w.opts.warnContext(), mcpV3ReplyEvidence(w.request))
}

func logMCPV3Error(log io.Writer, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		_, _ = fmt.Fprintf(log, "pipelock: MCP v3 receipt: audit_gap=true: %v\n", err)
	} else if err != nil {
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
		Transport: o.Transport, Target: firstNonEmpty(held.Target, held.Method), PolicyHash: o.receiptPolicyHash(),
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
		resolution.Layer = deferredResolutionLayer(res.ResolutionSource)
		resolution.Pattern = res.Reason
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

func (o MCPProxyOpts) claimV3DeferredSend(ctx context.Context, log io.Writer, frame MCPFrame, res deferred.Resolution, mu sync.Locker, generation uint64) (*mcpV3Exchange, func(), string, error) {
	effect, err := o.startV3Send(ctx, frame, res.ParentActionID)
	if err != nil {
		logMCPV3Error(log, err)
		return effect, nil, "receipt admission failed", err
	}
	prepared, finish := lockAndClaimDeferredRelease(mu, o, generation, res)
	if finish != nil && prepared.FinalDecision == config.ActionAllow && ctx.Err() == nil {
		return effect, sync.OnceFunc(finish), "", nil
	}
	if finish != nil {
		finish()
	}
	o.finishV3Send(ctx, log, effect, false)
	return nil, nil, firstNonEmpty(prepared.Reason, "request cancelled"), nil
}

// mcpV3NetworkExchange keeps settlement outside the listener's state and
// contract locks. A tools/list handler reserves both intents before taking
// its contract lock, then settles after releasing it.
type mcpV3NetworkExchange struct {
	ctx                           context.Context
	opts                          MCPProxyOpts
	log                           io.Writer
	send, refusedSend             *mcpV3Exchange
	reply                         *v3.EffectToken
	replyEvidence                 receipt.EmitOpts
	replyAdmitted                 bool
	sent, observed, wrote, framed bool
}

func (x *mcpV3NetworkExchange) admit(frame MCPFrame, actionID string) error {
	var err error
	x.send, err = x.opts.startV3Send(x.ctx, frame, actionID)
	if err != nil {
		x.refusedSend, x.send = x.send, nil
	}
	if x.send != nil {
		x.replyEvidence = mcpV3ReplyEvidence(x.send.request)
	}
	return err
}

func (x *mcpV3NetworkExchange) admitList(frame MCPFrame, lock *contractLock) (admissionErr, lockErr error) {
	if err := x.admit(frame, ""); err != nil {
		return err, nil
	}
	if err := x.admitReply(); err != nil {
		return err, nil
	}
	return nil, lock.Lock(x.ctx)
}

func (x *mcpV3NetworkExchange) refuseReply() {
	if x.send != nil && !x.replyAdmitted {
		logMCPV3Error(x.log, x.opts.refuseV3Reply(x.ctx, x.replyEvidence))
	}
}

func (x *mcpV3NetworkExchange) admitReply() error {
	if x.send == nil || x.replyAdmitted {
		return nil
	}
	var err error
	x.reply, err = x.opts.admitV3Effect(x.ctx, x.replyEvidence, mcpDownstreamDeliveryBoundary)
	x.replyAdmitted = err == nil
	return err
}

func (x *mcpV3NetworkExchange) observe() {
	x.observed = true
	if x.send != nil {
		logMCPV3Error(x.log, confirmMCPV3Effect(x.ctx, x.send.token, true))
	}
}

func (x *mcpV3NetworkExchange) finish() {
	if x.send == nil {
		return
	}
	if x.sent {
		logMCPV3Error(x.log, confirmMCPV3Effect(x.ctx, x.send.token, x.observed))
	} else {
		logMCPV3Error(x.log, x.send.token.Refuse(x.ctx))
	}
	if x.wrote {
		logMCPV3Error(x.log, confirmMCPV3Effect(x.ctx, x.reply, x.framed))
	} else if x.replyAdmitted {
		logMCPV3Error(x.log, x.reply.Refuse(x.ctx))
	}
}

func (x *mcpV3NetworkExchange) streamWriter(base transport.MessageWriter) transport.MessageWriter {
	if x.send == nil {
		return base
	}
	return &mcpV3NetworkStreamWriter{exchange: x, base: base}
}

type mcpV3NetworkStreamWriter struct {
	exchange *mcpV3NetworkExchange
	base     transport.MessageWriter
}

func (w *mcpV3NetworkStreamWriter) WriteMessage(msg []byte) error {
	x := w.exchange
	if err := x.admitReply(); err != nil {
		return err
	}
	if err := x.ctx.Err(); err != nil {
		return err
	}
	x.wrote = true
	return writeMCPForwardedMessage(w.base, msg)
}

func (w *mcpV3NetworkStreamWriter) writeDeniedMessage([]byte) error {
	x := w.exchange
	if x.replyAdmitted && !x.wrote {
		return nil // The reserved delivery settles as not released.
	}
	evidence := x.replyEvidence
	evidence.ActionID = receipt.NewActionID()
	return x.opts.refuseV3Reply(x.ctx, evidence)
}
