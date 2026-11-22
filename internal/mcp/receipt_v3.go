// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

const (
	mcpV3DeferRefusal             = "pipelock: deferred holds are not available while v3 receipts are enabled"
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
	actor := firstNonEmpty(opts.Agent, o.addressProtectionAgent())
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
	if identity := o.v3DoorIdentity; identity != nil {
		action.Principal = o.AuthorityActor
		action.Caller = v3.Caller{
			Authn: "mcp_door_verified", Issuer: identity.Issuer, Resource: identity.Resource,
			Subject: identity.Subject, ClientID: identity.ClientID,
		}
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
	request.ParentActionID, request.ActionID = request.ActionID, receipt.NewActionID()
	request.Target = firstNonEmpty(request.Target, "mcp://response")
	request.Verdict = config.ActionAllow
	return request
}

func confirmMCPV3Effect(ctx context.Context, token *v3.EffectToken, observed bool) error {
	return token.ConfirmDelivery(ctx, func() (bool, error) { return observed, nil })
}

// A successful trace is necessary but HTTP/1 can still fail the connection
// buffer flush. Combine this observation with the transport round-trip result.
func observeMCPHTTPWrite(ctx context.Context) (context.Context, func() bool) {
	var written atomic.Bool
	trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err == nil {
			written.Store(true)
		}
	}}
	return httptrace.WithClientTrace(ctx, trace), written.Load
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

func (o MCPProxyOpts) startV3Send(ctx context.Context, frame MCPFrame, request receipt.EmitOpts) (*mcpV3Exchange, error) {
	if !o.receiptEffects.enabled {
		return nil, nil
	}
	if request.ActionID == "" {
		request.ActionID = receipt.NewActionID()
	}
	request.RequestID, request.Method, request.Transport = canonicalID(frame.ID), frame.Method, o.Transport
	request.Target = firstNonEmpty(request.Target, firstNonEmpty(frame.ToolCallName, frame.Method))
	if request.Target == "" && isResponse(frame.Raw) {
		request.Target = "mcp://response"
	}
	request.Verdict = config.ActionAllow
	request = o.withReceiptPolicyHash(request)
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

func (o MCPProxyOpts) writeV3SendDenial(log io.Writer, writer transport.MessageWriter, frame MCPFrame, send *mcpV3Exchange) error {
	br := mcpV3SendDenial(frame, send)
	inputMCPDenial(o, mcpReceiptMcpInputDenialAudit(), &br)
	err := deliverMCPInputResult(o, br, o.v3SendDenialWriter(writer, log, br))
	logMCPV3Error(log, err)
	return err
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

func (w *mcpV3LocalWriter) replyWriter(id json.RawMessage) mcpV3ReplyWriter {
	request := receipt.EmitOpts{RequestID: canonicalID(id), Transport: w.opts.Transport}
	if w.send != nil {
		request = w.send.request
	}
	return mcpV3ReplyWriter{base: w.base, opts: w.opts, log: w.log, request: request, sendDenied: w.sendDenied}
}

func (w *mcpV3LocalWriter) WriteMessage(msg []byte) error {
	reply := w.replyWriter(ParseMCPFrame(msg).ID)
	return writeMCPForwardedMessage(&reply, msg)
}

func (w *mcpV3LocalWriter) writeDeniedMessage(msg []byte) error {
	reply := w.replyWriter(ParseMCPFrame(msg).ID)
	return reply.writeDeniedMessage(msg)
}

func (w *mcpV3LocalWriter) writeInputDenial(br BlockedRequest, msg []byte) error {
	reply := w.replyWriter(br.ID)
	if br.v3Evidence.Transport != "" && w.send == nil {
		reply.request = br.v3Evidence
	}
	if br.IsNotification {
		msg = nil
	}
	if w.sendDenied {
		if msg == nil {
			return nil
		}
		return writeMCPForwardedMessage(&reply, msg)
	}
	return reply.deliverDenial(msg, br.v3RefusalSigned, br.v3RefusalErr)
}

type mcpV3ReplyWriter struct {
	base         transport.MessageWriter
	opts         MCPProxyOpts
	log          io.Writer
	request      receipt.EmitOpts
	finished     bool
	sendDenied   bool
	onStream     bool
	takeAdmitted func() (*v3.EffectToken, bool)
}

var errMCPV3ReplyAdmission = errors.New("MCP reply receipt admission")

func (w *mcpV3ReplyWriter) WriteMessage(msg []byte) error {
	if w.finished {
		return nil
	}
	w.finished = true
	ctx := w.opts.warnContext()
	evidence := mcpV3ReplyEvidence(w.request)
	token, err := w.admit(ctx, evidence)
	if err != nil {
		return fmt.Errorf("%w: %w", errMCPV3ReplyAdmission, err)
	}
	if err := ctx.Err(); err != nil {
		logMCPV3Error(w.log, token.Refuse(ctx))
		return err
	}
	if w.sendDenied {
		err = deliverMCPDeniedMessage(w.base, msg)
	} else {
		err = writeMCPForwardedMessage(w.base, msg)
	}
	logMCPV3Error(w.log, confirmMCPV3Effect(ctx, token, err == nil && (!w.onStream || ctx.Err() == nil)))
	return err
}

func (w *mcpV3ReplyWriter) admit(ctx context.Context, evidence receipt.EmitOpts) (*v3.EffectToken, error) {
	action, policy := w.opts.v3EffectAction(evidence, mcpDownstreamDeliveryBoundary)
	if w.sendDenied {
		return w.opts.receiptEffects.gate.AdmitDenialDelivery(ctx, action, policy)
	}
	if w.takeAdmitted != nil {
		if token, ok := w.takeAdmitted(); ok {
			return token, nil
		}
	}
	return w.opts.receiptEffects.gate.Admit(ctx, action, policy)
}

func (w *mcpV3ReplyWriter) writeDeniedMessage(msg []byte) error {
	return w.deliverDenial(msg, false, nil)
}

func (w *mcpV3ReplyWriter) deliverDenial(msg []byte, signed bool, refusalErr error) error {
	if w.finished {
		return nil
	}
	if !signed && refusalErr == nil {
		refusalErr = w.opts.refuseV3Reply(w.opts.warnContext(), mcpV3ReplyEvidence(w.request))
	}
	if refusalErr != nil {
		logMCPV3Error(w.log, refusalErr)
		if w.opts.receiptEffects.gate.RequiresReceipts() {
			w.finished = true
			return fmt.Errorf("%w: %w", errMCPV3ReplyAdmission, refusalErr)
		}
	}
	if msg == nil {
		return nil
	}
	w.sendDenied = true
	return writeMCPForwardedMessage(w, msg)
}

func logMCPV3Error(log io.Writer, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		_, _ = fmt.Fprintf(log, "pipelock: MCP v3 receipt: audit_gap=true: %v\n", err)
	} else if err != nil {
		_, _ = fmt.Fprintf(log, "pipelock: MCP v3 receipt: %v\n", err)
	}
}

// mcpV3NetworkExchange owns the HTTP send and its non-stream reply. A
// tools/list request also reserves the reply before taking the contract lock.
// The matching SSE message can take that reservation for its own delivery.
type mcpV3NetworkExchange struct {
	ctx                           context.Context
	opts                          MCPProxyOpts
	log                           io.Writer
	send, refusedSend             *mcpV3Exchange
	reply                         *v3.EffectToken
	listReply                     *mcpV3ReplyReservation
	replyEvidence                 receipt.EmitOpts
	replyAdmitted                 bool
	sent, observed, wrote, framed bool
}

// Optional admission may succeed without a token. The reservation itself
// distinguishes that case from a reply that still needs admission.
type mcpV3ReplyReservation struct{ token *v3.EffectToken }

func (x *mcpV3NetworkExchange) admit(frame MCPFrame, evidence receipt.EmitOpts) error {
	var err error
	x.send, err = x.opts.startV3Send(x.ctx, frame, evidence)
	if err != nil {
		x.refusedSend, x.send = x.send, nil
	}
	if x.send != nil {
		x.replyEvidence = mcpV3ReplyEvidence(x.send.request)
	}
	return err
}

func (x *mcpV3NetworkExchange) admitList(frame MCPFrame, evidence receipt.EmitOpts, lock *contractLock) (admissionErr, lockErr error) {
	if err := x.admit(frame, evidence); err != nil {
		return err, nil
	}
	if x.send != nil {
		token, err := x.opts.admitV3Effect(x.ctx, x.replyEvidence, mcpDownstreamDeliveryBoundary)
		if err != nil {
			return err, nil
		}
		x.listReply = &mcpV3ReplyReservation{token: token}
	}
	return nil, lock.Lock(x.ctx)
}

func (x *mcpV3NetworkExchange) refuseReply() {
	if x.send != nil && !x.replyAdmitted && x.listReply == nil {
		logMCPV3Error(x.log, x.opts.refuseV3Reply(x.ctx, x.replyEvidence))
	}
}

func (x *mcpV3NetworkExchange) admitReply() error {
	if x.send == nil || x.replyAdmitted {
		return nil
	}
	if token, ok := x.takeListReply(); ok {
		x.reply, x.replyAdmitted = token, true
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
	if token, ok := x.takeListReply(); ok {
		logMCPV3Error(x.log, token.Refuse(x.ctx))
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

func (w *mcpV3NetworkStreamWriter) messageWriter(msg []byte, frame MCPFrame, correlated bool) *mcpV3ReplyWriter {
	x := w.exchange
	id := canonicalID(frame.ID)
	opts := x.opts
	opts.WarnContext = x.ctx
	reply := &mcpV3ReplyWriter{
		base: w.base, opts: opts, log: x.log, onStream: true,
		request: receipt.EmitOpts{RequestID: id, Method: frame.Method, Target: firstNonEmpty(frame.Method, "mcp://event"), Transport: opts.Transport},
	}
	if correlated && isResponse(msg) && id != "" && id == x.send.request.RequestID {
		reply.request = x.send.request
		reply.takeAdmitted = x.takeListReply
	}
	return reply
}

func (x *mcpV3NetworkExchange) takeListReply() (*v3.EffectToken, bool) {
	reserved := x.listReply
	if reserved == nil {
		return nil, false
	}
	x.listReply = nil
	return reserved.token, true
}

func (w *mcpV3NetworkStreamWriter) WriteMessage(msg []byte) error {
	return writeMCPForwardedMessage(w.messageWriter(msg, ParseMCPFrame(msg), false), msg)
}

func (w *mcpV3NetworkStreamWriter) localReplyWriter() transport.MessageWriter {
	x := w.exchange
	opts := x.opts
	opts.WarnContext = x.ctx
	return opts.localV3ReplyWriter(w.base, x.log, nil)
}

func (x *mcpV3NetworkExchange) deliverDeniedReply(base transport.MessageWriter, msg []byte) error {
	opts := x.opts
	opts.WarnContext = x.ctx
	reply := mcpV3ReplyWriter{base: base, opts: opts, log: x.log, request: x.send.request}
	return reply.writeDeniedMessage(msg)
}
