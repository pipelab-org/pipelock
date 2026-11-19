// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

const (
	boundaryUpstreamSend       = "upstream_send"
	boundaryTunnelOpen         = "tunnel_open"
	boundaryDownstreamDelivery = "downstream_delivery"
	boundaryNoEffect           = "none"
)

type v3TransportReceipt struct {
	action v3.Action
	policy v3.PolicySnapshot
}

func prepareV3TransportReceipt(cfg *config.Config, opts receipt.EmitOpts) v3TransportReceipt {
	actor := opts.Agent
	if actor == "" {
		actor = "pipelock"
	}
	action := v3.Action{
		ActionID: opts.ActionID, ParentActionID: opts.ParentActionID,
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
	return v3TransportReceipt{action: action, policy: v3.CapturePolicy(digest)}
}

// receiptWriteWithholdsEffect reports whether a failed receipt write must stop
// the effect. Required mode withholds on every failure. A v3 record that says
// the effect was not released withholds even when receipts are optional,
// because releasing it would contradict that record.
func receiptWriteWithholdsEffect(cfg *config.Config, err error) bool {
	if err == nil {
		return false
	}
	if cfg != nil && cfg.FlightRecorder.RequireReceipts {
		return true
	}
	return errors.Is(err, v3.ErrEffectNotReleased)
}

func (p *Proxy) confirmTransportReceipt(ctx context.Context, cfg *config.Config, opts receipt.EmitOpts, boundary string) (*v3TransportReceipt, error) {
	entry := prepareV3TransportReceipt(cfg, opts)
	attempt := int64(1)
	entry.action.Attempt = &attempt
	entry.action.EffectBoundary, entry.action.EffectRelation, entry.action.Phase = boundary, "before", "intent"
	if err := p.receiptV3.WriteAction(ctx, entry.action, entry.policy); err != nil {
		if cfg != nil && cfg.FlightRecorder.RequireReceipts {
			p.recordRequiredReceiptBlock(err, opts.Transport)
		} else if receiptWriteWithholdsEffect(cfg, err) {
			p.metrics.RecordOptionalReceiptWithhold(opts.Transport)
		}
		p.logReceiptEmissionFailure(opts, err)
		return nil, err
	}
	return &entry, nil
}

func (p *Proxy) emitRecordedEffectRefusal(ctx context.Context, opts receipt.EmitOpts, boundary string) bool {
	if p.receiptV3 == nil || opts.Verdict != config.ActionBlock {
		return p.emitRecordedReceipt(opts)
	}
	return p.recordV3TransportRefusal(ctx, nil, opts, boundary) == nil
}

func (p *Proxy) recordV3TransportRefusal(ctx context.Context, cfg *config.Config, opts receipt.EmitOpts, boundary string) error {
	entry := prepareV3TransportReceipt(cfg, opts)
	entry.action.Phase, entry.action.EffectBoundary, entry.action.EffectRelation = "decision", boundary, "not_attempted"
	if err := p.receiptV3.WriteAction(context.WithoutCancel(ctx), entry.action, entry.policy); err != nil {
		p.logReceiptEmissionFailure(opts, err)
		return err
	}
	return nil
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
	if entry == nil {
		return
	}
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

var errWSClientClosing = errors.New("WebSocket client is closing")

// writePayload carries the decision for one complete message or Ping/Pong
// through the write. Protocol Close frames carry no relayed payload.
func (r *wsRelay) writePayload(ctx context.Context, boundary string, opcode ws.OpCode, payload []byte, opts receipt.EmitOpts) (blocked bool, err error) {
	write, conn := wsutil.WriteClientMessage, r.upstreamConn
	if boundary == boundaryDownstreamDelivery {
		write, conn = wsutil.WriteServerMessage, r.clientConn
	}
	if r.proxy.receiptV3 == nil {
		return false, write(conn, opcode, payload)
	}
	if opts.ActionID == "" {
		opts.ActionID = receipt.NewActionID()
	}
	if opts.Verdict == "" {
		opts.Verdict = config.ActionAllow
	}
	opts.ParentActionID = r.requestActionID
	opts.Transport, opts.Method = TransportWS, "WS"
	opts.Target, opts.RequestID, opts.Agent = r.targetURL, r.requestID, r.agent
	intent, err := r.proxy.confirmTransportReceipt(ctx, r.cfg, opts, boundary)
	if receiptWriteWithholdsEffect(r.cfg, err) {
		return ctx.Err() == nil, err
	}
	if err = ctx.Err(); err == nil && boundary == boundaryDownstreamDelivery && r.clientClosing.Load() {
		err = errWSClientClosing
	}
	if err != nil {
		if intent != nil {
			r.proxy.recordTransportNotReleased(ctx, opts, intent)
		}
		return false, err
	}
	err = write(conn, opcode, payload)
	r.proxy.recordTransportOutcome(ctx, opts, intent, err == nil)
	return false, err
}

// confirmHTTPResponseDelivery gates the first write of an approved upstream
// response. The downstream action has its own ID and points at the send.
func (p *Proxy) confirmHTTPResponseDelivery(w http.ResponseWriter, ctx context.Context, cfg *config.Config, send receipt.EmitOpts) (*v3TransportReceipt, bool) {
	if p == nil || p.receiptV3 == nil {
		return nil, true
	}
	opts := deliveryReceiptOpts(send)
	entry, err := p.confirmTransportReceipt(ctx, cfg, opts, boundaryDownstreamDelivery)
	if !receiptWriteWithholdsEffect(cfg, err) {
		return entry, true
	}
	// Some callers have already staged upstream headers.
	clear(w.Header())
	writeBlockedError(w, blockInfoFor(blockreason.ReceiptEmissionFailed, receiptEmissionFailedLayer).WithRequestID(opts.RequestID),
		receiptEmissionBlockReason, http.StatusForbidden)
	return nil, false
}

func deliveryReceiptOpts(send receipt.EmitOpts) receipt.EmitOpts {
	opts := send
	opts.ActionID, opts.ParentActionID = receipt.NewActionID(), send.ActionID
	opts.Layer, opts.Pattern, opts.Verdict = "", "", config.ActionAllow
	return opts
}

func (p *Proxy) recordV3ExceptionAllows(cfg *config.Config, opts []receipt.EmitOpts) error {
	if len(opts) == 0 {
		return nil
	}
	required := cfg != nil && cfg.FlightRecorder.RequireReceipts
	actions := make([]v3.Action, 0, len(opts))
	var policy v3.PolicySnapshot
	for _, emit := range opts {
		tx := prepareV3TransportReceipt(cfg, emit)
		action := tx.action
		action.EffectBoundary, action.EffectRelation, action.Phase = boundaryUpstreamSend, "before", "decision"
		if required {
			attempt := int64(1)
			action.Phase, action.Attempt = "intent", &attempt
		}
		actions = append(actions, action)
		policy = tx.policy
	}
	if err := p.receiptV3.WriteAdmissionBatch(context.Background(), actions, policy); err != nil {
		p.logReceiptEmissionFailure(opts[0], err)
		if required {
			return err
		}
	}
	return nil
}
