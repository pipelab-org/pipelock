// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"strings"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

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
	// cfg is the request snapshot retained by the effect producer.
	digest := cfg.CanonicalPolicyHash()
	if digest != "" && !strings.HasPrefix(digest, "sha256:") {
		digest = "sha256:" + digest
	}
	return v3TransportReceipt{action: action, policy: v3.CapturePolicy(digest)}
}

func (p *Proxy) confirmTransportReceipt(ctx context.Context, cfg *config.Config, opts receipt.EmitOpts, boundary string) (*v3TransportReceipt, error) {
	entry := prepareV3TransportReceipt(cfg, opts)
	attempt := int64(1)
	entry.action.Attempt = &attempt
	entry.action.EffectBoundary, entry.action.EffectRelation, entry.action.Phase = boundary, "before", "intent"
	if err := p.receiptV3.WriteAction(ctx, entry.action, entry.policy); err != nil {
		if cfg.FlightRecorder.RequireReceipts {
			p.recordRequiredReceiptBlock(err, opts.Transport)
		}
		p.logReceiptEmissionFailure(opts, err)
		return nil, err
	}
	return &entry, nil
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
	if err != nil && r.cfg.FlightRecorder.RequireReceipts {
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
