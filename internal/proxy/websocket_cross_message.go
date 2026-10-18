// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	plwsutil "github.com/luckyPipewrench/pipelock/internal/wsutil"
)

const crossMessageIncompleteReason = "cross-message inspection incomplete: message exceeds JSON field limits (websocket_proxy.cross_message_field_limit)"

// crossMessageFieldLimit is the per-connection, per-direction JSON field
// budget for cross-message joining.
func (r *wsRelay) crossMessageFieldLimit() int {
	if r.cfg != nil && r.cfg.WebSocketProxy.CrossMessageFieldLimit > 0 {
		return r.cfg.WebSocketProxy.CrossMessageFieldLimit
	}
	return config.DefaultWebSocketCrossMessageFieldLimit
}

// upstreamCrossMessage carries upstream text into the scan of the next
// upstream text message, so an instruction the server splits across two
// messages is inspected joined: a raw tail for any text and per-field tails
// for JSON messages, whose envelope otherwise sits between the halves.
type upstreamCrossMessage struct {
	tail   []byte
	fields *extract.FieldTails
}

func newUpstreamCrossMessage(fieldLimit int) *upstreamCrossMessage {
	return &upstreamCrossMessage{fields: extract.NewFieldTailsWithLimit("", fieldLimit)}
}

// enforce scans msg against the retained upstream content. It returns true
// when the relay was closed.
func (c *upstreamCrossMessage) enforce(ctx context.Context, r *wsRelay, log *audit.Logger, msg []byte) bool {
	if !r.scanText || !r.scanner.ResponseScanningEnabled() {
		return false
	}
	frame := c.fields.ParseFrame(msg)
	reported := false
	if len(c.tail) > 0 {
		blocked, hit := r.enforceUpstreamCrossMessage(ctx, log, string(c.tail)+" ", string(msg))
		if blocked {
			return true
		}
		reported = hit
	}
	if !reported {
		for _, view := range c.fields.Views(frame) {
			blocked, hit := r.enforceUpstreamCrossMessage(ctx, log, view.Tail, view.Value)
			if blocked {
				return true
			}
			if hit {
				reported = true
				break
			}
		}
	}
	// A finding may be warn-only. An unjoined field is not a finding: the
	// raw tail cannot see across the JSON envelope, so the message closes
	// in every action, including warn and response-scan exemptions.
	if !reported && c.fields.Incomplete(frame) {
		r.blockCrossMessageIncomplete(log, audit.DirectionServerToClient)
		return true
	}
	// A reported finding clears the retained content so the same bytes are
	// not reported again by the next message.
	if reported {
		c.tail = nil
	} else {
		c.tail = updateWSCrossMessageTail(c.tail, msg)
	}
	c.fields.Advance(frame, reported)
	return false
}

func (r *wsRelay) upstreamCrossMessageAction() string {
	if isResponseScanExempt(r.hostname, r.cfg.ResponseScanning.ExemptDomains) {
		return config.ActionWarn
	}
	return decide.UpgradeAction(r.scanner.ResponseAction(), r.escalationLevel(), &r.cfg.AdaptiveEnforcement)
}

// enforceUpstreamCrossMessage scans tail followed directly by msg (separate
// raw messages pass a tail ending in a space) and acts only on
// patterns neither part matches alone; those were already handled by the
// per-message scan. A cross-message finding cannot be stripped because the
// first half was already delivered, so every action except warn closes.
func (r *wsRelay) enforceUpstreamCrossMessage(ctx context.Context, log *audit.Logger, tail, msg string) (blocked, reported bool) {
	joined := r.scanner.ScanResponseWithSuppress(ctx, tail+msg, r.targetURL, r.cfg.Suppress)
	if ctx.Err() != nil {
		return false, false
	}
	if joined.Failed() {
		r.closeUpstreamCrossMessage(log, "response scan failed: "+joined.ScanError, "response scan incomplete")
		return true, false
	}
	if joined.Clean {
		return false, false
	}
	seen := make(map[string]struct{})
	for _, part := range []string{tail, msg} {
		for _, match := range r.scanner.ScanResponseWithSuppress(ctx, part, r.targetURL, r.cfg.Suppress).Matches {
			seen[match.PatternName] = struct{}{}
		}
	}
	var names []string
	for _, match := range joined.Matches {
		if _, ok := seen[match.PatternName]; !ok {
			names = append(names, match.PatternName)
		}
	}
	if len(names) == 0 {
		return false, false
	}
	if !r.observeUpstreamResponseTaint(true) {
		return true, true
	}
	r.proxy.metrics.RecordWSScanHit("injection")
	action := r.upstreamCrossMessageAction()
	if action == config.ActionWarn {
		log.LogWSScan(audit.WSScanEvent{
			Target: r.targetURL, Direction: audit.DirectionServerToClient, ClientIP: r.clientIP, RequestID: r.requestID,
			Agent: r.agent, AgentAuth: string(r.actorAuth), Action: config.ActionWarn, MatchCount: len(names),
			PatternNames: names, BundleRules: responseBundleRules(joined.Matches),
		})
		return false, true
	}
	r.closeUpstreamCrossMessage(log, fmt.Sprintf("cross-message injection detected: %s", strings.Join(names, ", ")), "injection detected")
	return true, true
}

func (r *wsRelay) closeUpstreamCrossMessage(log *audit.Logger, reason, closeReason string) {
	log.LogWSBlocked(audit.WSBlockedEvent{
		Target: r.targetURL, Direction: audit.DirectionServerToClient, Scanner: responseScanLayer,
		Reason: reason, ClientIP: r.clientIP, RequestID: r.requestID,
		Agent: r.agent, AgentAuth: string(r.actorAuth),
	})
	_ = r.emitReceipt(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionBlock, Layer: responseScanLayer, Pattern: reason,
		Transport: TransportWS, Method: "WS", Target: r.targetURL, RequestID: r.requestID, Agent: r.agent,
	})
	plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, closeReason)
	plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, closeReason)
}

// blockCrossMessageIncomplete closes the relay when a JSON message is too
// large to join with the field content retained from earlier messages.
func (r *wsRelay) blockCrossMessageIncomplete(log *audit.Logger, direction string) {
	log.LogWSBlocked(audit.WSBlockedEvent{
		Target: r.targetURL, Direction: direction, Scanner: "ws_protocol",
		Reason: crossMessageIncompleteReason, ClientIP: r.clientIP, RequestID: r.requestID,
		Agent: r.agent, AgentAuth: string(r.actorAuth),
	})
	r.proxy.metrics.RecordWSScanHit("ws_protocol")
	_ = r.emitReceipt(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionBlock, Layer: "ws_protocol", Pattern: crossMessageIncompleteReason,
		Transport: TransportWS, Method: "WS", Target: r.targetURL, RequestID: r.requestID, Agent: r.agent,
	})
	plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "cross-message inspection incomplete")
	plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "cross-message inspection incomplete")
}
