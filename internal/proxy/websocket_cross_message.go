// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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
	var views [][2]string
	if len(c.tail) > 0 {
		// Applications may concatenate messages directly or separate words.
		// Inspect both interpretations without changing delivered bytes.
		for _, separator := range []string{"", " "} {
			views = append(views, [2]string{string(c.tail) + separator, string(msg)})
		}
	}
	for _, view := range c.fields.Views(frame) {
		views = append(views, [2]string{view.Tail, view.Value})
	}
	blocked, reported := r.enforceUpstreamCrossMessageViews(ctx, log, views)
	if blocked {
		return true
	}
	// A finding may be warn-only. An unjoined field is not a finding: the
	// raw tail cannot see across the JSON envelope, so the message closes
	// in every action, including warn and response-scan exemptions.
	if !reported && r.watchRefusal(c.fields.Incomplete(frame), "ws_protocol", crossMessageIncompleteReason, "uninspected") {
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

// enforceUpstreamCrossMessage scans tail followed directly by msg and acts only on
// patterns neither part matches alone; those were already handled by the
// per-message scan. A cross-message finding cannot be stripped because the
// first half was already delivered, so every action except warn closes.
func (r *wsRelay) enforceUpstreamCrossMessage(ctx context.Context, log *audit.Logger, tail, msg string) (blocked, reported bool) {
	return r.enforceUpstreamCrossMessageViews(ctx, log, [][2]string{{tail, msg}})
}

// enforceUpstreamCrossMessageViews reports each pattern once for the message,
// even when multiple joins find it. Parts already matched alone are excluded.
func (r *wsRelay) enforceUpstreamCrossMessageViews(ctx context.Context, log *audit.Logger, views [][2]string) (blocked, reported bool) {
	var matches []scanner.ResponseMatch
	var names []string
	reportedPatterns := make(map[string]struct{})
	for _, view := range views {
		joined := r.scanner.ScanResponseWithSuppress(ctx, view[0]+view[1], r.targetURL, r.cfg.Suppress)
		if ctx.Err() != nil {
			return false, false
		}
		if joined.Failed() && r.watchOnly() {
			r.recordWatch(responseScanLayer, joined.ScanError, "uninspected", int64(len(view[1])), false)
			continue
		}
		if joined.Failed() {
			r.closeUpstreamCrossMessage(log, "response scan failed: "+joined.ScanError, "response scan incomplete", "response_scan_error",
				blockInfoFor(blockreason.ParseError, "response_scan_error"))
			return true, false
		}
		if joined.Clean {
			continue
		}
		seen := make(map[string]struct{})
		for _, part := range view {
			for _, match := range r.scanner.ScanResponseWithSuppress(ctx, part, r.targetURL, r.cfg.Suppress).Matches {
				seen[match.PatternName] = struct{}{}
			}
		}
		for _, match := range joined.Matches {
			if _, ok := seen[match.PatternName]; ok {
				continue
			}
			if _, ok := reportedPatterns[match.PatternName]; ok {
				continue
			}
			reportedPatterns[match.PatternName] = struct{}{}
			names = append(names, match.PatternName)
			matches = append(matches, match)
		}
	}
	if len(names) == 0 {
		return false, false
	}
	if !r.observeUpstreamResponseFindings(responseScanFindingKinds(scanner.ResponseScanResult{Matches: matches})) {
		return true, true
	}
	r.proxy.metrics.RecordWSScanHit("injection")
	action := r.upstreamCrossMessageAction()
	if r.watchOnly() {
		r.recordWatch(responseScanLayer, strings.Join(names, ", "), action, 0, false)
		if err := r.confirmWatchResponseFinding(strings.Join(names, ", ")); err != nil {
			return r.blockOnCredentialAudienceReceiptFailure(log, err), true
		}
		return false, true
	}
	if action == config.ActionWarn {
		log.LogWSScan(audit.WSScanEvent{
			Target: r.targetURL, Direction: audit.DirectionServerToClient, ClientIP: r.clientIP, RequestID: r.requestID,
			Agent: r.agent, AgentAuth: string(r.actorAuth), Action: config.ActionWarn, MatchCount: len(names),
			PatternNames: names, BundleRules: responseBundleRules(matches),
		})
		return false, true
	}
	r.closeUpstreamCrossMessage(log, fmt.Sprintf("cross-message injection detected: %s", strings.Join(names, ", ")), "injection detected", responseScanLayer,
		blockInfoFor(blockreason.PromptInjection, responseScanLayer))
	return true, true
}

func (r *wsRelay) closeUpstreamCrossMessage(log *audit.Logger, reason, upstreamReason, layer string, info blockreason.Info) {
	log.LogWSBlocked(audit.WSBlockedEvent{
		Target: r.targetURL, Direction: audit.DirectionServerToClient, Scanner: layer,
		Reason: reason, ClientIP: r.clientIP, RequestID: r.requestID,
		Agent: r.agent, AgentAuth: string(r.actorAuth),
	})
	_ = r.emitReceipt(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionBlock, Layer: layer, Pattern: reason,
		Transport: TransportWS, Method: "WS", Target: r.targetURL, RequestID: r.requestID, Agent: r.agent,
	})
	plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation,
		info.WithRequestID(r.requestID).CloseFramePayload())
	plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, upstreamReason)
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
	plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation,
		blockInfo("ws_protocol").WithRequestID(r.requestID).CloseFramePayload())
	plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "cross-message inspection incomplete")
}
