// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"

	"github.com/gobwas/ws"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// watchOnly uses the policy admitted with this connection. A config reload
// changes subsequent connections; operator kill-switch state remains live.
func (r *wsRelay) watchOnly() bool {
	return r.cfg != nil && r.cfg.WatchOnly
}

func (r *wsRelay) recordWatch(scannerName, reason, action string, uninspectedBytes int64, enforced bool) {
	if r.proxy == nil {
		return
	}
	if r.proxy.logger != nil {
		r.proxy.logger.LogWatchOnlyRequest(r.requestID, TransportWS, scannerName, reason, action, uninspectedBytes, enforced)
	}
	if r.proxy.metrics != nil {
		r.proxy.metrics.RecordWatchOnly(TransportWS, scannerName, action, uninspectedBytes)
	}
}

// watchRefusal returns whether a policy decision still blocks this connection.
// The decision is evaluated before this helper so observation is not disabled.
func (r *wsRelay) watchRefusal(refuse bool, scannerName, reason, action string) bool {
	if !refuse || !r.watchOnly() {
		return refuse
	}
	r.recordWatch(scannerName, reason, action, 0, false)
	return false
}

// forwardUninspectedFrame retains the original framing and mask while copying
// through a bounded buffer. MaxMessageBytes remains an inspection bound, not an
// allocation request controlled by an untrusted frame header.
func (r *wsRelay) forwardUninspectedFrame(src, dst net.Conn, hdr ws.Header, reason string) (int64, error) {
	r.observeUpstreamResponseFindings(nil)
	if err := ws.WriteHeader(dst, hdr); err != nil {
		return 0, err
	}
	n, err := io.CopyN(dst, &watchFrameReader{Reader: src, relay: r, classifyRead: true}, hdr.Length)
	r.recordWatch("ws_protocol", reason, "uninspected", n, false)
	return n, err
}

// watchFrameReader checks operator revocation between bounded copy reads,
// including a frame too large to buffer for inspection.
type watchFrameReader struct {
	io.Reader
	relay        *wsRelay
	classifyRead bool
}

func (r *watchFrameReader) accessError() error {
	if r.relay.proxy != nil && r.relay.proxy.ks != nil && r.relay.proxy.ks.IsActive() {
		r.relay.recordWatch("kill_switch", "kill switch active", config.ActionBlock, 0, true)
		return errors.New("enforced in watch-only: kill switch active")
	}
	if r.relay.proxy != nil && !r.relay.proxy.stateIdentityConfigCurrent(r.relay.cfg, r.relay.actorAuth) {
		r.relay.recordWatch("identity_reload", stateIdentityReloadReason, config.ActionBlock, 0, true)
		return errors.New("enforced in watch-only: identity configuration changed")
	}
	return nil
}

func (r *watchFrameReader) Read(p []byte) (int, error) {
	if err := r.accessError(); err != nil {
		return 0, err
	}
	n, err := r.Reader.Read(p)
	if n > 0 {
		if accessErr := r.accessError(); accessErr != nil {
			return 0, accessErr
		}
	}
	if err != nil && r.classifyRead {
		err = &watchResponseReadError{err: err}
	}
	return n, err
}

func (p *Proxy) watchWSRefusal(cfg *config.Config, refuse bool, scannerName, reason, action string) bool {
	if !refuse || cfg == nil || !cfg.WatchOnly {
		return refuse
	}
	p.logger.LogWatchOnly(TransportWS, scannerName, reason, action, 0, false)
	p.metrics.RecordWatchOnly(TransportWS, scannerName, action, 0)
	return false
}

func (r *wsRelay) enforceEnabled() bool {
	return !r.watchOnly() && (r.cfg.Enforce == nil || *r.cfg.Enforce)
}

// forwardWatchResponseFragment preserves inbound fragmentation while scanning
// each bounded payload plus the existing cross-message overlap. Outbound
// fragments use the normal complete-message scanner before any delivery.
func (r *wsRelay) forwardWatchResponseFragment(ctx context.Context, hdr ws.Header, opcode ws.OpCode, tail *[]byte) (int64, error) {
	// The relay routes frames above maxMsg to the uninspected stream path;
	// keep the bound local so the buffer can never exceed it.
	if hdr.Length < 0 || hdr.Length > int64(r.maxMsg) {
		return 0, fmt.Errorf("watch-only response fragment length %d outside 0..%d", hdr.Length, r.maxMsg)
	}
	raw := make([]byte, int(hdr.Length))
	if _, err := io.ReadFull(&watchFrameReader{Reader: r.upstreamConn, relay: r, classifyRead: true}, raw); err != nil {
		return 0, err
	}
	payload := bytes.Clone(raw)
	if hdr.Masked {
		ws.Cipher(payload, hdr.Mask, 0)
	}
	if opcode == ws.OpText && r.scanText && r.scanner.ResponseScanningEnabled() {
		scanInput := append(bytes.Clone(*tail), payload...)
		result := r.scanner.ScanResponseWithSuppress(ctx, string(scanInput), r.targetURL, r.cfg.Suppress)
		r.observeUpstreamResponseFindings(upstreamResponseFindingKinds(result))
		action := r.scanner.ResponseAction()
		if isResponseScanExempt(r.hostname, r.cfg.ResponseScanning.ExemptDomains) {
			action = config.ActionWarn
		}
		for _, match := range result.Matches {
			r.recordWatch(responseScanLayer, match.PatternName, action, 0, false)
		}
		if !result.Clean {
			if err := r.confirmWatchResponseFinding(strings.Join(responseMatchNames(result.Matches), ", ")); err != nil {
				return 0, err
			}
			if action == config.ActionStrip {
				r.recordFinding(session.SignalStrip, r.proxy.logger, responseScanLayer, "injection detected: "+strings.Join(responseMatchNames(result.Matches), ", "))
			}
		}
	} else {
		r.observeUpstreamResponseFindings(nil)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if opcode == ws.OpText && r.scanText {
		*tail = updateWSCrossMessageTail(*tail, payload)
	} else {
		*tail = nil
	}
	if err := ws.WriteHeader(r.clientConn, hdr); err != nil {
		return 0, err
	}
	n, err := r.clientConn.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	r.recordWatch("ws_protocol", "fragmented message inspected per frame", "uninspected", int64(n), false)
	return int64(n), err
}

func (r *wsRelay) enforcementConfig() *config.Config {
	if r.cfg == nil {
		return nil
	}
	snapshot := *r.cfg
	snapshot.WatchOnly = r.watchOnly()
	return &snapshot
}

// A retired per-profile scanner cannot be replaced by the global policy.
func pinWebSocketScanner(sc *scanner.Scanner) (*scanner.Scanner, func(), bool) {
	if sc != nil {
		if release, ok := sc.BeginUse(); ok {
			return sc, release, true
		}
	}
	return nil, func() {}, false
}

func (r *wsRelay) confirmWatchResponseFinding(pattern string) error {
	if r.cfg == nil || !r.cfg.FlightRecorder.RequireReceipts {
		return nil
	}
	return r.proxy.emitAllowPathReceipt(r.cfg, withReceiptShard(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), ParentActionID: r.requestActionID,
		Verdict: config.ActionWarn, Layer: responseScanLayer,
		Pattern: pattern, Transport: TransportWS, Method: "WS", Target: r.targetURL,
		RequestID: r.requestID, Agent: r.agent,
	}, r.receiptShard))
}

type watchResponseReadError struct{ err error }

func (e *watchResponseReadError) Error() string { return e.err.Error() }
func (e *watchResponseReadError) Unwrap() error { return e.err }

func (r *wsRelay) classifyWatchResponseCopyError(ctx context.Context, err error) {
	var upstream *watchResponseReadError
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		r.upstreamCancelled = true
	} else if errors.As(err, &upstream) {
		r.upstreamIncomplete = true
	} else {
		// A downstream write or local refusal ended delivery, matching the
		// complete-message path's cancellation outcome.
		r.upstreamCancelled = true
	}
}
