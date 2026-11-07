// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"

	"github.com/gobwas/ws"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// watchOnly follows reloads without mutating the configuration snapshot shared
// by the two relay pumps. Other policy remains pinned to the admitted session.
func (r *wsRelay) watchOnly() bool {
	if r.proxy != nil {
		if cfg := r.proxy.cfgPtr.Load(); cfg != nil {
			return cfg.WatchOnly
		}
	}
	return r.cfg != nil && r.cfg.WatchOnly
}

func (r *wsRelay) recordWatch(scannerName, reason, action string, uninspectedBytes int64, enforced bool) {
	if r.watchReceiptGap {
		uninspectedBytes = 0
	}
	if r.proxy == nil {
		return
	}
	if r.proxy.logger != nil {
		r.proxy.logger.LogWatchOnly(TransportWS, scannerName, reason, action, uninspectedBytes, enforced)
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
	if err := ws.WriteHeader(dst, hdr); err != nil {
		return 0, err
	}
	n, err := io.CopyN(dst, &watchFrameReader{Reader: src, relay: r}, hdr.Length)
	r.recordWatch("ws_protocol", reason, "uninspected", n, false)
	return n, err
}

// watchFrameReader checks operator revocation between bounded copy reads,
// including a frame too large to buffer for inspection.
type watchFrameReader struct {
	io.Reader
	relay *wsRelay
}

func (r *watchFrameReader) Read(p []byte) (int, error) {
	if r.relay.proxy != nil && r.relay.proxy.ks != nil && r.relay.proxy.ks.IsActive() {
		r.relay.recordWatch("kill_switch", "kill switch active", config.ActionBlock, 0, true)
		return 0, errors.New("enforced in watch-only: kill switch active")
	}
	return r.Reader.Read(p)
}

func (rp *ReverseProxyHandler) watchRefusal(cfg *config.Config, refuse bool, scannerName, reason, action string) bool {
	if !refuse || cfg == nil || !cfg.WatchOnly {
		return refuse
	}
	rp.recordWatch(scannerName, reason, action, 0, false)
	return false
}

func (rp *ReverseProxyHandler) recordWatch(scannerName, reason, action string, uninspectedBytes int64, enforced bool) {
	if rp.logger != nil {
		rp.logger.LogWatchOnly(TransportReverse, scannerName, reason, action, uninspectedBytes, enforced)
	}
	if rp.metrics != nil {
		rp.metrics.RecordWatchOnly(TransportReverse, scannerName, action, uninspectedBytes)
	}
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

// forwardWatchFragment preserves fragmentation while scanning each bounded
// payload plus the existing cross-message overlap. Full-message parsers cannot
// certify an incomplete fragment, so the forwarded bytes stay uninspected.
func (r *wsRelay) forwardWatchFragment(ctx context.Context, hdr ws.Header, tail *[]byte, outbound bool) (int64, bool, error) {
	src, dst := r.upstreamConn, r.clientConn
	if outbound {
		src, dst = r.clientConn, r.upstreamConn
	}
	raw := make([]byte, int(hdr.Length))
	if _, err := io.ReadFull(src, raw); err != nil {
		return 0, false, err
	}
	payload := bytes.Clone(raw)
	if hdr.Masked {
		ws.Cipher(payload, hdr.Mask, 0)
	}
	log := r.proxy.logger.With("agent", r.agent).WithCorrelation(r.correlation)
	scanInput := append(bytes.Clone(*tail), payload...)
	if outbound {
		result := r.scanner.ScanTextForDLP(ctx, string(scanInput))
		matches, _ := r.scanner.FilterTextDLPMatchesForDestination(result.Matches, r.targetURL, "websocket_frame")
		for _, match := range matches {
			r.recordWatch(scannerLabelBodyDLP, match.PatternName, config.ActionBlock, 0, scanner.IsCoreCriticalMatch(match))
		}
		if containsCoreFloorMatch(matches) {
			return 0, r.handleClientTextFindings(log, matches, nil), nil
		}
	} else {
		result := r.scanner.ScanResponseWithSuppress(ctx, string(scanInput), r.targetURL, r.cfg.Suppress)
		for _, match := range result.Matches {
			r.recordWatch(responseScanLayer, match.PatternName, r.scanner.ResponseAction(), 0, false)
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	*tail = updateWSCrossMessageTail(*tail, payload)
	if err := ws.WriteHeader(dst, hdr); err != nil {
		return 0, false, err
	}
	n, err := dst.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	r.recordWatch("ws_protocol", "fragmented message inspected per frame", "uninspected", int64(n), false)
	return int64(n), false, err
}

func (r *wsRelay) enforcementConfig() *config.Config {
	if r.cfg == nil {
		return nil
	}
	snapshot := *r.cfg
	snapshot.WatchOnly = r.watchOnly()
	return &snapshot
}
