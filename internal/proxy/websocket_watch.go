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

// forwardWatchResponseFragment preserves inbound fragmentation while scanning
// each bounded payload plus the existing cross-message overlap. Outbound
// fragments use the normal complete-message scanner before any delivery.
func (r *wsRelay) forwardWatchResponseFragment(ctx context.Context, hdr ws.Header, tail *[]byte) (int64, error) {
	// The relay routes frames above maxMsg to the uninspected stream path;
	// keep the bound local so the buffer can never exceed it.
	if hdr.Length < 0 || hdr.Length > int64(r.maxMsg) {
		return 0, fmt.Errorf("watch-only response fragment length %d outside 0..%d", hdr.Length, r.maxMsg)
	}
	raw := make([]byte, int(hdr.Length))
	if _, err := io.ReadFull(r.upstreamConn, raw); err != nil {
		return 0, err
	}
	payload := bytes.Clone(raw)
	if hdr.Masked {
		ws.Cipher(payload, hdr.Mask, 0)
	}
	scanInput := append(bytes.Clone(*tail), payload...)
	result := r.scanner.ScanResponseWithSuppress(ctx, string(scanInput), r.targetURL, r.cfg.Suppress)
	for _, match := range result.Matches {
		r.recordWatch(responseScanLayer, match.PatternName, r.scanner.ResponseAction(), 0, false)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	*tail = updateWSCrossMessageTail(*tail, payload)
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
