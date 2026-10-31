// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/url"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	plwsutil "github.com/luckyPipewrench/pipelock/internal/wsutil"
)

// adaptiveRefusalWriter changes only the delivered refusal. Scanners and their
// audit, metrics and receipt producers run in their existing order. Checking at
// WriteHeader also covers a finding that starts lockdown during this request.
type adaptiveRefusalWriter struct {
	http.ResponseWriter
	level       func() int
	cfg         *config.AdaptiveEnforcement
	transport   string
	wroteHeader bool
	refused     bool
}

type adaptiveRefusalOptions struct {
	config          *config.Config
	agent, clientIP string
	auth            envelope.ActorAuth
	host            func() string
	transport       string
}

func (p *Proxy) withAdaptiveRefusal(w http.ResponseWriter, opts adaptiveRefusalOptions) http.ResponseWriter {
	cfg := opts.config
	if p == nil || cfg == nil || !cfg.AdaptiveEnforcement.Enabled {
		return w
	}
	return &adaptiveRefusalWriter{ResponseWriter: w, cfg: &cfg.AdaptiveEnforcement, transport: opts.transport, level: func() int {
		return p.adaptiveRefusalLevel(opts)
	}}
}

func (p *Proxy) adaptiveRefusalLevel(opts adaptiveRefusalOptions) int {
	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		return 0
	}
	// Do not admit a session, refresh activity, or consume capacity.
	sm.mu.RLock()
	sess := sm.sessions[sessionKeyFor(opts.config, opts.agent, opts.clientIP, opts.auth)]
	sm.mu.RUnlock()
	if sess == nil {
		return 0
	}
	return sess.EffectiveEscalationLevel(adaptiveScopeForHost(opts.host()))
}

type adaptiveCloseConn struct {
	net.Conn
	level func() int
	cfg   *config.AdaptiveEnforcement
}

func (c *adaptiveCloseConn) ProjectCloseFrame(code ws.StatusCode, reason string) (ws.StatusCode, string) {
	if info, _, blocked := decide.AdaptiveRefusal(c.level(), c.cfg); blocked {
		return ws.StatusPolicyViolation, info.CloseFramePayload()
	}
	return code, reason
}

func (p *Proxy) withAdaptiveClose(conn net.Conn, opts adaptiveRefusalOptions) net.Conn {
	if conn == nil || opts.config == nil || !opts.config.AdaptiveEnforcement.Enabled {
		return conn
	}
	return &adaptiveCloseConn{Conn: conn, cfg: &opts.config.AdaptiveEnforcement, level: func() int { return p.adaptiveRefusalLevel(opts) }}
}

// refusalTargetHost derives the /fetch and /ws destination exactly as those
// handlers do before scoring it. A different parse lets a target the handler
// accepts, such as one carrying a stripped control character, select no scope
// here and bypass the projection.
func refusalTargetHost(r *http.Request) string {
	return refusalURLHost(stripFetchControlChars(extractTargetURL(r)))
}

// refusalConnectHost uses the CONNECT handler's authority normalization.
func refusalConnectHost(authority string) string {
	_, host, _, _, ok := normalizeConnectTarget(authority)
	if !ok {
		return ""
	}
	return host
}

func refusalURLHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func (w *adaptiveRefusalWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *adaptiveRefusalWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	// Informational responses do not commit the final response.
	if status < http.StatusOK {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.wroteHeader = true
	info, message, blocked := decide.AdaptiveRefusal(w.level(), w.cfg)
	if status < http.StatusBadRequest || !blocked || keepsOwnRefusal(w.Header()) {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.refused = true
	// Remove detector hints, correlation/receipt identifiers and any upstream
	// metadata. Their presence must not reveal which refusal path was taken.
	for key := range w.Header() {
		w.Header().Del(key)
	}
	info.SetHeaders(w.Header())
	switch w.transport {
	case TransportFetch:
		writeJSON(w.ResponseWriter, http.StatusForbidden, FetchResponse{Blocked: true, BlockReason: message})
	case TransportReverse:
		w.Header().Set("Content-Type", "application/json")
		w.ResponseWriter.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w.ResponseWriter).Encode(ReverseProxyBlockResponse{Error: "blocked by pipelock", Blocked: true, BlockReason: message, Direction: scanDirectionRequest})
	default:
		http.Error(w.ResponseWriter, message, http.StatusForbidden)
	}
}

// keepsOwnRefusal reports a refusal that block_all must not project. The kill
// switch runs before every detector on each path and carries the operator's
// message, so its own refusal reveals nothing about a detector.
func keepsOwnRefusal(header http.Header) bool {
	return header.Get(blockreason.HeaderReason) == string(blockreason.KillSwitchActive)
}

func (w *adaptiveRefusalWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.refused {
		return len(body), nil
	}
	return w.ResponseWriter.Write(body)
}

func (w *adaptiveRefusalWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *adaptiveRefusalWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

// Both relay directions use the same refusal, including a close sent to an
// upstream controlled by the caller. Normal closes outside lockdown are intact.
func (r *wsRelay) refusalClose(code ws.StatusCode, reason string) (ws.StatusCode, string) {
	if r.cfg == nil {
		return code, reason
	}
	if info, _, blocked := decide.AdaptiveRefusal(r.escalationLevel(), &r.cfg.AdaptiveEnforcement); blocked {
		return ws.StatusPolicyViolation, info.CloseFramePayload()
	}
	return code, reason
}

// writeKillSwitchClose sends the kill switch's own close in both directions,
// past the block_all projection; see keepsOwnRefusal.
func (r *wsRelay) writeKillSwitchClose() {
	plwsutil.WriteCloseFrame(unprojectedConn(r.clientConn), ws.StatusPolicyViolation,
		blockInfoFor(blockreason.KillSwitchActive, "kill_switch").WithRequestID(r.requestID).CloseFramePayload())
	plwsutil.WriteClientCloseFrame(unprojectedConn(r.upstreamConn), ws.StatusPolicyViolation, "kill switch active")
}

func unprojectedConn(conn net.Conn) net.Conn {
	if projected, ok := conn.(*adaptiveCloseConn); ok {
		return projected.Conn
	}
	return conn
}

func (r *wsRelay) writeClientClose(code ws.StatusCode, reason string) {
	code, reason = r.refusalClose(code, reason)
	plwsutil.WriteCloseFrame(r.clientConn, code, reason)
}

func (r *wsRelay) writeUpstreamClose(code ws.StatusCode, reason string) {
	code, reason = r.refusalClose(code, reason)
	plwsutil.WriteClientCloseFrame(r.upstreamConn, code, reason)
}
