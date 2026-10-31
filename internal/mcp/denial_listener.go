// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/decide"
)

// mcpListenerDenialWriter is the listener admission adapter. The handler selects
// a typed descriptor at the refusal site. Allowed replies and ordinary upstream
// failures leave it empty; status codes alone never classify an MCP denial.
type mcpListenerDenialWriter struct {
	http.ResponseWriter
	opts           MCPProxyOpts
	descriptor     *mcpDenialAudit
	terminal       *mcpTerminalDecision
	direction      string
	wroteHeader    bool
	uniform        bool
	uniformMessage string
	replied        bool
}

// A withheld upstream reply is a response even when revocation reuses an
// admission descriptor. Keep that route independent of its label and resource.
func (w *mcpListenerDenialWriter) setResponseDenial(reason string) {
	w.direction = "response"
	if w.descriptor.kind == "" {
		*w.descriptor = mcpListenerWithholdAudit(reason)
	}
}

func (w *mcpListenerDenialWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *mcpListenerDenialWriter) decision(reply []byte) *mcpDenial {
	if w.descriptor.kind == "" {
		return nil
	}
	if w.terminal == nil {
		direction := firstNonEmpty(w.direction, "input")
		opts := w.opts
		opts.Transport = "mcp_http_listener"
		w.terminal = newMCPDenial(opts, *w.descriptor, direction, nil).decision
	}
	// The listener writes HTTP bodies and SSE framing. JSON-RPC message
	// projection belongs to the message adapters, not to an SSE byte chunk.
	return &mcpDenial{decision: w.terminal, reply: reply, framed: true}
}

func (w *mcpListenerDenialWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	if status < http.StatusOK {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.wroteHeader = true
	d := w.decision(nil)
	if d == nil {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.opts.Rec != nil {
		if info, message, blocked := decide.AdaptiveRefusal(w.opts.Rec.EscalationLevel(), w.opts.adaptiveCfg()); blocked {
			w.uniform = true
			w.uniformMessage = "pipelock: " + message
			for key := range w.Header() {
				w.Header().Del(key)
			}
			info.SetHeaders(w.Header())
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if status != http.StatusAccepted {
				status = http.StatusForbidden
			}
		}
	}
	_ = finishMCPDenial(d, mcpDeniedDelivery(func([]byte) error { w.ResponseWriter.WriteHeader(status); return nil }))
}

func (w *mcpListenerDenialWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.uniform {
		if w.replied {
			return len(p), nil
		}
		w.replied = true
		_, err := w.ResponseWriter.Write(blockSessionDenyResponse(ParseMCPFrame(p).ID, w.uniformMessage))
		return len(p), err
	}
	d := w.decision(p)
	if d == nil {
		return w.ResponseWriter.Write(p)
	}
	var n int
	err := finishMCPDenial(d, mcpDeniedDelivery(func(reply []byte) error {
		var err error
		n, err = w.ResponseWriter.Write(reply)
		return err
	}))
	return n, err
}

func (w *mcpListenerDenialWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	deliver := mcpDeniedDelivery(func([]byte) error { return http.NewResponseController(w.ResponseWriter).Flush() })
	if d := w.decision(nil); d != nil {
		_ = finishMCPDenial(d, deliver)
	} else {
		_ = deliver(nil)
	}
}

func writeMCPHTTPInputResult(opts MCPProxyOpts, br BlockedRequest, w http.ResponseWriter) {
	terminal := br.terminal
	if terminal == nil {
		terminal = newMCPDenial(opts, mcpDenialAudit{}, "input", nil).decision
	}
	if listener, ok := w.(*mcpListenerDenialWriter); ok {
		listener.opts = opts
		listener.terminal = terminal
		*listener.descriptor = terminal.audit
	}
	_ = finishMCPDenial(&mcpDenial{decision: terminal, reply: blockRequestResponse(br)}, mcpDeniedDelivery(func(reply []byte) error {
		w.Header().Set("Content-Type", "application/json")
		if br.IsNotification {
			w.WriteHeader(http.StatusAccepted)
			return nil
		}
		_, err := w.Write(reply)
		return err
	}))
}
