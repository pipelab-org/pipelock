// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import "net/http"

// mcpListenerDenialWriter is the listener admission adapter. The handler selects
// a typed descriptor at the refusal site. Allowed replies and ordinary upstream
// failures leave it empty; status codes alone never classify an MCP denial.
type mcpListenerDenialWriter struct {
	http.ResponseWriter
	opts       MCPProxyOpts
	descriptor *mcpDenialAudit
	terminal   *mcpTerminalDecision
}

func (w *mcpListenerDenialWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *mcpListenerDenialWriter) decision(reply []byte) *mcpDenial {
	if w.descriptor.kind == "" {
		return nil
	}
	if w.terminal == nil {
		direction := "input"
		spec, _ := denialSpec(w.descriptor.kind)
		if spec.resource == "mcp_response" || spec.resource == "upstream_error_reply" || w.descriptor.kind == "listener_inspection" {
			direction = "response"
		}
		opts := w.opts
		opts.Transport = "mcp_http_listener"
		w.terminal = newMCPDenial(opts, *w.descriptor, direction, nil).decision
	}
	return &mcpDenial{decision: w.terminal, reply: reply}
}

func (w *mcpListenerDenialWriter) WriteHeader(status int) {
	d := w.decision(nil)
	if d == nil {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	_ = finishMCPDenial(d, mcpDeniedDelivery(func([]byte) error { w.ResponseWriter.WriteHeader(status); return nil }))
}

func (w *mcpListenerDenialWriter) Write(p []byte) (int, error) {
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
