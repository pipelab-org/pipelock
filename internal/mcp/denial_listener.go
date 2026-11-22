// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
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
	localReply     *mcpListenerLocalReply
	receiptManaged bool
	uniform        bool
	uniformMessage string
	replied        bool
	// notification marks a parsed POST notification. A clean one is refused
	// with 202 and no body, so block_all gives a caught one the same answer.
	notification bool
}

// mcpListenerLocalReply stages an HTTP status and body until their delivery
// can be admitted outside listener state and contract locks.
type mcpListenerLocalReply struct {
	ctx            context.Context
	writer         *mcpListenerDenialWriter
	opts           MCPProxyOpts
	log            io.Writer
	exchange       *mcpV3NetworkExchange
	evidence       receipt.EmitOpts
	blocked        *BlockedRequest
	receiptFailure bool
	status         int
	body           bytes.Buffer
}

func (r *mcpListenerLocalReply) WriteMessage(msg []byte) error {
	w := r.writer.ResponseWriter
	if r.status != http.StatusNoContent && r.status != http.StatusNotModified {
		w.Header().Set("Content-Length", strconv.Itoa(len(msg)))
	}
	w.WriteHeader(r.status)
	if len(msg) != 0 {
		n, err := w.Write(msg)
		if err != nil {
			return err
		}
		if n != len(msg) {
			return io.ErrShortWrite
		}
	}
	return http.NewResponseController(w).Flush()
}

func (r *mcpListenerLocalReply) finish() {
	if r.status == 0 {
		return
	}
	r.opts.WarnContext = r.ctx
	evidence := r.evidence
	if r.receiptFailure {
		evidence.Layer = mcpReceiptEmissionReason
		evidence.Target = "mcp://receipt-admission"
	} else if r.exchange != nil && r.exchange.send != nil {
		evidence = r.exchange.send.request
	}
	// An empty HTTP response still has status framing to deliver.
	body := r.body.Bytes()
	if body == nil {
		body = []byte{}
	}
	reply := mcpV3ReplyWriter{base: r, opts: r.opts, log: r.log, request: evidence}
	var err error
	withListenerWriteDeadline(r.writer, listenerDownstreamWriteTimeout, func() {
		switch {
		case r.receiptFailure:
			reply.sendDenied = true
			err = reply.WriteMessage(body)
		case r.blocked != nil:
			reply.request = r.blocked.v3Evidence
			err = reply.deliverDenial(body, r.blocked.v3RefusalSigned, r.blocked.v3RefusalErr)
		case r.writer.descriptor.kind != "":
			err = reply.writeDeniedMessage(body)
		default:
			err = reply.WriteMessage(body)
		}
	})
	logMCPV3Error(r.log, err)
	if errors.Is(err, errMCPV3ReplyAdmission) {
		_ = httpstream.Abort(r.ctx, err)
	}
}

func (w *mcpListenerDenialWriter) wireHeader(status int) {
	if local := w.localReply; local != nil && !w.receiptManaged &&
		(local.exchange == nil || !local.exchange.wrote) {
		local.status = status
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *mcpListenerDenialWriter) wireBody(p []byte) (int, error) {
	if w.localReply != nil && w.localReply.status != 0 {
		return w.localReply.body.Write(p)
	}
	return w.ResponseWriter.Write(p)
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

func (w *mcpListenerDenialWriter) responseDenial(terminal *mcpTerminalDecision) {
	w.direction = "response"
	w.terminal = terminal
	*w.descriptor = terminal.audit
}

func (w *mcpListenerDenialWriter) pendingAdaptiveRefusal() bool {
	if w.wroteHeader || w.terminal == nil || w.terminal.audit.keepsOwnRefusal() {
		return false
	}
	_, blocked := adaptiveRefusalMessage(w.opts)
	return blocked
}

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
	w.writeHeader(status, nil)
}

// WriteMessage delivers one local JSON-RPC reply with final HTTP framing.
func (w *mcpListenerDenialWriter) WriteMessage(msg []byte) error {
	w.receiptManaged = true
	w.Header().Set("Content-Type", "application/json")
	n, err := w.writeBuffered(msg)
	if err != nil {
		return err
	}
	if n != len(msg) {
		return io.ErrShortWrite
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// writeBuffered fixes the response framing before flushing delivery evidence.
func (w *mcpListenerDenialWriter) writeBuffered(body []byte) (int, error) {
	if !w.wroteHeader {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.writeHeader(http.StatusOK, body)
	}
	return w.Write(body)
}

func (w *mcpListenerDenialWriter) writeHeader(status int, buffered []byte) {
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
		w.wireHeader(status)
		return
	}
	if w.opts.Rec != nil && !d.decision.audit.keepsOwnRefusal() {
		if info, message, blocked := decide.AdaptiveRefusal(w.opts.Rec.EscalationLevel(), w.opts.adaptiveCfg()); blocked {
			w.uniform = true
			w.uniformMessage = "pipelock: " + message
			for key := range w.Header() {
				// setListenerCORSHeaders depends only on the request Origin, so
				// keeping its headers reveals nothing and lets a browser client
				// read the refusal.
				if isListenerCORSHeader(key) {
					continue
				}
				w.Header().Del(key)
			}
			info.SetHeaders(w.Header())
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if buffered != nil {
				size := 0
				if !w.notification {
					size = len(blockSessionDenyResponse(ParseMCPFrame(buffered).ID, w.uniformMessage))
				}
				w.Header().Set("Content-Length", strconv.Itoa(size))
			}
			if w.notification {
				// Door mode answers a refused notification with 403 like any
				// other tool-policy denial; elsewhere notifications get 202.
				if w.opts.ListenerDoor == nil || status != http.StatusForbidden {
					status = http.StatusAccepted
				}
			} else if status != http.StatusAccepted {
				status = http.StatusForbidden
			}
		}
	}
	_ = finishMCPDenial(d, mcpDeniedDelivery(func([]byte) error { w.wireHeader(status); return nil }))
}

func (w *mcpListenerDenialWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.uniform {
		if w.replied || w.notification {
			return len(p), nil
		}
		w.replied = true
		_, err := w.wireBody(blockSessionDenyResponse(ParseMCPFrame(p).ID, w.uniformMessage))
		return len(p), err
	}
	d := w.decision(p)
	if d == nil {
		return w.wireBody(p)
	}
	var n int
	err := finishMCPDenial(d, mcpDeniedDelivery(func(reply []byte) error {
		var err error
		n, err = w.wireBody(reply)
		return err
	}))
	return n, err
}

func (w *mcpListenerDenialWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.localReply != nil && w.localReply.status != 0 {
		return
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
		if opts.ListenerDoor != nil && terminal.audit.kind == "policy" {
			w.WriteHeader(http.StatusForbidden)
			if br.IsNotification {
				return nil
			}
		} else if br.IsNotification {
			w.WriteHeader(http.StatusAccepted)
			return nil
		}
		_, err := w.Write(reply)
		return err
	}))
}
