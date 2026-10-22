// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

type mcpDenialAudit struct {
	kind    mcpDenialKind
	pattern string
	context *audit.LogContext
}

type mcpDenialScope struct {
	transport string
	direction string
	method    string
}

type mcpTerminalDecision struct {
	once   sync.Once
	audit  mcpDenialAudit
	scope  mcpDenialScope
	logger *audit.Logger
}

type mcpDenial struct {
	decision *mcpTerminalDecision
	reply    []byte
}

type (
	mcpDenialAdapter  interface{ deliverDeniedReply([]byte) error }
	mcpDeniedDelivery func([]byte) error
)

func (f mcpDeniedDelivery) deliverDeniedReply(reply []byte) error { return f(reply) }

// newMCPDenial allocates identity at the terminal decision, never by RPC ID.
// Unknown descriptors preserve enforcement and use a fixed operational event.
func newMCPDenial(opts MCPProxyOpts, descriptor mcpDenialAudit, direction string, reply []byte) *mcpDenial {
	if _, valid := denialSpec(descriptor.kind); !valid {
		descriptor = mcpDenialAudit{kind: "unclassified"}
	}
	method := "MCP"
	if spec, _ := denialSpec(descriptor.kind); spec.resource == "mcp-input" {
		method = "CEE"
	}
	create := func() *mcpTerminalDecision {
		return &mcpTerminalDecision{
			audit: descriptor, logger: opts.AuditLogger,
			scope: mcpDenialScope{transport: firstNonEmpty(opts.Transport, transportMCPStdio), direction: direction, method: method},
		}
	}
	terminal := create
	if opts.denialTerminal != nil {
		terminal = func() *mcpTerminalDecision { return opts.denialTerminal.load(create) }
	}
	return &mcpDenial{decision: terminal(), reply: reply}
}

// finishMCPDenial owns the one canonical emission attempt. Sink failure never
// changes enforcement. Delivery is attempted after audit, including silent drops.
func finishMCPDenial(d *mcpDenial, adapter mcpDenialAdapter) error {
	d.decision.once.Do(func() {
		terminal := d.decision
		if terminal.logger == nil {
			return
		}
		spec, _ := denialSpec(terminal.audit.kind)
		reason := spec.reason
		if reason == "" {
			reason = terminal.audit.pattern
		}
		if reason == "" {
			reason = spec.label
		}
		ctx := mustMCPAuditContext(terminal.logger, terminal.scope.method, spec.resource)
		if terminal.audit.context != nil {
			ctx = *terminal.audit.context
		}
		ctx = ctx.WithMCPRoute(terminal.scope.transport, terminal.scope.direction)
		terminal.logger.LogMCPBlocked(ctx, spec.label, reason, audit.BlockDetail{Class: spec.class})
	})
	if err := adapter.deliverDeniedReply(d.reply); err != nil {
		return &mcpFinalizedDenialError{err: err}
	}
	return nil
}

func dropMCPDenial(opts MCPProxyOpts, descriptor mcpDenialAudit, direction string) {
	_ = finishMCPDenial(newMCPDenial(opts, descriptor, direction, nil), mcpDeniedDelivery(func([]byte) error { return nil }))
}

func writeMCPDenial(opts MCPProxyOpts, descriptor mcpDenialAudit, writer transport.MessageWriter, reply []byte) error {
	return finishMCPDenial(newMCPDenial(opts, descriptor, "response", reply), mcpDeniedDelivery(func(reply []byte) error { return deliverMCPDeniedMessage(writer, reply) }))
}

// sendMCPDenial is the stdio input handoff adapter. Notification suppression is
// downstream of finalization, so notifications leave the same canonical event.
func sendMCPDenial(opts MCPProxyOpts, descriptor mcpDenialAudit, br BlockedRequest, out chan<- BlockedRequest) {
	d := newMCPDenial(opts, descriptor, "input", nil)
	br.terminal = d.decision
	_ = finishMCPDenial(d, mcpDeniedDelivery(func([]byte) error { out <- br; return nil }))
}

// inputMCPDenial is the HTTP/WS input result adapter. The decision pointer is
// retained in the handoff so a later wire adapter can reuse its emission state.
func inputMCPDenial(opts MCPProxyOpts, descriptor mcpDenialAudit, br *BlockedRequest) *BlockedRequest {
	if br == nil {
		return nil
	}
	d := newMCPDenial(opts, descriptor, "input", nil)
	br.terminal = d.decision
	_ = finishMCPDenial(d, mcpDeniedDelivery(func([]byte) error { return nil }))
	return br
}

// Successful redirects are synthetic results, never terminal denials.
type mcpSyntheticResult struct {
	response     []byte
	notification bool
	logMessage   string
}

// The legacy channel is a wire handoff only. Success has a separate typed
// disposition before entering it and never acquires a terminal denial.
func sendMCPSynthetic(result mcpSyntheticResult, out chan<- BlockedRequest) {
	out <- BlockedRequest{SyntheticResponse: result.response, IsNotification: result.notification, LogMessage: result.logMessage}
}

func deliverMCPSynthetic(result *mcpSyntheticResult, writer transport.MessageWriter) error {
	if result.notification {
		return nil
	}
	return writer.WriteMessage(result.response)
}

func writeMCPResponseDisposition(opts MCPProxyOpts, descriptor mcpDenialAudit, writer transport.MessageWriter, reply []byte, denied bool) error {
	if denied {
		return writeMCPDenial(opts, descriptor, writer, reply)
	}
	return writer.WriteMessage(reply)
}

// deliverMCPInputResult preserves the shared terminal identity across input
// handoff and wire delivery. Successful synthetic redirects have no denial.
func deliverMCPInputResult(opts MCPProxyOpts, br BlockedRequest, writer transport.MessageWriter) error {
	var reply []byte
	if br.SyntheticResponse != nil {
		reply = br.SyntheticResponse
	} else {
		reply = blockRequestResponse(br)
	}
	if br.terminal == nil && br.SyntheticResponse != nil {
		if br.IsNotification {
			return nil
		}
		return writer.WriteMessage(reply)
	}
	terminal := br.terminal
	if terminal == nil {
		terminal = newMCPDenial(opts, mcpDenialAudit{}, "input", nil).decision
	}
	return finishMCPDenial(&mcpDenial{decision: terminal, reply: reply}, mcpDeniedDelivery(func(reply []byte) error {
		if br.IsNotification {
			return nil
		}
		return deliverMCPDeniedMessage(writer, reply)
	}))
}

func writeMCPInputDenial(opts MCPProxyOpts, descriptor mcpDenialAudit, writer transport.MessageWriter, reply []byte) error {
	return finishMCPDenial(newMCPDenial(opts, descriptor, "input", reply), mcpDeniedDelivery(func(reply []byte) error { return deliverMCPDeniedMessage(writer, reply) }))
}

// mcpDeferredTerminal shares one decision across retries of a held call's
// terminal callback. Separate holds, even with equal RPC IDs, get fresh slots.
type mcpDeferredTerminal struct {
	once     sync.Once
	decision *mcpTerminalDecision
}

func (s *mcpDeferredTerminal) load(create func() *mcpTerminalDecision) *mcpTerminalDecision {
	s.once.Do(func() { s.decision = create() })
	return s.decision
}

// Revocation-aware writers retain their final gate for denied replies, without
// turning a failed error delivery into a second terminal decision.
func deliverMCPDeniedMessage(writer transport.MessageWriter, reply []byte) error {
	if denied, ok := writer.(interface{ writeDeniedMessage([]byte) error }); ok {
		return denied.writeDeniedMessage(reply)
	}
	return writer.WriteMessage(reply)
}

// Carry finalization through existing error wrapping so listener fallbacks do
// not create a second event when delivery of an already denied frame fails.
type mcpFinalizedDenialError struct{ err error }

func (e *mcpFinalizedDenialError) Error() string { return e.err.Error() }
func (e *mcpFinalizedDenialError) Unwrap() error { return e.err }

func mcpDenialWasFinalized(err error) bool {
	var denied *mcpFinalizedDenialError
	return errors.As(err, &denied)
}
