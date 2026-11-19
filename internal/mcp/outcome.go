// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const mcpUpstreamWriteFailed = "upstream_write_failed"

// One confirmed v1 intent grants a single terminal write on that writer.
type mcpOutcomeHandle struct {
	v1       *receipt.Emitter
	v2       *proxydecision.Emitter
	group    *MCPReceiptGroup
	required bool
	settled  atomic.Bool
}

func isPairedMCPMethod(method string) bool {
	return method == methodToolsCall || method == "initialize" || method == "tools/list" || IsA2AMethod(method)
}

// trackMCPOutcome settles handles that lost correlation without attributing
// a response to them. Writes happen after releasing the tracker's lock.
func trackMCPOutcome(logW io.Writer, opts MCPProxyOpts, tracker *RequestTracker, id json.RawMessage, outcome TrackedRequestOutcome) *requestRegistration {
	registration, unowned := tracker.registerOutcome(id, outcome)
	for _, pending := range unowned {
		pending.outcome.settle(logW, opts, "incomplete", -1, pending.reason)
	}
	return registration
}

func (o TrackedRequestOutcome) settle(logW io.Writer, opts MCPProxyOpts, status string, size int64, reason string) bool {
	if o.Receipt.ActionID == "" {
		return false
	}
	h := o.handle
	if h == nil {
		// Callers that already supply a receipt in a fixed writer context
		// use the established outcome path.
		if status == mcpOutcomeStatusBlocked {
			emitMCPBlockedOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, o.Receipt, size, reason, opts.requireReceipts())
		} else {
			emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, o.Receipt, status, size, reason, opts.requireReceipts())
		}
		return true
	}
	if !h.settled.CompareAndSwap(false, true) {
		return false
	}
	r := mcpOutcomeReceiptOpts(o.Receipt, status, size, reason)
	r.Verdict = config.ActionAllow
	if status == mcpOutcomeStatusBlocked {
		r.Verdict = config.ActionBlock
	} else {
		r.Layer = mcpOutcomeLayer
	}
	return h.emit(logW, r)
}

func (h *mcpOutcomeHandle) emit(logW io.Writer, r receipt.EmitOpts) bool {
	durable := h.required && r.Verdict == config.ActionBlock
	write := h.v1.Emit
	if durable {
		write = h.v1.EmitDurable
	}
	err := write(r)
	if errors.Is(err, receipt.ErrReceiptNotAppended) {
		// Keep the same claim and writer. An error after chain advancement
		// can mean the first append reached disk and must never be retried.
		err = write(r)
	}
	if err != nil {
		h.requiredGroupFailure(err)
		logReceiptEmitFailure(logW, err, h.required, r.Verdict)
		return false
	}
	// Preserve the existing v2 refusal and required-mode evidence.
	if h.v2 != nil && (h.required || r.Verdict == config.ActionBlock) {
		if err := emitMCPV2Decision(h.v2, r, h.required, durable); err != nil {
			h.requiredGroupFailure(err)
			logReceiptEmitFailure(logW, err, h.required, r.Verdict)
			return false
		}
	}
	return true
}

func (h *mcpOutcomeHandle) requiredGroupFailure(err error) {
	if h.required && h.group != nil && (errors.Is(err, receipt.ErrReceiptPostAdvance) || errors.Is(err, receipt.ErrReceiptNotAppended) ||
		h.v1.HealthError() != nil || (h.v2 != nil && h.v2.HealthError() != nil)) {
		h.group.Shards.MarkUnhealthy(err)
		if h.group.OnRequiredFailure != nil {
			h.group.OnRequiredFailure(err)
		}
	}
}
