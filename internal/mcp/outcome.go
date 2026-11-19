// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
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
	if err := write(r); err != nil {
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
	if h.required && h.group != nil && (errors.Is(err, receipt.ErrReceiptPostAdvance) ||
		h.v1.HealthError() != nil || (h.v2 != nil && h.v2.HealthError() != nil)) {
		h.group.Shards.MarkUnhealthy(err)
		if h.group.OnRequiredFailure != nil {
			h.group.OnRequiredFailure(err)
		}
	}
}
