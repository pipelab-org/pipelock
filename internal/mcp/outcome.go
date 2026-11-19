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
	settled, _ := o.settleResult(logW, opts, status, size, reason)
	return settled
}

func (o TrackedRequestOutcome) settleResult(logW io.Writer, opts MCPProxyOpts, status string, size int64, reason string) (bool, error) {
	if o.Receipt.ActionID == "" {
		return false, nil
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
		return true, nil
	}
	if !h.settled.CompareAndSwap(false, true) {
		return false, nil
	}
	r := mcpOutcomeReceiptOpts(o.Receipt, status, size, reason)
	r.Verdict = config.ActionAllow
	if status == mcpOutcomeStatusBlocked {
		r.Verdict = config.ActionBlock
	} else {
		r.Layer = mcpOutcomeLayer
	}
	err := h.emit(logW, r, false)
	return err == nil, err
}

func (h *mcpOutcomeHandle) emit(logW io.Writer, r receipt.EmitOpts, allowFallback bool) error {
	durable := h.required
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
		if allowFallback && errors.Is(err, receipt.ErrReceiptNotAppended) {
			// The listener's deferred settlement still owns the request.
			// Keep the writer usable only when the v1 chain did not advance.
			h.settled.Store(false)
		} else {
			h.requiredGroupFailure(err)
		}
		logReceiptEmitFailure(logW, err, h.required, r.Verdict)
		return err
	}
	// Preserve the existing v2 refusal and required-mode evidence.
	if h.v2 != nil && (h.required || r.Verdict == config.ActionBlock) {
		if err := emitMCPV2Decision(h.v2, r, h.required, durable); err != nil {
			h.requiredGroupFailure(err)
			logReceiptEmitFailure(logW, err, h.required, r.Verdict)
			return err
		}
	}
	return nil
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

const mcpTransportAdmissionLayer = "mcp_transport_admission"

// admitDurableTransport records the single-phase receipt for opening an MCP
// stream. Best-effort mode records nothing. Required mode returns the error
// instead of opening when that receipt cannot be written.
func admitDurableTransport(opts MCPProxyOpts, method, target string) (receipt.EmitOpts, error) {
	if !opts.requireReceipts() {
		return receipt.EmitOpts{}, nil
	}
	admission := opts.withReceiptPolicyHash(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionForward,
		Transport: opts.Transport,
		Method:    method,
		Target:    target,
		Layer:     mcpTransportAdmissionLayer,
	})
	if group := opts.ReceiptGroup; group != nil && group.Shards != nil {
		admission = group.Shards.Admit(admission)
	}
	if _, err := opts.emitReceiptDecision(MCPDecision{Receipt: admission, RequireReceipt: true}); err != nil {
		return receipt.EmitOpts{}, err
	}
	return admission, nil
}

// warnTransportAdmission closes an admitted stream on the same action and shard.
// An empty action means this open was not recorded.
func warnTransportAdmission(logW io.Writer, opts MCPProxyOpts, admission receipt.EmitOpts, reason string) {
	recordTransportAdmissionResult(logW, opts, admission, "error", reason)
}

func recordTransportAdmissionResult(logW io.Writer, opts MCPProxyOpts, admission receipt.EmitOpts, status, reason string) {
	if admission.ActionID == "" {
		return
	}
	result := mcpOutcomeReceiptOpts(admission, status, -1, reason)
	// Transport admissions are single-phase. Keep the result on the same
	// action without opening an intent pair.
	result.DecisionPhase = ""
	result.Verdict, result.Layer = config.ActionWarn, mcpOutcomeLayer
	if status == "completed" {
		result.Verdict = config.ActionForward
	}
	if _, err := opts.emitReceiptDecision(MCPDecision{
		Receipt: result, RequireReceipt: true, RequiredMode: true, retryV1NotAppended: true,
	}); err != nil {
		logReceiptEmitFailure(logW, err, true, result.Verdict)
	}
}
