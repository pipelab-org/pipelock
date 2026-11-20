// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const nativeCapacityReason = "native_ael_capacity"

func recordListenerStreamError(ctx context.Context, logW io.Writer, opts MCPProxyOpts, outcome TrackedRequestOutcome, standalone bool, err error) {
	reason := httpstream.Reason(ctx, err)
	if errors.Is(err, ael.ErrCapacity) {
		reason = nativeCapacityReason
	}
	if reason == httpstream.Incomplete {
		_, _ = fmt.Fprintf(logW, "pipelock: response stream %s: %v\n", reason, err)
		if opts.AuditLogger != nil {
			opts.AuditLogger.LogError(audit.NewMethodLogContext(outcome.Receipt.Method), fmt.Errorf("response stream %s: %w", reason, err))
		}
	}
	if opts.ReceiptV3 != nil {
		recordMCPStreamDiagnostic(opts, logW, outcome.Receipt, standalone, reason)
		return
	}
	outcome.Receipt = opts.withReceiptPolicyHash(outcome.Receipt)
	if standalone {
		if outcome.Receipt.Layer == mcpTransportAdmissionLayer {
			if reason == httpstream.Cancelled {
				recordTransportAdmissionResult(logW, opts, outcome.Receipt, "cancelled", reason)
			} else {
				warnTransportAdmission(logW, opts, outcome.Receipt, reason)
			}
			return
		}
		emitMCPStandaloneStreamReceipt(opts, logW, outcome.Receipt, "200", reason)
		return
	}
	// The listener request-end path settles this same handle. A direct outcome
	// write would leave two terminal receipts for one intent.
	status := "incomplete"
	switch reason {
	case nativeCapacityReason:
		status = "200"
	case httpstream.Cancelled:
		status = "cancelled"
	}
	outcome.settle(logW, opts, status, -1, reason)
}

func logMCPIncompleteResponse(logW io.Writer, opts MCPProxyOpts, method string, err error) {
	if !errors.Is(err, transport.ErrIncompleteResponse) || opts.warnContext().Err() != nil {
		return
	}
	_, _ = fmt.Fprintf(logW, "pipelock: response stream incomplete: %v\n", err)
	if opts.AuditLogger != nil {
		opts.AuditLogger.LogError(audit.NewMethodLogContext(method), fmt.Errorf("response stream incomplete: %w", err))
	}
}

func emitTrackedStreamError(ctx context.Context, logW io.Writer, tracker *RequestTracker, id json.RawMessage, opts MCPProxyOpts, err error) {
	outcome, pending := consumeTrackedRequestOutcome(tracker, id)
	// A consumed unary reply already owns its terminal outcome. A stream
	// can have separate evidence for its lifetime after the reply settles.
	if !pending && !opts.nativeSSE && !isRPCNotification(id) && errors.Is(err, ael.ErrCapacity) {
		return
	}
	standalone := !pending || outcome.Receipt.ActionID == ""
	if standalone {
		outcome.Receipt = mcpStreamReceipt(opts, http.MethodPost)
	}
	reason, status := httpstream.Reason(ctx, err), "incomplete"
	if errors.Is(err, ael.ErrCapacity) {
		reason = nativeCapacityReason
	}
	if opts.ReceiptV3 != nil {
		recordMCPStreamDiagnostic(opts, logW, outcome.Receipt, standalone, reason)
		return
	}
	if reason == httpstream.Cancelled {
		status = "cancelled"
	}
	if standalone {
		defer outcome.releaseNativeLease()
		emitMCPStandaloneStreamReceipt(opts, logW, outcome.Receipt, status, reason)
	} else {
		outcome.settle(logW, opts, status, -1, reason)
	}
}

// A terminal stream error stops further delivery. It does not change the
// outcomes of complete messages that already reached the client.
func recordMCPStreamDiagnostic(opts MCPProxyOpts, logW io.Writer, parent receipt.EmitOpts, standalone bool, reason string) {
	if standalone {
		parent.ActionID = ""
	}
	parent.Transport = firstNonEmpty(parent.Transport, opts.Transport)
	parent.Target = firstNonEmpty(parent.Target, opts.AuthorityDestination, "mcp://response")
	parent.Layer = "mcp_response_stream"
	opts.recordV3MCPRefusal(logW, parent, mcpV3Delivery, reason)
}

func mcpStreamReceipt(opts MCPProxyOpts, method string) receipt.EmitOpts {
	intent := opts.withReceiptPolicyHash(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Transport: opts.Transport,
		Method: method, Target: opts.AuthorityDestination,
	})
	if opts.ReceiptGroup != nil && opts.ReceiptGroup.Shards != nil {
		return opts.ReceiptGroup.Shards.Admit(intent)
	}
	return intent
}

func refuseListenerStreamCapacity(w http.ResponseWriter, r *http.Request, stream *sseMessageWriter) {
	if !stream.Wrote() {
		http.Error(w, ael.ErrCapacity.Error(), http.StatusServiceUnavailable)
		return
	}
	_ = httpstream.Abort(r.Context(), ael.ErrCapacity)
}

// scanMCPHTTPResponse keeps the stream terminal reservation separate from
// the individual event reservations used by ForwardScanned.
func scanMCPHTTPResponse(ctx context.Context, reader transport.MessageReader, writer transport.MessageWriter, logW io.Writer, tracker *RequestTracker, opts MCPProxyOpts) (bool, error) {
	if transport.IsStreamingResponse(reader) {
		opts.nativeSSE = true
		opts.WarnContext = ctx
	}
	return ForwardScanned(opts.withResponseTimeout(reader), writer, logW, tracker, opts)
}
