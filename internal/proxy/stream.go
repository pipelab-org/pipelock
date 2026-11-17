// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
)

// recordStreamError shares the audit vocabulary with the existing receipt
// outcome reason. Cancellation is an operator-visible end, not an upstream fault.
func recordStreamError(ctx context.Context, logger *audit.Logger, actx audit.LogContext, err error) string {
	reason := httpstream.Reason(ctx, err)
	if logger != nil && reason == httpstream.Incomplete {
		logger.LogError(actx, fmt.Errorf("response stream %s: %w", reason, err))
	}
	return reason
}

// receiptReasonSSEStreamCancelled is the outcome reason SSE streams already
// record when the client goes away.
const receiptReasonSSEStreamCancelled = "sse_stream_cancelled"

// sseStreamReason keeps the established SSE cancellation reason.
func sseStreamReason(reason string) string {
	if reason == httpstream.Cancelled {
		return receiptReasonSSEStreamCancelled
	}
	return reason
}

// flushFailureReason replaces a delivery-claiming outcome reason when the
// final flush to the client fails. The proxy had already read the upstream
// body, so the failure is a failed write to the client. It is recorded the way
// httpstream.Reason records a failed client write mid-stream, as cancellation,
// and never as an incomplete upstream response. The same stalled or departed
// client then gets one reason whether its failure surfaces while the body is
// copied or at the final flush. An HTTP/2 client that resets the stream after
// the body is buffered fails only the flush, so a cancelled request would
// otherwise read as an upstream fault. Neither reason claims delivery.
func flushFailureReason(deliveredReason string) string {
	if strings.HasPrefix(deliveredReason, "sse_stream") {
		return receiptReasonSSEStreamCancelled
	}
	return httpstream.Cancelled
}

// outcomeReasonClaimsDelivery identifies allowed outcomes that claim delivery.
// Flush failures must retain block verdicts and failure or inspection reasons.
func outcomeReasonClaimsDelivery(reason, verdict string) bool {
	if verdict != config.ActionAllow {
		return false
	}
	switch reason {
	case "", "complete", "sse_stream", "sse_stream_unscanned", "unscannable_passthrough",
		mediaUnscannedOutcome, "non_shieldable_passthrough", "strip":
		return true
	default:
		return false
	}
}
