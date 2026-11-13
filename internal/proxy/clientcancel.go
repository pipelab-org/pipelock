// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// clientCanceledStatusText is the response body for a request whose own
// context ended before scanning finished. It is not a block.
const clientCanceledStatusText = "request canceled"

// requestClientCanceled reports that the inbound request context ended
// because the caller went away. A deadline, a nil context, and a context
// that is still live are not this case.
func requestClientCanceled(ctx context.Context) bool {
	return ctx != nil && errors.Is(ctx.Err(), context.Canceled)
}

// bodyResultHasFinding reports a credential, injection, address, entropy,
// or redaction finding already produced by the scan.
func bodyResultHasFinding(result BodyScanResult) bool {
	return len(result.DLPMatches) > 0 || len(result.InjectionMatches) > 0 ||
		len(result.AddressFindings) > 0 || result.EntropyFinding != nil ||
		result.RedactionBlockReason != ""
}

// clientCanceledIncompleteBody is an unfinished body scan whose request
// context was canceled and that produced no finding. Any other unfinished
// scan stays a block.
func clientCanceledIncompleteBody(ctx context.Context, result BodyScanResult) bool {
	return result.ScanError != "" && requestClientCanceled(ctx) && !bodyResultHasFinding(result)
}

// clientCanceledContextRefusal is a URL or admission result that stopped
// because the request context was canceled, rather than a completed check.
func clientCanceledContextRefusal(ctx context.Context, result scanner.Result) bool {
	return result.Scanner == scanner.ScannerContext && requestClientCanceled(ctx)
}

func logRequestCanceled(logger *audit.Logger, actx audit.LogContext, reason string) {
	if logger == nil {
		return
	}
	if reason == "" {
		reason = context.Canceled.Error()
	}
	logger.LogRequestCanceled(actx, reason)
}

func writeClientCanceled(w http.ResponseWriter) {
	http.Error(w, clientCanceledStatusText, http.StatusServiceUnavailable)
}

func writeClientCanceledFetch(w http.ResponseWriter, displayURL, agent string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(FetchResponse{
		URL:     displayURL,
		Agent:   agent,
		Blocked: false,
		Error:   clientCanceledStatusText,
	})
}

// refuseClientCanceledScan logs one cancellation and writes 503 when the
// URL admission stopped because the client went away. The caller returns
// without forwarding, counting a block, or emitting a block receipt.
func refuseClientCanceledScan(ctx context.Context, w http.ResponseWriter, logger *audit.Logger, actx audit.LogContext, result scanner.Result) bool {
	if !clientCanceledContextRefusal(ctx, result) {
		return false
	}
	logRequestCanceled(logger, actx, result.Reason)
	writeClientCanceled(w)
	return true
}
