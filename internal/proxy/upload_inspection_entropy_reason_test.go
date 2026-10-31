// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A blocking entropy finding and an unread upload share one reason. The
// entropy finding is named first and the unread file follows, so the receipt
// pattern records both and the hint keeps the entropy sentence.
func TestUploadInspectionEntropyAndUnreadReason(t *testing.T) {
	body := "Rar!\x1a\x07\x01\x00 " + opaqueHighEntropyBodyValue()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.ContentEntropyEnabled = true
	cfg.RequestBodyScanning.ContentEntropyAction = config.ActionBlock
	cfg.RequestBodyScanning.ContentEntropyThreshold = 4.5
	cfg.RequestBodyScanning.ContentEntropyMinLength = 32
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body: strings.NewReader(body), Scheme: "https", Method: http.MethodPost, ContentType: "application/octet-stream",
		MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc, Action: config.ActionBlock,
		ContentEntropyEnabled: true, ContentEntropyAction: config.ActionBlock,
		ContentEntropyThreshold: 4.5, ContentEntropyMinLength: 32,
	})
	if result.EntropyFinding == nil || len(result.DLPMatches) != 0 || len(result.InjectionMatches) != 0 || len(result.AddressFindings) != 0 || result.FileInspectionIncomplete == "" {
		t.Fatalf("fixture must carry only an entropy finding and an unread file: %+v", result)
	}
	if !strings.HasPrefix(result.Reason, bodyEntropyReason(result)) || !strings.HasSuffix(result.Reason, result.FileInspectionIncomplete) {
		t.Fatalf("reason=%q", result.Reason)
	}
	got, ok := scanner.GuidanceForResult(scannerLabelBodyEntropy, result.Reason)
	if !ok || !strings.HasPrefix(got.AgentReason, "Request blocked: high-entropy content") || !strings.Contains(got.AgentReason, "could not be fully read") ||
		!strings.Contains(got.OperatorKnob, "content_entropy_warn_routes") || !strings.Contains(got.OperatorKnob, "request_body_scanning.action") {
		t.Fatalf("guidance = %+v ok=%t", got, ok)
	}
}
