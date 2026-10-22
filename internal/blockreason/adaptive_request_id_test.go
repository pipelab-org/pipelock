// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package blockreason

import (
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

// After a WebSocket upgrade the request ID is the operator's only handle for
// the audit explanation, so optional adaptive numbers must yield to it.
func TestAdaptiveCloseDetailYieldsToRequestID(t *testing.T) {
	requestID := receiptcontent.NewRequestID()
	if !receiptcontent.ValidRequestID(requestID) {
		t.Fatalf("minted request ID %q is not valid", requestID)
	}
	for _, reason := range []Reason{EscalationLevel, AirlockActive, DLPMatch, PromptInjection} {
		info := Info{Reason: reason, Severity: SeverityCritical, Retry: RetryNone, Layer: "adaptive_enforcement"}
		payload := info.WithRequestID(requestID).CloseFramePayload()
		var got map[string]any
		if err := json.Unmarshal([]byte(payload), &got); err != nil {
			t.Fatalf("%s: decode %q: %v", reason, payload, err)
		}
		if got["request_id"] != requestID {
			t.Fatalf("%s: close payload %s dropped request_id while keeping optional metadata", reason, payload)
		}
		if got["adaptive"] != nil {
			t.Fatalf("%s: unexpected adaptive metadata with minted ID: %s", reason, payload)
		}
		if got["version"] != SchemaVersion {
			t.Fatalf("%s: close payload lost schema version: %s", reason, payload)
		}
	}
}
