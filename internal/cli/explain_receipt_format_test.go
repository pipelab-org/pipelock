// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestExplainEventRefusesReceiptV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, _, path string) {
		_, err := lookupExplainEvent(path, "event", explainEventSanitizer{})
		testreceipt.RequiresV3Refusal(t, err, "explain event", "the audit event reader")
	})
	v3File, _ := testreceipt.V3(t, t.TempDir(), false)
	v3Bytes, err := os.ReadFile(filepath.Clean(v3File))
	if err != nil {
		t.Fatal(err)
	}
	mixed := filepath.Join(t.TempDir(), "audit.jsonl")
	content := append([]byte(`{"request_id":"req-1","action":"allow"}`+"\n"), v3Bytes...)
	if err := os.WriteFile(mixed, content, 0o600); err != nil {
		t.Fatal(err)
	}
	// Unmatched lookup scans past line 1 and must refuse line 2 as v3.
	_, err = lookupExplainEvent(mixed, "req-missing", explainEventSanitizer{})
	testreceipt.RequiresV3Refusal(t, err, "explain event", "the audit event reader")
	// Leading blank line before v3 must also be refused.
	leadingBlank := filepath.Join(t.TempDir(), "leading-blank.jsonl")
	if err := os.WriteFile(leadingBlank, append([]byte("\n"), v3Bytes...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = lookupExplainEvent(leadingBlank, "req-1", explainEventSanitizer{})
	testreceipt.RequiresV3Refusal(t, err, "explain event", "the audit event reader")
}
