// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestLogCredentialAudienceMismatches(t *testing.T) {
	for _, surface := range []string{"body", "header"} {
		for _, present := range []bool{false, true} {
			t.Run(surface+"/"+map[bool]string{false: "absent", true: "present"}[present], func(t *testing.T) {
				var buf bytes.Buffer
				logger, err := New("json", "custom", "", true, true)
				if err != nil {
					t.Fatal(err)
				}
				logger.zl = logger.zl.Output(&buf)
				sink := &collectingSink{}
				emitter := emit.NewEmitter("test-audience-diagnostics", sink)
				logger.SetEmitter(emitter)
				t.Cleanup(func() { _ = emitter.Close() })
				var mismatches []scanner.CredentialAudienceMismatch
				if present {
					mismatches = []scanner.CredentialAudienceMismatch{{PatternName: "Provider Key", Surface: surface, Destination: "api.vendor.example", Hosts: []string{"api.provider.example"}}}
				}
				ctx := LogContext{method: "POST", target: "https://api.vendor.example/v1"}
				if surface == "body" {
					logger.LogBodyDLP(ctx, actionBlock, 1, []string{"Provider Key"}, nil, mismatches...)
				} else {
					logger.LogHeaderDLP(ctx, "Authorization", actionBlock, []string{"Provider Key"}, nil, mismatches...)
				}
				var entry map[string]json.RawMessage
				if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
					t.Fatal(err)
				}
				if err := emitter.Close(); err != nil {
					t.Fatal(err)
				}
				sink.mu.Lock()
				defer sink.mu.Unlock()
				if len(sink.events) != 1 {
					t.Fatalf("emitted %d events, want 1", len(sink.events))
				}
				emitted, emittedPresent := sink.events[0].Fields["credential_audience_mismatches"]
				if emittedPresent != present {
					t.Fatalf("emitter diagnosis present=%v, want %v", emittedPresent, present)
				}
				raw, ok := entry["credential_audience_mismatches"]
				if ok != present {
					t.Fatalf("present=%v log=%s", present, buf.String())
				}
				if !present {
					return
				}
				emittedJSON, err := json.Marshal(emitted)
				if err != nil || !bytes.Equal(emittedJSON, raw) {
					t.Fatalf("emitter metadata=%s log metadata=%s err=%v", emittedJSON, raw, err)
				}
				var got []scanner.CredentialAudienceMismatch
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 || got[0].Surface != surface || got[0].PatternName != "Provider Key" || got[0].Destination != "api.vendor.example" || len(got[0].Hosts) != 1 || got[0].Hosts[0] != "api.provider.example" {
					t.Fatalf("metadata=%+v", got)
				}
			})
		}
	}
}
