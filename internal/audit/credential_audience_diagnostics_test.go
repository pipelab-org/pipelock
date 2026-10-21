// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestLogCredentialAudienceMismatches(t *testing.T) {
	for _, surface := range []string{"body", "header", "url"} {
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
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.DLP.GitHubEnterpriseHosts = []string{"ghe.corp.example"}
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					matches := sc.ScanTextForDLP(t.Context(), "ghp_"+strings.Repeat("a", 36)).Matches
					mismatches = scanner.TextDLPCredentialAudienceMismatches(matches, "https://api.vendor.example/v1", surface)
				}
				ctx := LogContext{method: "POST", target: "https://api.vendor.example/v1"}
				switch surface {
				case "body":
					logger.LogBodyDLP(ctx, actionBlock, 1, []string{"Provider Key"}, nil, mismatches...)
				case "url":
					logger.LogReverseURLDLP(ctx, actionBlock, 1, []string{"Provider Key"}, nil, mismatches...)
				default:
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
				var hint string
				if err := json.Unmarshal(entry["remediation_hint"], &hint); err != nil {
					t.Fatal(err)
				}
				if sink.events[0].Fields["remediation_hint"] != hint {
					t.Fatal("audit and emitter guidance differ")
				}
				if surface == "url" {
					if string(entry["event"]) != `"body_dlp"` || !strings.Contains(hint, "Remove the credential from the request URL") || !strings.Contains(hint, "does not consult") {
						t.Fatalf("reverse URL event=%s hint=%q", entry["event"], hint)
					}
				} else if !strings.Contains(hint, "path-scoped") {
					t.Fatalf("body/header guidance changed: %q", hint)
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
				if len(got) != 1 || got[0].Surface != surface || got[0].PatternName != "GitHub Token" || got[0].Destination != "api.vendor.example" || !got[0].CoreRule || len(got[0].Hosts) == 0 {
					t.Fatalf("metadata=%+v", got)
				}
				if strings.Contains(buf.String()+string(emittedJSON), "ghe.corp.example") {
					t.Fatal("audit or emitter disclosed an operator-declared audience host")
				}
			})
		}
	}
}
