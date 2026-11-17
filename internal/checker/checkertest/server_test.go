// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package checkertest

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/checker/selection"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Consumers rely on these outcomes being valid protocol replies, rather than
// malformed replies that coincidentally produce the same delivery decision.
func TestServerProtocolOutcomes(t *testing.T) {
	for state, want := range map[string]checker.State{"benign": checker.StateBenign, "finding": checker.StateFinding, "not_checked": checker.StateNotAssessed, "incomplete": checker.StateIncomplete, "failure": checker.StateNotAssessed} {
		t.Run(state, func(t *testing.T) {
			srv := New(t, state)
			cfg := config.Defaults()
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
			set, err := selection.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(set.Close)
			binding, ok := set.Decider(config.InjectionSurfaceHTTPResponse)
			if !ok {
				t.Fatal("missing fixture binding")
			}
			const text = "ordinary text"
			item := checker.Item{ID: "protocol-test", Kind: checker.KindText, Surface: config.InjectionSurfaceHTTPResponse, Transport: "test", Direction: "response", ExtractionVersion: "test/v1", Parts: []checker.Part{{ID: "text-0", Role: "content", Representation: "original", Text: text}}, OriginalBytes: int64(len(text)), SubmittedBytes: int64(len(text)), Completeness: &checker.Completeness{Status: checker.Complete}}
			got := binding.Checker.Check(t.Context(), item, binding.Policy)
			if got.State != want || got.Reason == checker.ReasonMalformed {
				t.Fatalf("fixture %s returned an invalid outcome: %+v", state, got)
			}
			if len(srv.Items()) != 1 {
				t.Fatal("fixture did not observe request")
			}
		})
	}
}

func TestServerRejectsMalformedRequests(t *testing.T) {
	for _, body := range []string{`{`, `{"item":"wrong"}`} {
		t.Run(body, func(t *testing.T) {
			srv := New(t, "benign")
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.srv.URL, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := srv.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusBadRequest || len(srv.Items()) != 0 {
				t.Fatalf("malformed fixture request admitted: status=%d", resp.StatusCode)
			}
		})
	}
}
