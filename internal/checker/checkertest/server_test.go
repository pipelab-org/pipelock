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

// NewMatching flags an item only when one of its parts is exactly the supplied
// text, and attributes the finding to that part rather than the first one.
func TestServerNewMatchingAttributesFindingToMatchedPart(t *testing.T) {
	const wording = "decoded wording under test"
	part := func(id, text string) checker.Part {
		return checker.Part{ID: id, Role: "decoded_view", Representation: "for_matching/v1", Text: text}
	}
	tests := []struct {
		name  string
		parts []checker.Part
		want  checker.State
		ids   []string
	}{
		{name: "match_in_later_part", parts: []checker.Part{part("p0", "ordinary text"), part("p1", wording), part("p2", wording+" again")}, want: checker.StateFinding, ids: []string{"p1"}},
		{name: "match_in_first_part", parts: []checker.Part{part("p0", wording), part("p1", "ordinary text")}, want: checker.StateFinding, ids: []string{"p0"}},
		{name: "substring_is_not_a_match", parts: []checker.Part{part("p0", "prefix "+wording), part("p1", wording+" suffix")}, want: checker.StateBenign},
		{name: "no_match", parts: []checker.Part{part("p0", "ordinary text")}, want: checker.StateBenign},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewMatching(t, wording)
			cfg := config.Defaults()
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
			var size int64
			for _, p := range tc.parts {
				size += int64(len(p.Text))
			}
			item := checker.Item{ID: "matching-test", Kind: checker.KindText, Surface: config.InjectionSurfaceHTTPResponse, Transport: "test", Direction: "response", ExtractionVersion: "test/v1", Parts: tc.parts, OriginalBytes: size, SubmittedBytes: size, Completeness: &checker.Completeness{Status: checker.Complete}}
			got := binding.Checker.Check(t.Context(), item, binding.Policy)
			if got.State != tc.want || got.Reason == checker.ReasonMalformed {
				t.Fatalf("assessment: %+v", got)
			}
			if tc.want == checker.StateBenign {
				if got.Response == nil || len(got.Response.Findings) != 0 {
					t.Fatalf("benign item carried findings: %+v", got.Response)
				}
				return
			}
			if got.Response == nil || len(got.Response.Findings) != 1 || strings.Join(got.Response.Findings[0].PartIDs, ",") != strings.Join(tc.ids, ",") {
				t.Fatalf("finding not attributed to %v: %+v", tc.ids, got.Response)
			}
		})
	}
}
