// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package checkertest

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/checker"
)

func mockPolicy() checker.Policy {
	return checker.Policy{
		Mode: checker.ModeBlock, Generation: "g", Revision: MockRevision,
		Timeout: 2 * time.Second, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12,
	}
}

func mockItem(texts ...string) checker.Item {
	item := checker.Item{
		ID: "i", Kind: checker.KindText, Surface: "s", Transport: "t", Direction: "response", ExtractionVersion: "v",
		Completeness: &checker.Completeness{Status: checker.Complete},
	}
	for i, text := range texts {
		item.Parts = append(item.Parts, checker.Part{ID: string(rune('a' + i)), Role: "content", Representation: "original", Text: text})
		item.OriginalBytes += int64(len(text))
	}
	item.SubmittedBytes = item.OriginalBytes
	return item
}

// The mock answers each behaviour the way the tests that depend on it assume.
func TestMockServerBehaviours(t *testing.T) {
	m := NewMockServer(t, BehaviorClassify)
	client, err := checker.NewClient(checker.Options{Endpoint: m.URL, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Check(t.Context(), mockItem("plain text"), mockPolicy()); got.State != checker.StateBenign {
		t.Fatalf("classify benign = %+v", got)
	}
	got := client.Check(t.Context(), mockItem("plain text", SuspiciousMarker), mockPolicy())
	if got.State != checker.StateFinding || got.Response == nil || len(got.Response.Findings) != 1 ||
		len(got.Response.Findings[0].PartIDs) != 1 || got.Response.Findings[0].PartIDs[0] != "b" {
		t.Fatalf("classify finding should cite part b: %+v", got)
	}

	m.SetBehavior(BehaviorUncited)
	got = client.Check(t.Context(), mockItem("plain text"), mockPolicy())
	if got.State != checker.StateFinding || len(got.Response.Findings[0].PartIDs) != 0 {
		t.Fatalf("uncited = %+v", got)
	}

	m.SetBehavior(BehaviorDown)
	if got := client.Check(t.Context(), mockItem("plain text"), mockPolicy()); got.State != checker.StateNotAssessed {
		t.Fatalf("down = %+v", got)
	}
	if m.Requests() != 4 {
		t.Fatalf("requests = %d, want 4", m.Requests())
	}
}

func TestMockServerRejectsMalformedRequest(t *testing.T) {
	m := NewMockServer(t, BehaviorClassify)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, m.URL, strings.NewReader("{"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
