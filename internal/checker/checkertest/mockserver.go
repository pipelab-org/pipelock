// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package checkertest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker"
)

// Mock server behaviours.
const (
	// BehaviorClassify answers suspicious when any part contains the
	// SuspiciousMarker, benign otherwise. The finding cites the first part
	// containing the marker.
	BehaviorClassify = "classify"
	// BehaviorDown answers HTTP 503.
	BehaviorDown = "down"
	// BehaviorUncited answers suspicious with a finding citing no parts.
	BehaviorUncited = "uncited"
	// BehaviorEchoReason answers suspicious with the first part's text as the
	// finding's reason ID, like a checker that echoes assessed content.
	BehaviorEchoReason = "echo_reason"
)

// SuspiciousMarker is the text BehaviorClassify treats as an attack.
const SuspiciousMarker = "Ignore all previous instructions"

// MockRevision is the identity the mock reports in every response.
var MockRevision = checker.Revision{Checker: "mock/v1", Model: "mock-model/v1", Adapter: "mock-adapter/v1"}

// MockServer is a loopback pipelock.checker/v1 service for integration tests.
type MockServer struct {
	URL      string
	requests atomic.Int32
	mu       sync.Mutex
	behavior string
}

// Requests reports how many requests the server received.
func (m *MockServer) Requests() int { return int(m.requests.Load()) }

// SetBehavior switches the server's behaviour for later requests.
func (m *MockServer) SetBehavior(b string) {
	m.mu.Lock()
	m.behavior = b
	m.mu.Unlock()
}

// NewMockServer starts a mock checker on a loopback address and stops it at
// test cleanup.
func NewMockServer(t testing.TB, behavior string) *MockServer {
	t.Helper()
	m := &MockServer{behavior: behavior}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		var req checker.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var item checker.Item
		_ = json.Unmarshal(req.Item, &item)
		m.mu.Lock()
		behavior := m.behavior
		m.mu.Unlock()
		if behavior == BehaviorDown {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		resp := checker.Response{
			Version: checker.Version, RequestID: req.ID, ItemID: item.ID, InputBinding: req.InputBinding,
			Revision: MockRevision, Completeness: &checker.Completeness{Status: checker.Complete},
			Status: checker.StatusAssessed, Classification: checker.Benign,
		}
		switch behavior {
		case BehaviorUncited:
			resp.Classification = checker.Suspicious
			resp.Findings = []checker.Finding{{ReasonID: "instruction_override"}}
		case BehaviorEchoReason:
			resp.Classification = checker.Suspicious
			if len(item.Parts) > 0 {
				resp.Findings = []checker.Finding{{ReasonID: item.Parts[0].Text}}
			}
		default:
			for _, p := range item.Parts {
				if strings.Contains(p.Text, SuspiciousMarker) {
					resp.Classification = checker.Suspicious
					resp.Findings = []checker.Finding{{ReasonID: "instruction_override", PartIDs: []string{p.ID}}}
					break
				}
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	m.URL = srv.URL + "/check"
	return m
}
