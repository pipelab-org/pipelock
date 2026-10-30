// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package checkertest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker"
)

func TestHarness(t *testing.T) {
	Run(t, func(t *testing.T, endpoint string) checker.Checker {
		t.Helper()
		client, err := checker.NewClient(checker.Options{Endpoint: endpoint, AllowLoopbackHTTP: true})
		if err != nil {
			t.Fatal(err)
		}
		return client
	})
}

func TestMalformedMockRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/check", strings.NewReader("{"))
	if err := serveResponse(w, r, nil, nil); err == nil || w.Code != http.StatusBadRequest {
		t.Fatalf("err=%v status=%d", err, w.Code)
	}
}
