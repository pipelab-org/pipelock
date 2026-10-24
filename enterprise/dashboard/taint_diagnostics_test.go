//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDashboardMCPTaintDiagnostics_RenderedWithoutRawValues(t *testing.T) {
	handler := New(Options{
		Config: config.Defaults(), ReceiptDir: t.TempDir(), HasFeature: allowAgentsFeature,
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
	})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/exemptions", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	for _, want := range []string{"MCP taint diagnostics", "taint.mcp_recorder", "taint.mcp_listener", "taint.mcp_origin", "taint.mcp_recovery", "cross-request taint protection is NOT active", "live recorder allocation and caller binding are unproven"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("dashboard omitted %q", want)
		}
	}
}
