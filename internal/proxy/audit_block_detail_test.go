// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestAuditDetailFromResult_MapsDNSInfrastructureError(t *testing.T) {
	t.Parallel()

	got := auditDetailFromResult(scanner.Result{
		Class:        scanner.ClassInfrastructureError,
		DNSErrorKind: scanner.DNSErrorTimeout,
	})

	if got.Class != audit.BlockClassInfrastructureError {
		t.Fatalf("Class = %q, want %q", got.Class, audit.BlockClassInfrastructureError)
	}
	if got.DNSErrorKind != string(scanner.DNSErrorTimeout) {
		t.Fatalf("DNSErrorKind = %q, want %q", got.DNSErrorKind, scanner.DNSErrorTimeout)
	}
}

func TestAuditDetailFromResult_ThreatKeepsLegacyZeroClass(t *testing.T) {
	t.Parallel()

	got := auditDetailFromResult(scanner.Result{Class: scanner.ClassThreat})

	if got.Class != "" {
		t.Fatalf("Class = %q, want empty legacy threat class", got.Class)
	}
	if got.DNSErrorKind != "" || got.MatchView != "" {
		t.Fatalf("unexpected audit detail: %+v", got)
	}
}

func TestIntercept_URLDLPMatchView(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cache, pool, cfg, sc, _, metrics := testInterceptSetup(t)
	auditPath, logger := codedAuditLogger(t)
	const id, number = "40000000000", "00000006"
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/orders", http.StatusNoContent},
		{"/orders/detail?id=" + id + "&page=review&number=" + number, http.StatusForbidden},
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := interceptAndRequest(t, upstream, cache, pool, cfg, sc, logger, metrics, req)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream received %d requests, want only the list request", hits.Load())
	}
	auditText := codedAuditText(t, logger, auditPath)
	if !strings.Contains(auditText, `"match_view":"dlp_normalized:query_subsequence"`) {
		t.Fatalf("missing match view in blocked event: %s", auditText)
	}
	if strings.Contains(auditText, id) || strings.Contains(auditText, number) {
		t.Fatal("audit exposed a query value")
	}
}

func TestAuditDetailFromResult_MapsNonThreatClasses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		class     scanner.ResultClass
		wantClass string
	}{
		{"protective", scanner.ClassProtective, audit.BlockClassProtective},
		{"config mismatch", scanner.ClassConfigMismatch, audit.BlockClassConfigMismatch},
		{"structural exemption", scanner.ClassStructuralExemption, audit.BlockClassStructuralExemption},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := auditDetailFromResult(scanner.Result{Class: tc.class})
			if got.Class != tc.wantClass {
				t.Fatalf("Class = %q, want %q", got.Class, tc.wantClass)
			}
		})
	}
}
