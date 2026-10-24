// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInterceptIssuerUploadLocation(t *testing.T) {
	const uploadPath = "/v2/project/blobs/uploads/12345678-1234-1234-1234-123456789abc"
	for _, tc := range []struct {
		name, method string
		status       int
		foreign      bool
		unissued     bool
		secret       bool
		want         int
	}{
		{name: "201 PATCH", status: http.StatusCreated, method: http.MethodPatch, want: http.StatusOK},
		{name: "201 PUT", status: http.StatusCreated, method: http.MethodPut, want: http.StatusOK},
		{name: "202 PATCH", status: http.StatusAccepted, method: http.MethodPatch, want: http.StatusOK},
		{name: "202 PUT", status: http.StatusAccepted, method: http.MethodPut, want: http.StatusOK},
		{name: "unissued value", status: http.StatusAccepted, method: http.MethodPatch, unissued: true, want: http.StatusForbidden},
		{name: "foreign 201", status: http.StatusCreated, method: http.MethodPut, foreign: true, want: http.StatusForbidden},
		{name: "foreign 202", status: http.StatusAccepted, method: http.MethodPatch, foreign: true, want: http.StatusForbidden},
		{name: "issued secret 201", status: http.StatusCreated, method: http.MethodPut, secret: true, want: http.StatusForbidden},
		{name: "issued secret 202", status: http.StatusAccepted, method: http.MethodPatch, secret: true, want: http.StatusForbidden},
		{name: "200 Location", status: http.StatusOK, method: http.MethodPatch, want: http.StatusForbidden},
		{name: "404 Location", status: http.StatusNotFound, method: http.MethodPut, want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := issuedTestToken()
			if tc.secret {
				value += issuerUnissuedSecret()
			}
			location := uploadPath + "?_state=" + value
			if tc.foreign {
				location = "https://other.vendor.example" + location
			}
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/project/blobs/uploads/" {
					w.Header().Set("Location", location)
					w.WriteHeader(tc.status)
					return
				}
				_, _ = io.WriteString(w, "ok")
			}))
			defer upstream.Close()
			cache, pool, cfg, _, _, m := testInterceptSetup(t)
			issuerCookieTestConfig(t, cfg)
			auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
			logger, err := audit.New("json", "file", auditPath, true, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(logger.Close)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			do := func(method, path string) (int, http.Header) {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), method, upstream.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
					Upstream: upstream, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
					Logger: logger, Metrics: m, Request: req, Proxy: p,
					Agent: "agent-one", ActorAuth: envelope.ActorAuthBound,
				})
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return resp.StatusCode, resp.Header
			}
			issuedStatus, issuedHeader := do(http.MethodPost, "/v2/project/blobs/uploads/")
			if issuedStatus != tc.status || issuedHeader.Get("Location") != location {
				t.Fatalf("issuance: status=%d Location=%q, want %d %q", issuedStatus, issuedHeader.Get("Location"), tc.status, location)
			}
			followValue := value
			if tc.unissued {
				followValue = "x" + value
			}
			followStatus, _ := do(tc.method, uploadPath+"?_state="+followValue)
			if followStatus != tc.want {
				t.Fatalf("follow-up status=%d, want %d", followStatus, tc.want)
			}
			logBytes, err := os.ReadFile(filepath.Clean(auditPath))
			if err != nil {
				t.Fatal(err)
			}
			logText := string(logBytes)
			if got := strings.Contains(logText, `"event":"entropy_issuer_query_allow"`); got != (tc.want == http.StatusOK) {
				t.Fatalf("entropy_issuer_query_allow=%v, want %v", got, tc.want == http.StatusOK)
			}
			if tc.want == http.StatusForbidden {
				finding := `high entropy query param`
				if tc.secret {
					finding = "AWS Access ID"
				}
				if !strings.Contains(logText, finding) {
					t.Fatalf("audit missing blocking finding %q", finding)
				}
			}
		})
	}
}

func TestIssuerUploadLocationDLP(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusAccepted} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.TLSInterception.Enabled = true
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			ic := &InterceptContext{Proxy: p, Config: cfg, Agent: "agent-one", ActorAuth: envelope.ActorAuthBound}
			value := issuedTestToken() + issuerUnissuedSecret()
			issuer := mustIssuerQueryURL(t, "https://registry.vendor.example/v2/project/blobs/uploads/")
			target := issuer.ResolveReference(mustIssuerQueryURL(t, "/upload?_state="+value))
			recordDeliveredIssuerQuery(ic, &http.Response{
				Request: &http.Request{URL: issuer}, StatusCode: status,
				Header: http.Header{"Location": {target.String()}},
			}, nil, true)
			session := sessionKeyFor(cfg, ic.Agent, ic.ClientIP, ic.ActorAuth)
			allows := func(key, value string) bool { return ic.issuerQueryStore().allows(session, target, key, value) }
			if !allows("_state", value) {
				t.Fatal("secret control did not receive issuer entropy evidence")
			}
			ctx := scanner.WithIssuerQueryAllowance(t.Context(), allows)
			if result := sc.Scan(ctx, target.String()); result.Allowed || result.Scanner != scanner.ScannerCoreDLP {
				t.Fatalf("issued secret must still hit DLP: %+v", result)
			}
		})
	}
}
