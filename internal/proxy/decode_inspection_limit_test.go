// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// deepEntityChain is benign text behind more nested HTML entity layers than
// the decoder's pass limit. Its decoded content is harmless; the refusal is
// about the content the scan could not reach, not about what it found.
func deepEntityChain() string {
	return "note: &" + strings.Repeat("amp;", 24) + "#104;ello"
}

// percentNested encodes s's first byte so that n decoding rounds recover it.
func percentNested(s string, n int) string {
	out := fmt.Sprintf("%%%02X", s[0])
	for i := 1; i < n; i++ {
		out = strings.ReplaceAll(out, "%", "%25")
	}
	return out + s[1:]
}

func TestDecodeInspectionLimitForwardAndFetch(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, nil)
	defer cleanup()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	deepPercent := percentNested("hello", 501)
	split := "dap" + "i" + "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	gapQuery := []string{"p0=" + split[:18]}
	for i := 0; i < 19; i++ {
		gapQuery = append(gapQuery, fmt.Sprintf("m%d=zz", i))
	}
	gapQuery = append(gapQuery, "p1="+split[18:])

	do := func(t *testing.T, method, target, body string) (int, string, string) {
		t.Helper()
		var req *http.Request
		var err error
		if body == "" {
			req, err = http.NewRequestWithContext(t.Context(), method, target, nil)
		} else {
			req, err = http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
			req.Header.Set("Content-Type", "text/plain")
		}
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		detail, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		return resp.StatusCode, resp.Header.Get(blockreason.HeaderReason), string(detail)
	}

	for _, tc := range []struct {
		name, method, target, body string
		want                       int
	}{
		{"forward query rounds", http.MethodGet, upstream.URL + "/p?k=" + deepPercent, "", http.StatusForbidden},
		{"forward path rounds", http.MethodGet, upstream.URL + "/" + deepPercent, "", http.StatusForbidden},
		{"forward split past twenty values", http.MethodGet, upstream.URL + "/p?" + strings.Join(gapQuery, "&"), "", http.StatusForbidden},
		{"forward body entity chain", http.MethodPost, upstream.URL + "/upload", deepEntityChain(), http.StatusForbidden},
		{"forward body control", http.MethodPost, upstream.URL + "/upload", "Tom &amp;amp; Jerry", http.StatusOK},
		{"forward query control", http.MethodGet, upstream.URL + "/p?q=a%2520b", "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := hits.Load()
			got, reason, detail := do(t, tc.method, tc.target, tc.body)
			if got != tc.want {
				t.Fatalf("status %d, want %d", got, tc.want)
			}
			if tc.body == deepEntityChain() {
				if reason != string(blockreason.RequestBodyInspectionLimit) || !strings.Contains(detail, "request body inspection limit reached") {
					t.Fatalf("unexpected request body refusal: reason %q, detail %q", reason, detail)
				}
			}
			if delivered := hits.Load() != before; delivered != (tc.want == http.StatusOK) {
				t.Fatalf("upstream delivered=%v", delivered)
			}
		})
	}

	t.Run("fetch rounds", func(t *testing.T) {
		before := hits.Load()
		target := upstream.URL + "/p?k=" + deepPercent
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+proxyAddr+"/fetch?url="+url.QueryEscape(target), nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || hits.Load() != before {
			t.Fatalf("fetch status %d delivered=%v", resp.StatusCode, hits.Load() != before)
		}
		if !strings.Contains(string(body), "inspection limit") {
			t.Fatalf("fetch refusal does not name the inspection limit: %s", body)
		}
	})
}

func TestRequestBodyInspectionLimitReason(t *testing.T) {
	for _, surface := range []struct {
		name    string
		observe func(*testing.T, []byte, string, func(*testing.T, []byte) []byte) codedObservation
	}{
		{"intercept", observeInterceptUpload},
		{"reverse", observeReverseUpload},
	} {
		for _, tc := range []struct {
			name, body string
			reason     blockreason.Reason
		}{
			{"limit only", deepEntityChain(), blockreason.RequestBodyInspectionLimit},
			{"credential", fakeAPIKey(), blockreason.DLPMatch},
			{"credential and unfinished scan", fakeAPIKey() + "\n" + deepEntityChain(), blockreason.ParseError},
		} {
			t.Run(surface.name+"/"+tc.name, func(t *testing.T) {
				got := surface.observe(t, []byte(tc.body), "", nil)
				if got.status != http.StatusForbidden || got.hits != 0 || got.reason != string(tc.reason) {
					t.Fatalf("status=%d hits=%d reason=%q, want 403 with no delivery and %q", got.status, got.hits, got.reason, tc.reason)
				}
			})
		}
	}
}

func TestDecodeInspectionLimitWebSocketDirection(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	cfg.RequestBodyScanning.Action = config.ActionWarn
	r, _ := newWebSocketFrameSuppressionRelay(t, cfg, "wss://api.vendor.example/socket")
	if !r.scanClientText(t.Context(), audit.NewNop(), []byte(deepEntityChain())) {
		t.Fatal("outbound WebSocket frame past the entity pass limit was not refused")
	}
	if r.scanClientText(t.Context(), audit.NewNop(), []byte("Tom &amp;amp; Jerry")) {
		t.Fatal("outbound WebSocket control refused")
	}
	// Server-to-client text keeps its delivery contract.
	received, blocked := r.enforceUpstreamTextPayload(t.Context(), audit.NewNop(), []byte(deepEntityChain()), false)
	if blocked || string(received) != deepEntityChain() {
		t.Fatalf("inbound WebSocket refused at a decode bound: blocked=%v", blocked)
	}
}
