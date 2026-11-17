// Copyright 2026 Pipelock contributors
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
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestBufferedCheckerHTTPTransports(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportConnect, TransportReverse} {
		for _, state := range []string{"benign", "finding", "failure", "not_checked"} {
			for _, mode := range []string{config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
				t.Run(transport+"/"+state+"/"+mode, func(t *testing.T) {
					srv := checkertest.New(t, state)
					cfg := shieldRewriteMarkerConfig()
					cfg.BrowserShield.Enabled = false
					cfg.ResponseScanning.Enabled = true
					cfg.ResponseScanning.Action = config.ActionWarn
					if state == "benign" {
						cfg.ResponseScanning.Action = config.ActionBlock
					}
					srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, mode)
					body := "ordinary upstream content"
					if state == "benign" {
						body = checkertest.Directive
					}
					status, got := requestShieldScan(t, cfg, transport, []byte(body), "text/plain")
					block := mode == config.InjectionModeBlock && state != "benign"
					if (status != http.StatusOK) != block {
						t.Fatalf("status=%d block=%v: %s", status, block, got)
					}
					items := srv.Items()
					if mode == config.InjectionModeOff {
						if len(items) != 0 {
							t.Fatal("off made a request")
						}
						return
					}
					if len(items) != 1 {
						t.Fatalf("checker calls=%d", len(items))
					}
					if items[0].Surface != config.InjectionSurfaceHTTPResponse || items[0].Transport != transport {
						t.Fatalf("item=%+v", items[0])
					}
				})
			}
		}
	}
}

func TestBufferedCheckerShieldTransports(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportConnect, TransportReverse} {
		for _, state := range []string{"benign", "finding", "failure"} {
			t.Run(transport+"/"+state, func(t *testing.T) {
				srv := checkertest.New(t, state)
				cfg := shieldRewriteMarkerConfig()
				enableShieldRewriteMarkerCategories(cfg)
				cfg.BrowserShield.Enabled = true
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Action = config.ActionWarn
				if state == "benign" {
					cfg.ResponseScanning.Action = config.ActionBlock
				}
				srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeOff)
				srv.Configure(cfg, config.InjectionSurfaceBrowserShield, config.InjectionModeBlock)
				body := `<html><body><article><p>` + strings.Repeat("Ordinary documentation. ", 60) + `</p><div style="display:none">` + checkertest.Directive + `</div></article></body></html>`
				status, got := requestShieldScan(t, cfg, transport, []byte(body), "text/html")
				if (status != http.StatusOK) != (state != "benign") {
					t.Fatalf("status=%d: %s", status, got)
				}
				if len(srv.Items()) != 1 || srv.Items()[0].Surface != config.InjectionSurfaceBrowserShield {
					t.Fatalf("items=%+v", srv.Items())
				}
			})
		}
	}
}

func TestBufferedCheckerRequestBody(t *testing.T) {
	for _, state := range []string{"benign", "finding", "failure", "not_checked", "incomplete"} {
		for _, mode := range []string{config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
			t.Run(state+"/"+mode, func(t *testing.T) {
				srv := checkertest.New(t, state)
				cfg := testScannerConfig()
				srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, mode)
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				text := "ordinary input"
				if state == "benign" {
					text = checkertest.Directive
				}
				_, got := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(`{"message":"` + text + `"}`), ContentType: "application/json", MaxBytes: 1024, Scanner: sc, Action: config.ActionWarn})
				finding := mode == config.InjectionModeBlock && state == "finding"
				block := mode == config.InjectionModeBlock && state != "benign" && !finding
				if (!got.Clean && got.Action == config.ActionBlock) != block || scanner.HasCheckerFinding(got.InjectionMatches) != finding {
					t.Fatalf("block=%v finding=%v result=%+v", block, finding, got)
				}
				if finding && got.Action != "" && got.Action != config.ActionWarn {
					t.Fatalf("finding replaced request action: %+v", got)
				}
				if block && (got.ScanError == "" || len(got.InjectionMatches) != 0) {
					t.Fatalf("checker failure became a finding: %+v", got)
				}
				if !block && !finding && !got.Clean {
					t.Fatalf("non-blocking checker retained wording findings: %+v", got)
				}
				if mode != config.InjectionModeOff && len(srv.Items()) != 1 {
					t.Fatalf("calls=%d", len(srv.Items()))
				}
			})
		}
	}
}

func TestBufferedCheckerRequestTrust(t *testing.T) {
	for _, enforce := range []bool{true, false} {
		for _, trusted := range []bool{true, false} {
			t.Run(fmt.Sprintf("enforce=%t/trusted=%t", enforce, trusted), func(t *testing.T) {
				cfg := testScannerConfig()
				cfg.Enforce = &enforce
				if trusted {
					cfg.RequestBodyScanning.TrustedHosts = []string{"api.vendor.example"}
				}
				srv := checkertest.New(t, "finding")
				srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, config.InjectionModeBlock)
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				assessed := sc.ScanBufferedInjection(t.Context(), scanner.BufferedInjectionScan{Surface: config.InjectionSurfaceHTTPRequestBody, Content: "ordinary input"})
				if !assessed.CheckerBlocked() {
					t.Fatal("fixture did not produce a block finding")
				}
				r := BodyScanResult{InjectionMatches: assessed.Matches}
				if got, want := shouldHardBlockBodyPromptInjection(r, "api.vendor.example", cfg), enforce && !trusted; got != want {
					t.Fatalf("hard block=%t want=%t", got, want)
				}
			})
		}
	}
}

func TestBufferedCheckerRequestTransports(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportConnect, TransportReverse} {
		for _, enforce := range []bool{true, false} {
			for _, trusted := range []bool{true, false} {
				for _, action := range []string{config.ActionWarn, config.ActionBlock} {
					for _, state := range []string{"builtin", "finding", "failure", "not_checked", "incomplete"} {
						t.Run(fmt.Sprintf("%s/enforce=%t/trusted=%t/%s/%s", transport, enforce, trusted, action, state), func(t *testing.T) {
							srv := checkertest.New(t, state)
							cfg := testScannerConfig()
							cfg.DLP.ScanEnv = false
							cfg.AdaptiveEnforcement.Enabled = false
							cfg.Enforce = &enforce
							cfg.RequestBodyScanning.Action = action
							cfg.ResponseScanning.Action = config.ActionBlock
							if trusted {
								cfg.RequestBodyScanning.TrustedHosts = []string{"api.vendor.example"}
							}
							text := "ordinary input"
							if state == "builtin" {
								text = checkertest.Directive
							} else {
								srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, config.InjectionModeBlock)
							}
							status, hits, body := bufferedRequestDelivery(t, cfg, transport, text)
							finding := state == "builtin" || state == "finding"
							block := !finding || (enforce && (!trusted || action == config.ActionBlock)) || (transport == TransportForward && action == config.ActionBlock)
							if (status != http.StatusOK) != block || (hits == 0) != block {
								t.Fatalf("status=%d hits=%d block=%v: %s", status, hits, block, body)
							}
							calls := 1
							if state == "builtin" {
								calls = 0
							}
							if len(srv.Items()) != calls {
								t.Fatalf("checker calls=%d want=%d", len(srv.Items()), calls)
							}
						})
					}
				}
			}
		}
	}
}

func bufferedRequestDelivery(t *testing.T, cfg *config.Config, transport, text string) (int, int32, string) {
	t.Helper()
	sc, err := scanner.NewWithOptions(cfg, scanner.Options{UpstreamResolver: scanner.NewStaticOverrideResolver(map[string][]string{"api.vendor.example": {"93.184.216.34"}}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var hits atomic.Int32
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ordinary response")), Request: r}, nil
	})
	p.client.Transport = rt
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.vendor.example/notes", strings.NewReader(`{"text":"`+text+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	switch transport {
	case TransportForward:
		p.handleForwardHTTP(w, req)
	case TransportConnect:
		req.URL.Scheme, req.URL.Host = "", ""
		newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics, Proxy: p}, rt).ServeHTTP(w, req)
	case TransportReverse:
		upstream, parseErr := url.Parse("https://api.vendor.example")
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		rp := NewReverseProxy(upstream, &p.cfgPtr, &p.scannerPtr, p.logger, p.metrics, nil, nil, nil)
		rp.proxy.Transport = rt
		rp.ServeHTTP(w, req)
	}
	return w.Code, hits.Load(), w.Body.String()
}

func TestBufferedCheckerStructuredResponse(t *testing.T) {
	for _, state := range []string{"benign", "finding", "failure"} {
		t.Run(state, func(t *testing.T) {
			srv := checkertest.New(t, state)
			cfg := testScannerConfig()
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			text := "ordinary structured text"
			if state == "benign" {
				text = checkertest.Directive
			}
			body := []byte(`{"text":"` + text + `","other":"ordinary field"}`)
			view, err := extractStructuredResponse(body)
			if err != nil {
				t.Fatal(err)
			}
			view.ordinaryCap = int64(len(body))
			got := scanStructuredResponse(t.Context(), sc, cfg, body, "https://api.vendor.example", view)
			if state == "benign" && (!got.Clean || len(got.Matches) != 0) {
				t.Fatalf("basic wording ran on external structured surface: %+v", got)
			}
			if state == "finding" && !got.CheckerBlocked() {
				t.Fatalf("structured finding lost: %+v", got)
			}
			if state == "failure" && !got.Failed() {
				t.Fatalf("structured failure delivered: %+v", got)
			}
			if len(srv.Items()) != 1 || srv.Items()[0].OriginalBytes != int64(len(body)) {
				t.Fatalf("wrong item: %+v", srv.Items())
			}
		})
	}
}

func TestBufferedCheckerResponseAudit(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportConnect, TransportReverse} {
		for _, state := range []string{"finding", "failure"} {
			t.Run(transport+"/"+state, func(t *testing.T) {
				srv := checkertest.New(t, state)
				cfg := shieldRewriteMarkerConfig()
				enforce := false
				cfg.Enforce = &enforce
				cfg.BrowserShield.Enabled = false
				cfg.ResponseScanning.Action = config.ActionWarn
				srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
				status, body := requestShieldScan(t, cfg, transport, []byte("ordinary response"), "text/plain")
				if status == http.StatusOK {
					t.Fatalf("response delivered in audit mode: %s", body)
				}
				if len(srv.Items()) != 1 {
					t.Fatalf("checker calls=%d", len(srv.Items()))
				}
			})
		}
	}
}

func TestBufferedCheckerStructuredPartialCoverage(t *testing.T) {
	for _, state := range []string{"benign", "finding", "failure"} {
		t.Run(state, func(t *testing.T) {
			srv := checkertest.New(t, state)
			cfg := testScannerConfig()
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			body := []byte(`{"text":"ordinary text","omitted_number":42}`)
			view, err := extractStructuredResponse(body)
			if err != nil {
				t.Fatal(err)
			}
			view.ordinaryCap = 1
			got := scanStructuredResponse(t.Context(), sc, cfg, body, "https://api.vendor.example", view)
			if got.Clean || got.Assessment.Status == scanner.AssessmentBenign || len(srv.Items()) != 1 || srv.Items()[0].Completeness.Status != "partial" {
				t.Fatalf("partial coverage earned credit: result=%+v items=%+v", got, srv.Items())
			}
			if state == "finding" && !got.CheckerBlocked() {
				t.Fatalf("partial finding lost: %+v", got)
			}
			if state != "finding" && !got.Failed() {
				t.Fatalf("partial refusal lost: %+v", got)
			}
		})
	}
}

func TestBufferedCheckerStructuredCopyBudget(t *testing.T) {
	srv := checkertest.New(t, "benign")
	cfg := testScannerConfig()
	srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	body := []byte(`{"text":"ordinary text"}`)
	view, err := extractStructuredResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	view.ordinaryCap = int64(len(body))
	view.account = &structuredResponseAccount{budget: &sizeExemptScanBudget{}, limit: int64(len(body))}
	got := scanStructuredResponse(t.Context(), sc, cfg, body, "https://api.vendor.example", view)
	if !got.Failed() || got.ScanError != errStructuredViewBudget.Error() || len(srv.Items()) != 0 {
		t.Fatalf("unreserved checker copy admitted: result=%+v items=%+v", got, srv.Items())
	}
}

func TestBufferedCheckerRequestInvalidUTF8(t *testing.T) {
	srv := checkertest.New(t, "benign")
	cfg := testScannerConfig()
	srv.Configure(cfg, config.InjectionSurfaceHTTPRequestBody, config.InjectionModeBlock)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	text := "ordinary" + string([]byte{0xff, 0xfe}) + "request"
	forwarded, got := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(text), ContentType: "text/plain", MaxBytes: 1024, Scanner: sc, Action: config.ActionBlock})
	if !got.Clean || got.ScanError != "" || string(forwarded) != text {
		t.Fatalf("benign invalid-byte request refused or changed: %+v", got)
	}
	items := srv.Items()
	if len(items) != 1 || len(items[0].Parts) == 0 {
		t.Fatalf("checker calls=%d", len(items))
	}
	for _, part := range items[0].Parts {
		if !utf8.ValidString(part.Text) || part.Text != "ordinary request" {
			t.Fatalf("unexpected checker text %q", part.Text)
		}
	}
}
