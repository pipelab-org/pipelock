// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/shield"
)

func TestBufferedCheckerWarnCapture(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportForward, TransportConnect, TransportReverse} {
		t.Run(transport, func(t *testing.T) {
			srv := checkertest.New(t, "finding")
			cfg := shieldRewriteMarkerConfig()
			cfg.BrowserShield.Enabled = false
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionBlock
			cfg.ForwardProxy.Enabled = true
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeWarn)
			obs := newReverseDLPRecordObserver()
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ordinary upstream content")) })
			upstream := httptest.NewUnstartedServer(handler)
			if transport == TransportConnect {
				upstream.StartTLS()
			} else {
				upstream.Start()
			}
			t.Cleanup(upstream.Close)
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithCaptureObserver(obs))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
			w := httptest.NewRecorder()
			switch transport {
			case TransportFetch:
				req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.URL), nil)
				p.handleFetch(w, req)
			case TransportForward:
				p.handleForwardHTTP(w, req)
			case TransportConnect:
				cache, pool, _, _, logger, m := testInterceptSetup(t)
				resp := interceptAndRequestWithProxy(t, upstream, cache, pool, cfg, sc, logger, m, req, p)
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				w.Code = resp.StatusCode
			case TransportReverse:
				target, parseErr := url.Parse(upstream.URL)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				var cfgPtr atomic.Pointer[config.Config]
				var scPtr atomic.Pointer[scanner.Scanner]
				cfgPtr.Store(cfg)
				scPtr.Store(sc)
				reverse := NewReverseProxy(target, &cfgPtr, &scPtr, audit.NewNop(), metrics.New(), killswitch.New(cfg), obs, shield.NewEngine(nil))
				reverse.ServeHTTP(w, req)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			rec := waitReverseResponseRecord(t, obs, "response_"+map[string]string{TransportConnect: "intercept", TransportFetch: "fetch", TransportForward: "forward", TransportReverse: "reverse"}[transport])
			if rec.EffectiveAction != config.ActionWarn || rec.Outcome != capture.OutcomeWarned || len(rec.RawFindings) != 1 || len(rec.EffectiveFindings) != 1 || rec.EffectiveFindings[0].Action != config.ActionWarn || rec.EffectiveFindings[0].PatternName != "checker:fixture" {
				t.Fatalf("warning capture lost: %+v", rec)
			}
		})
	}
}
