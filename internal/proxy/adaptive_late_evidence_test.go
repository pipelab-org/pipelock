// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type adaptiveResponseObserver struct {
	capture.NopObserver
	onResponse func()
}

func (o adaptiveResponseObserver) ObserveResponseVerdict(context.Context, *capture.ResponseVerdictRecord) {
	o.onResponse()
}

func TestFetchAdaptiveResponseUsesLatestScopedEvidence(t *testing.T) {
	for _, sameScope := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_scope=%v", sameScope), func(t *testing.T) {
			cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
			cfg.Airlock.Enabled = false
			cfg.AdaptiveEnforcement.EscalationThreshold = session.SignalPoints[session.SignalBlock]
			block := config.ActionBlock
			cfg.AdaptiveEnforcement.Levels.Elevated.UpgradeWarn = &block
			cfg.ResponseScanning.Enabled = true
			cfg.ResponseScanning.Action = config.ActionWarn
			cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response_marker", Regex: "response marker"}}
			_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = fmt.Fprint(w, "response marker")
			})
			rec := p.sessionMgrPtr.Load().GetOrCreate(airlockAdmissionClient)
			scope := adaptiveScopeForHost(upstream.Hostname())
			if !sameScope {
				scope = adaptiveScopeForHost("unrelated.example")
			}
			injected := false
			p.captureObs = adaptiveResponseObserver{onResponse: func() {
				injected = true
				rec.RecordScopedSignal(scope, session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
			}}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(upstream.String()), nil)
			req.RemoteAddr = airlockAdmissionClient + ":12345"
			w := httptest.NewRecorder()
			p.handleFetch(w, req)
			want := http.StatusOK
			if sameScope {
				want = http.StatusForbidden
			}
			if !injected || w.Code != want {
				t.Fatalf("injected=%v status=%d want=%d body=%s", injected, w.Code, want, w.Body.String())
			}
			if got := rec.ThreatScore(); got != session.SignalPoints[session.SignalBlock] {
				t.Fatalf("warning changed independent evidence score: %v", got)
			}
		})
	}
}

// Independent enforced evidence may arrive after admission. A warning must
// neither create that evidence nor hide an existing block at the final gate.
func TestAdaptiveLateEvidenceStillDenies(t *testing.T) {
	for _, finding := range []string{"header", "cee"} {
		for _, transport := range []string{TransportFetch, TransportForward, TransportWS, TransportConnect, "connect_admission"} {
			if finding == "header" && (transport == TransportConnect || transport == "connect_admission") {
				continue // TLS interception below exercises its inner HTTP request.
			}
			t.Run(finding+"/"+transport, func(t *testing.T) {
				cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
				cfg.Airlock.Enabled = false
				cfg.WebSocketProxy.Enabled = true
				cfg.TLSInterception.MaxResponseBytes = 1024 * 1024
				cfg.AdaptiveEnforcement.EscalationThreshold = session.SignalPoints[session.SignalBlock]
				cfg.AdaptiveEnforcement.Levels.Elevated.BlockAll = boolPtr(true)
				if finding == "cee" {
					cfg.CrossRequestDetection.Enabled = true
					cfg.CrossRequestDetection.EntropyBudget.Enabled = true
					cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 1 // Existing CEE boundary fixture.
					cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionWarn
				}
				var calls atomic.Int32
				_, p, upstream := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					_, _ = fmt.Fprint(w, "upstream-control")
				})
				rec := p.sessionMgrPtr.Load().GetOrCreate(airlockAdmissionClient)
				var injected atomic.Bool
				logger, err := audit.NewWithStream("json", "stdout", "", true, true, airlockLogCallback(func(record []byte) {
					matches := bytes.Contains(record, []byte(`"event":"header_dlp"`)) || (bytes.Contains(record, []byte(`"event":"anomaly"`)) && bytes.Contains(record, []byte(`"scanner":"dlp"`)))
					if finding == "cee" {
						matches = bytes.Contains(record, []byte(`"scanner":"cross_request_entropy"`))
					}
					if matches && injected.CompareAndSwap(false, true) {
						rec.RecordSignal(session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
					}
				}))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				p.logger = logger
				if finding == "cee" {
					inject := func() {
						if injected.CompareAndSwap(false, true) {
							rec.RecordSignal(session.SignalBlock, cfg.AdaptiveEnforcement.EscalationThreshold)
						}
					}
					switch transport {
					case TransportWS:
						p.ceeAdmissionLocked = inject
					case "connect_admission":
						p.connectCEEReady = inject
					}
				}
				target := upstream.String() + "/control?value=abc123def456"
				switch transport {
				case TransportFetch:
					target = "http://proxy.example/fetch?url=" + url.QueryEscape(target)
				case TransportWS:
					target = "http://proxy.example/ws?url=" + url.QueryEscape(strings.Replace(target, "http://", "ws://", 1))
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
				req.RemoteAddr = airlockAdmissionClient + ":12345"
				if finding == "header" {
					req.Header.Set("Authorization", "Bearer "+airlockHeaderMarker)
				}
				w := httptest.NewRecorder()
				switch transport {
				case TransportFetch:
					p.handleFetch(w, req)
				case TransportForward:
					p.handleForwardHTTP(w, req)
				case TransportWS:
					p.handleWebSocket(w, req)
				case "connect_admission":
					req.Method = http.MethodConnect
					req.Host = upstream.Host
					p.handleConnect(w, req)
				case TransportConnect:
					handler := newInterceptHandler(&InterceptContext{
						TargetHost: upstream.Hostname(), TargetPort: upstream.Port(), Config: cfg,
						Scanner: p.scannerPtr.Load(), Logger: logger, Metrics: p.metrics,
						ClientIP: airlockAdmissionClient, Proxy: p, Recorder: rec,
					}, &interceptMockRT{body: "unexpected upstream", contentType: "text/plain"})
					handler.ServeHTTP(w, req)
				}
				if !injected.Load() || w.Code != http.StatusForbidden || calls.Load() != 0 {
					t.Fatalf("late evidence bypassed final admission: injected=%v status=%d calls=%d body=%s", injected.Load(), w.Code, calls.Load(), w.Body.String())
				}
				caller := w.Body.String() + w.Header().Get(headerAdaptiveDetail)
				if !strings.Contains(caller, "recovery:") || !strings.Contains(caller, "category=") {
					t.Fatalf("late denial omitted recovery guidance: body=%s headers=%v", w.Body.String(), w.Header())
				}
				for _, forbidden := range []string{"score=", "threshold=", "level=", "minutes=", "seconds=", "decay="} {
					if strings.Contains(caller, forbidden) {
						t.Errorf("late denial exposes %s: %s", forbidden, caller)
					}
				}
			})
		}
	}
}
