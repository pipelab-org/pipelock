// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
	plwsutil "github.com/luckyPipewrench/pipelock/internal/wsutil"
)

// Compare the entire delivered header set and body, including hints and optional
// metadata. A comparison of the reason header alone misses the probing channel.
func TestAdaptiveUniformRefusalTransports(t *testing.T) {
	for _, transport := range []string{TransportForward, TransportConnect, TransportFetch, TransportWS, "intercept", TransportReverse} {
		t.Run(transport, func(t *testing.T) {
			cfg := adaptiveConfigBlockAll()
			cfg.Enforce = ptrBool(true)
			cfg.DefaultAgentIdentity = ""
			cfg.BindDefaultAgentIdentity = false
			cfg.ExplainBlocks = ptrBool(true)
			cfg.WebSocketProxy.Enabled = true
			cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.vendor.example"}
			cfg.TLSInterception.MaxResponseBytes = 1024 * 1024
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyHTTPTest)
			escalateRec(rec, 1)
			var handle http.HandlerFunc
			target := "https://api.vendor.example/ok"
			makeRequest := func(caught bool) *http.Request {
				requestURL := target
				if caught {
					requestURL += "?token=" + "gh" + "p_" + strings.Repeat("aB3c", 9)
				}
				switch transport {
				case TransportFetch:
					requestURL = "http://proxy.example/fetch?url=" + url.QueryEscape(requestURL)
				case TransportWS:
					requestURL = "http://proxy.example/ws?url=" + url.QueryEscape(strings.Replace(requestURL, "https://", "wss://", 1))
				case TransportConnect:
					host := "api.vendor.example:443"
					if caught {
						host = "blocked.vendor.example:443"
					}
					r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "https://"+host, nil)
					r.Host = host
					return r
				}
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
			}
			switch transport {
			case TransportForward:
				handle = p.handleForwardHTTP
			case TransportConnect:
				handle = p.handleConnect
			case TransportFetch:
				handle = p.handleFetch
			case TransportWS:
				handle = p.handleWebSocket
			case "intercept":
				handle = newInterceptHandler(&InterceptContext{Proxy: p, TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics, ClientIP: adaptiveSessionKeyHTTPTest, Agent: agentAnonymous, SessionMgr: p.sessionMgrPtr.Load(), Recorder: rec}, &interceptMockRT{}).ServeHTTP
			case TransportReverse:
				upstream, _ := url.Parse(target)
				rp := NewReverseProxy(upstream, p.ConfigPtr(), p.ScannerPtr(), p.logger, p.metrics, nil, nil, nil)
				rp.SetOwnerProxy(p)
				handle = rp.ServeHTTP
			}
			clean := httptest.NewRecorder()
			handle(clean, makeRequest(false))
			before := rec.ThreatScore()
			caught := httptest.NewRecorder()
			handle(caught, makeRequest(true))
			if clean.Code != http.StatusForbidden || caught.Code != clean.Code || !reflect.DeepEqual(caught.Result().Header, clean.Result().Header) || !bytes.Equal(caught.Body.Bytes(), clean.Body.Bytes()) {
				t.Fatalf("lockdown differs:\nclean %d %v %s\ncaught %d %v %s", clean.Code, clean.Result().Header, clean.Body.String(), caught.Code, caught.Result().Header, caught.Body.String())
			}
			if caught.Header().Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) {
				t.Fatalf("lockdown reason: %v", caught.Header())
			}
			if rec.ThreatScore() <= before {
				t.Errorf("scanner finding during lockdown lost its adaptive signal: before=%g after=%g events=%+v", before, rec.ThreatScore(), rec.RecentEvents())
			}
			// Clearing lockdown restores the scanner contract. The scanner's
			// one block stays below the initial escalation threshold.
			_, _ = rec.Reset(false)
			below := httptest.NewRecorder()
			handle(below, makeRequest(true))
			want := blockreason.DLPMatch
			if transport == TransportConnect {
				want = blockreason.DomainBlocklist
			}
			if below.Code != http.StatusForbidden || below.Header().Get(blockreason.HeaderReason) != string(want) {
				t.Fatalf("below lockdown: %d %v %s", below.Code, below.Header(), below.Body.String())
			}
		})
	}
}

func TestAdaptiveUniformRefusalStartsDuringRequest(t *testing.T) {
	cfg := adaptiveConfigBlockAll()
	cfg.Enforce = ptrBool(true)
	cfg.AdaptiveEnforcement.EscalationThreshold = session.SignalPoints[session.SignalBlock]
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	target := "https://api.vendor.example/ok"
	caught := httptest.NewRecorder()
	p.handleForwardHTTP(caught, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target+"?token="+"gh"+"p_"+strings.Repeat("aB3c", 9), nil))
	clean := httptest.NewRecorder()
	p.handleForwardHTTP(clean, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
	if caught.Code != http.StatusForbidden || caught.Code != clean.Code || !reflect.DeepEqual(caught.Result().Header, clean.Result().Header) || !bytes.Equal(caught.Body.Bytes(), clean.Body.Bytes()) {
		t.Fatalf("threshold-crossing refusal differs:\n%v %s\n%v %s", caught.Header(), caught.Body.String(), clean.Header(), clean.Body.String())
	}
}

func TestAdaptiveUniformRefusalKeepsScannerEvidence(t *testing.T) {
	cfg := adaptiveConfigBlockAll()
	cfg.Enforce = ptrBool(true)
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", false, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	dir := t.TempDir()
	emitter, recorder, _ := newCoverageEmitter(t, dir)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m, WithReceiptEmitter(emitter))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	escalateRec(p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyHTTPTest), 1)
	clean := httptest.NewRecorder()
	p.handleForwardHTTP(clean, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/", nil))
	target := "https://api.vendor.example/?token=" + "gh" + "p_" + strings.Repeat("aB3c", 9)
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
	if w.Code != http.StatusForbidden || w.Header().Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) {
		t.Fatalf("wire refusal: %d %v", w.Code, w.Header())
	}
	if clean.Code != w.Code || !reflect.DeepEqual(clean.Result().Header, w.Result().Header) || !bytes.Equal(clean.Body.Bytes(), w.Body.Bytes()) {
		t.Fatalf("receipt-enabled refusals differ: %v %s / %v %s", clean.Header(), clean.Body.String(), w.Header(), w.Body.String())
	}
	if !strings.Contains(logs.String(), `"scanner":"core_dlp"`) {
		t.Fatalf("scanner audit lost: %s", logs.String())
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	receipts := extractReceiptsFromDir(t, dir)
	if len(receipts) != 2 || receipts[0].ActionRecord.Layer != adaptiveSessionDeny || receipts[1].ActionRecord.Layer != scanner.ScannerCoreDLP || receipts[1].ActionRecord.Verdict != config.ActionBlock || receipts[1].ActionRecord.Pattern == "" {
		t.Fatalf("scanner receipt lost: %+v", receipts)
	}
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, family := range families {
		if family.GetName() != "pipelock_scanner_hits_total" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "scanner" && label.GetValue() == scanner.ScannerCoreDLP && metric.GetCounter().GetValue() == 1 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("scanner metric lost")
	}
}

func TestAdaptiveUniformRefusalWebSocketClose(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		t.Run(map[bool]string{false: "client", true: "upstream"}[upstream], func(t *testing.T) {
			cfg := adaptiveConfigBlockAll()
			rec := NewSessionManager(&cfg.SessionProfiling, nil, nil)
			t.Cleanup(rec.Close)
			sess := rec.GetOrCreate("websocket")
			escalateRec(sess, 1)
			r := &wsRelay{rec: sess, cfg: cfg}
			readClose := func(code ws.StatusCode, reason string, beforeRelay bool) []byte {
				a, b := net.Pipe()
				defer func() { _ = a.Close(); _ = b.Close() }()
				conn := &adaptiveCloseConn{Conn: a, level: r.escalationLevel, cfg: &cfg.AdaptiveEnforcement}
				r.clientConn, r.upstreamConn = conn, conn
				done := make(chan struct{})
				go func() {
					defer close(done)
					if beforeRelay {
						if upstream {
							plwsutil.WriteClientCloseFrame(conn, code, reason)
						} else {
							plwsutil.WriteCloseFrame(conn, code, reason)
						}
						return
					}
					if upstream {
						r.writeUpstreamClose(code, reason)
					} else {
						r.writeClientClose(code, reason)
					}
				}()
				hdr, err := ws.ReadHeader(b)
				if err != nil {
					t.Fatal(err)
				}
				payload := make([]byte, hdr.Length)
				if _, err := io.ReadFull(b, payload); err != nil {
					t.Fatal(err)
				}
				if hdr.Masked {
					ws.Cipher(payload, hdr.Mask, 0)
				}
				<-done
				return payload
			}
			cleanWire := readClose(ws.StatusPolicyViolation, adaptiveBlockedReason, false)
			caughtWire := readClose(ws.StatusInternalServerError, "upstream dial failed", true)
			if !bytes.Equal(cleanWire, caughtWire) {
				t.Fatalf("close payloads differ: %q / %q", cleanWire, caughtWire)
			}
			// The projection compares decoded close payloads; masking keys on
			// client-to-server frames are random under RFC 6455.
			cleanCode, clean := r.refusalClose(ws.StatusPolicyViolation, adaptiveBlockedReason)
			caughtCode, caught := r.refusalClose(ws.StatusPolicyViolation, "DLP violation")
			if cleanCode != caughtCode || clean != caught || strings.Contains(caught, "dlp") {
				t.Fatalf("close differs: %d %q / %d %q", cleanCode, clean, caughtCode, caught)
			}
			_, _ = sess.Reset(false)
			if belowWire := readClose(ws.StatusPolicyViolation, "DLP violation", true); !bytes.Contains(belowWire, []byte("DLP violation")) {
				t.Fatalf("early close changed below lockdown: %q", belowWire)
			}
			_, below := r.refusalClose(ws.StatusPolicyViolation, "DLP violation")
			if below != "DLP violation" {
				t.Fatal("scanner-specific close changed below lockdown")
			}
		})
	}
}

// HTTP findings escalate a destination scope, not the whole session. The
// refusal projection must resolve that scope from the same target the handler
// scores: /fetch and /ws strip control characters before parsing, so a tab in
// the target must not hide the scope from the projection.
func TestAdaptiveUniformRefusalScopedTargetParsing(t *testing.T) {
	for _, transport := range []string{TransportFetch, TransportWS} {
		t.Run(transport, func(t *testing.T) {
			cfg := adaptiveConfigBlockAll()
			cfg.Enforce = ptrBool(true)
			cfg.DefaultAgentIdentity = ""
			cfg.BindDefaultAgentIdentity = false
			cfg.ExplainBlocks = ptrBool(true)
			cfg.WebSocketProxy.Enabled = true
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			scope := adaptiveScopeForHost("api.vendor.example")
			rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyHTTPTest)
			for rec.EffectiveEscalationLevel(scope) < 1 {
				rec.RecordScopedSignal(scope, session.SignalBlock, adaptiveTestThreshold)
			}
			if rec.EffectiveEscalationLevel("") >= 1 {
				t.Fatal("fixture must escalate only the destination scope")
			}
			handle := p.handleFetch
			endpoint, scheme := "/fetch", "https://"
			if transport == TransportWS {
				handle, endpoint, scheme = p.handleWebSocket, "/ws", "wss://"
			}
			makeRequest := func(caught bool) *http.Request {
				target := scheme + "api.vendor.example/o\tk"
				if caught {
					target += "?token=" + "gh" + "p_" + strings.Repeat("aB3c", 9)
				}
				return httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example"+endpoint+"?url="+url.QueryEscape(target), nil)
			}
			clean, caught := httptest.NewRecorder(), httptest.NewRecorder()
			handle(clean, makeRequest(false))
			handle(caught, makeRequest(true))
			if caught.Header().Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) || caught.Code != clean.Code || !reflect.DeepEqual(caught.Result().Header, clean.Result().Header) || !bytes.Equal(caught.Body.Bytes(), clean.Body.Bytes()) {
				t.Fatalf("scoped lockdown differs:\nclean %d %v %s\ncaught %d %v %s", clean.Code, clean.Result().Header, clean.Body.String(), caught.Code, caught.Result().Header, caught.Body.String())
			}
		})
	}
}

func TestRefusalHostsMatchHandlerParsing(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.example/fetch?url=https://API.vendor.example/a%09b?x=1&y=2", nil)
	if got := refusalTargetHost(r); got != "API.vendor.example" {
		t.Fatalf("target host = %q", got)
	}
	for authority, want := range map[string]string{"api.vendor.example:443": "api.vendor.example", "api.vendor.example": "api.vendor.example", "[2001:db8::1]:443": "2001:db8::1", "::1": "::1", "bad:port": ""} {
		if got := refusalConnectHost(authority); got != want {
			t.Errorf("refusalConnectHost(%q) = %q, want %q", authority, got, want)
		}
	}
}
