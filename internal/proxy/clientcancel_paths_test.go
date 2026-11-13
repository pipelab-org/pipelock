// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// cancelThenFailRead ends the request context and then fails the read, the
// way a body read fails once its client has gone.
type cancelThenFailRead struct{ cancel context.CancelFunc }

func (r cancelThenFailRead) Read([]byte) (int, error) {
	r.cancel()
	return 0, context.Canceled
}

func TestBodyReadErrorAfterCancel(t *testing.T) {
	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()
	for _, clientGone := range []bool{true, false} {
		ctx, cancel := scanStopContext(t, clientGone)
		body, result := scanRequestBody(ctx, BodyScanRequest{
			Body: cancelThenFailRead{cancel: cancel}, ContentType: contentTypeJSON, MaxBytes: 1024, Scanner: sc, Action: config.ActionWarn,
		})
		if body != nil || result.Clean || result.Action != config.ActionBlock || result.Reason == "" {
			t.Fatalf("client_gone=%t: failed read not refused: %+v", clientGone, result)
		}
		if got := clientCanceledIncompleteBody(ctx, result); got != clientGone {
			t.Fatalf("client_gone=%t: classified as cancellation=%t: %+v", clientGone, got, result)
		}
	}
}

// A header scan that already matched a secret keeps the match when the
// context ends before the scan returns, and becomes a block under warn.
func TestCanceledHeaderScanKeepsFinding(t *testing.T) {
	cfg := testScannerConfig()
	cfg.Enforce = new(false)
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
	cfg.RequestBodyScanning.Action = config.ActionWarn
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	headers := http.Header{"X-Fixture": {fakeNonCoreAPIKey()}}
	kept := false
	for checkpoint := int32(1); checkpoint <= 128; checkpoint++ {
		base, cancel := context.WithCancel(t.Context())
		ctx := &bodyScanCheckpointContext{Context: base, cancel: cancel, after: checkpoint}
		result := scanRequestHeaders(ctx, headers, cfg, sc)
		finished := base.Err() == nil
		cancel()
		if finished {
			if result == nil || len(result.DLPMatches) == 0 {
				t.Fatalf("fixture must match: %+v", result)
			}
			break
		}
		if result == nil || result.Clean || result.Action != config.ActionBlock || result.ScanError == "" {
			t.Fatalf("checkpoint %d: unfinished header scan not failed closed: %+v", checkpoint, result)
		}
		if len(result.DLPMatches) > 0 {
			kept = true
			if action, _ := headerDLPDecision(result, cfg); action != config.ActionBlock {
				t.Fatalf("checkpoint %d: kept finding decided %q, want block", checkpoint, action)
			}
		}
	}
	if !kept {
		t.Fatal("no checkpoint stopped after the header scan had matched")
	}
}

func TestRefuseTextDLPScanErrorForContext(t *testing.T) {
	logger, logs := newCancelAuditLogger(t)
	if w := httptest.NewRecorder(); refuseTextDLPScanErrorForContext(t.Context(), w, logger, audit.LogContext{}, "complete", nil) || w.Body.Len() != 0 {
		t.Fatal("a complete scan was refused")
	}
	for _, clientGone := range []bool{true, false} {
		ctx, cancel := scanStopContext(t, clientGone)
		cancel()
		logs.Reset()
		w := httptest.NewRecorder()
		if !refuseTextDLPScanErrorForContext(ctx, w, logger, audit.LogContext{}, "incomplete", scanner.ErrTextDLPIncomplete) || w.Code != http.StatusServiceUnavailable {
			t.Fatalf("client_gone=%t: not refused: status=%d", clientGone, w.Code)
		}
		canceled := countAuditEvent(logs.String(), "request_canceled") == 1
		blocked := w.Header().Get("X-Pipelock-Block-Reason") != ""
		if canceled != clientGone || blocked == clientGone {
			t.Fatalf("client_gone=%t: canceled=%t blocked=%t logs=%s", clientGone, canceled, blocked, logs.String())
		}
	}
}

func TestLogRequestCanceledDefaults(t *testing.T) {
	logRequestCanceled(nil, audit.LogContext{}, "ignored")
	logger, logs := newCancelAuditLogger(t)
	logRequestCanceled(logger, audit.LogContext{}, "")
	if !strings.Contains(logs.String(), `"reason":"`+context.Canceled.Error()+`"`) {
		t.Fatalf("empty reason not defaulted: %s", logs.String())
	}
}

// A client that goes away during the TLS handshake of an intercepted tunnel
// is a cancellation. A handshake that fails with the client still there is
// still recorded as a block.
func TestInterceptHandshakeCancelIsNotABlock(t *testing.T) {
	for _, clientGone := range []bool{true, false} {
		cache, _, cfg, sc, _, m := testInterceptSetup(t)
		logger, logs := newCancelAuditLogger(t)
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		ctx := t.Context()
		if clientGone {
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			ctx = canceled
		} else {
			// The write completes only once the handshake reads it.
			go func() {
				_, _ = clientConn.Write([]byte("not a TLS record\r\n\r\n"))
				_ = clientConn.Close()
			}()
		}
		err := interceptTunnel(ctx, proxyConn, &InterceptContext{
			TargetHost: testLoopbackIP, TargetPort: "443", Config: cfg, Scanner: sc, CertCache: cache,
			Logger: logger, Metrics: m, ClientIP: "192.0.2.1", RequestID: "handshake-cancel",
		})
		if err == nil || !strings.Contains(err.Error(), "TLS handshake") {
			t.Fatalf("client_gone=%t: err=%v, want a TLS handshake failure", clientGone, err)
		}
		canceled := countAuditEvent(logs.String(), "request_canceled")
		blocked := countAuditEvent(logs.String(), "blocked")
		if clientGone && (canceled != 1 || blocked != 0) || !clientGone && (canceled != 0 || blocked != 1) {
			t.Fatalf("client_gone=%t: canceled=%d blocked=%d logs=%s", clientGone, canceled, blocked, logs.String())
		}
	}
}

// The submit profile scans the upstream URL before anything else. A client
// that goes away during that scan is a cancellation and is never forwarded.
func TestSubmitProfileCanceledURLScanIsNotABlock(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer upstream.Close()
	cfg, upstreamURL := submitProfileTestConfig(upstream.URL)
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)
	logger, logs := newCancelAuditLogger(t)
	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, metrics.New(), killswitch.New(cfg), nil, nil)

	target := (&url.URL{Scheme: "http", Host: "proxy.vendor.example", Path: "/v1/batch"}).String()
	// The handler derives its own deadline context, so the request context
	// is ended before the call rather than at a counted check.
	base, cancel := context.WithCancel(t.Context())
	cancel()
	req := httptest.NewRequestWithContext(base, http.MethodPost, target, strings.NewReader(`{"ordinary":"text"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if hits.Load() != 0 {
		t.Fatalf("canceled request reached upstream %d times", hits.Load())
	}
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), clientCanceledStatusText) || w.Header().Get("X-Pipelock-Block-Reason") != "" {
		t.Fatalf("status=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
	}
	if countAuditEvent(logs.String(), "request_canceled") != 1 || countAuditEvent(logs.String(), "blocked") != 0 {
		t.Fatalf("logs=%s", logs.String())
	}
}
