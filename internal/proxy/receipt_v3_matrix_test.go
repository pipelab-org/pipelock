// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/contract/runtime/contractruntimetest"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type v3AppendFaultFile struct {
	*os.File
	writes, syncs      int
	failWrite          bool
	failAt             int
	beforeWriteFailure func()
}

func (f *v3AppendFaultFile) Write(data []byte) (int, error) {
	f.writes++
	if f.failWrite && f.writes == f.failAt {
		if f.beforeWriteFailure != nil {
			f.beforeWriteFailure()
		}
		return 0, errors.New("append failed")
	}
	return f.File.Write(data)
}

func (f *v3AppendFaultFile) Sync() error {
	f.syncs++
	if !f.failWrite && f.syncs == f.failAt {
		return errors.New("flush failed")
	}
	return f.File.Sync()
}

// The opening record succeeds. One append to that file fails, and the writer
// can publish a successor using the normal filesystem.
func v3FirstAppendFault(failWrite bool) func(string, string) (v3.StreamFile, error) {
	return v3AppendFault(2, failWrite)
}

func v3AppendFault(failAt int, failWrite bool) func(string, string) (v3.StreamFile, error) {
	first := true
	return func(dir, pattern string) (v3.StreamFile, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil || !first {
			return file, err
		}
		first = false
		return &v3AppendFaultFile{File: file, failWrite: failWrite, failAt: failAt}, nil
	}
}

func newTestV3HTTPProxy(t *testing.T, surface string, required bool, createTemp func(string, string) (v3.StreamFile, error), configure ...func(*config.Config)) (*Proxy, *v3.StreamWriter, string, []ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	keySeed := sha256.Sum256([]byte("receipt transport fixture"))
	key := ed25519.NewKeyFromSeed(keySeed[:])
	keys := []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}
	cfg := testScannerConfig()
	cfg.Internal = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.WebSocketProxy.Enabled = true
	cfg.WebSocketProxy.MaxConnectionSeconds = 10
	cfg.WebSocketProxy.IdleTimeoutSeconds = 2
	cfg.ResponseScanning.Enabled = false
	for _, apply := range configure {
		apply(cfg)
	}
	writerOpts := v3.StreamWriterOptions{
		Dir: dir, SigningKey: key, PolicyHash: v3.Digest(nil), CreateTempFile: createTemp,
		Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		Coverage: v3.Coverage{
			ReceiptsRequired: required, Surfaces: []string{surface},
			RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: v3.Digest(nil)},
		},
	}
	writer, err := v3.OpenStreamWriter(t.Context(), writerOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = writer.Close(ctx, nil)
	})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithV3ReceiptWriter(writer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, writer, dir, keys
}

func TestV3HTTPTransportParity(t *testing.T) {
	for _, surface := range []string{TransportFetch, TransportForward, TransportConnect, transportInterceptReceipt, TransportReverse, TransportWS} {
		for _, required := range []bool{false, true} {
			for _, tc := range []struct {
				name     string
				fault    func(string, string) (v3.StreamFile, error)
				released bool
				closed   bool
				blocked  bool
			}{
				{name: "ok", released: true},
				{name: "intent write failure", fault: v3FirstAppendFault(true)},
				{name: "intent flush failure", fault: v3FirstAppendFault(false)},
				{name: "writer unavailable", closed: true, released: !required},
				{name: "policy block", blocked: true},
			} {
				t.Run(fmt.Sprintf("%s/required=%t/%s", surface, required, tc.name), func(t *testing.T) {
					p, writer, dir, keys := newTestV3HTTPProxy(t, surface, required, tc.fault, func(cfg *config.Config) {
						if tc.blocked && surface != TransportReverse {
							cfg.FetchProxy.Monitoring.Blocklist = []string{testLoopbackIP}
						}
					})
					if tc.closed {
						if err := writer.Close(t.Context(), nil); err != nil {
							t.Fatal(err)
						}
					}
					var reached, intentVisible atomic.Int64
					observe := func() {
						reached.Add(1)
						result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
						if err != nil || result.Integrity != "ok" {
							return
						}
						if surface == TransportWS {
							for _, action := range readV3TransportActions(t, dir) {
								if action.Phase == "intent" && action.EffectBoundary == boundaryUpstreamSend {
									intentVisible.Add(1)
								}
							}
						} else if (result.Counts.EffectsUnknown != nil && *result.Counts.EffectsUnknown > 0) ||
							(result.Counts.EffectsCompleted != nil && *result.Counts.EffectsCompleted > 0) {
							intentVisible.Add(1)
						}
					}
					status := exerciseV3Transport(t, p, surface, v3TransportExercise{policyBlock: tc.blocked}, observe)
					if tc.released {
						want := http.StatusOK
						if surface == TransportWS {
							want = http.StatusSwitchingProtocols
						}
						expectedPrior := int64(1)
						if tc.closed {
							expectedPrior = 0
						}
						if status != want || reached.Load() != 1 || intentVisible.Load() != expectedPrior {
							t.Fatalf("status=%d upstream hits=%d with prior intent=%d, want %d/1/%d", status, reached.Load(), intentVisible.Load(), want, expectedPrior)
						}
					} else if status != http.StatusForbidden || reached.Load() != 0 {
						t.Fatalf("failed intent released an effect: status=%d upstream hits=%d", status, reached.Load())
					}
					if err := writer.Close(t.Context(), nil); err != nil {
						t.Fatal(err)
					}
					result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
					if err != nil || result.Integrity != "ok" {
						t.Fatalf("receipt verification: %+v (%v)", result, err)
					}
					if (tc.released || tc.closed || tc.blocked) && result.Verdict != "VALID" {
						t.Fatalf("verdict=%s findings=%v", result.Verdict, result.Findings)
					}
					if tc.blocked && (result.Counts.Decisions == nil ||
						!slices.Contains(*result.Counts.Decisions, v3.StateCount{State: "blocked", Count: 1})) {
						t.Fatalf("expected one policy refusal: %+v", result)
					}
					if tc.fault != nil {
						if result.Counts.Decisions == nil || !slices.Contains(*result.Counts.Decisions, v3.StateCount{State: "not_released", Count: 1}) ||
							result.Counts.EffectsCompleted == nil || *result.Counts.EffectsCompleted != 0 {
							t.Fatalf("expected one repaired refusal and zero completed effects: %+v", result)
						}
					}
					if tc.released && !tc.closed {
						assertV3TransportEffects(t, dir, surface)
					}
				})
			}
		}
	}
	t.Run("upstream_error", runV3MatrixUpstreamError)
	t.Run("cancellation", runV3MatrixCancellation)
	t.Run("delivery_uncertainty", runV3MatrixDeliveryUncertainty)
	t.Run("redirect", runV3MatrixRedirect)
	t.Run("adaptive_refusal", runV3MatrixAdaptiveRefusal)
}

type v3TransportExercise struct {
	ctx           context.Context
	policyBlock   bool
	upstreamError bool
	flushError    bool
	http2         bool
	redirect      bool
	responseBody  string
}

func exerciseV3Transport(t *testing.T, p *Proxy, surface string, exercise v3TransportExercise, observe func()) int {
	t.Helper()
	ctx := exercise.ctx
	if ctx == nil {
		ctx = t.Context()
	}
	if surface == TransportConnect {
		return exerciseV3Connect(t, p, exercise, observe)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observe()
		if exercise.redirect && r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		if exercise.upstreamError {
			if surface == TransportWS {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			panic(http.ErrAbortHandler)
		}
		if surface == TransportWS {
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set(headerContentType, "text/plain")
		_, _ = io.WriteString(w, firstNonEmptyString(exercise.responseBody, "example"))
	}))
	t.Cleanup(upstream.Close)
	response := httptest.NewRecorder()
	var downstream http.ResponseWriter = response
	if exercise.flushError {
		downstream = &v3DeliveryObserver{
			ResponseRecorder: response, beforeHeader: func() {},
			flush: func() error { return errors.New("downstream flush failed") },
		}
	}
	request := func(target string) *http.Request {
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if exercise.http2 {
			req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0
		}
		return req
	}
	switch surface {
	case TransportFetch:
		p.handleFetch(downstream, request("/fetch?url="+upstream.URL))
	case TransportForward:
		p.handleForwardHTTP(downstream, request(upstream.URL))
	case TransportReverse:
		target, err := url.Parse(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
		reverse.SetOwnerProxy(p)
		path := "/"
		// Generic reverse proxying scans the client-controlled path and query.
		// Its operator-configured destination is outside the URL blocklist.
		if exercise.policyBlock {
			path = "/?value=" + fakeAPIKey()
		}
		reverse.ServeHTTP(downstream, request(path))
	case TransportWS:
		done := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(done)
			p.handleWebSocket(w, r.WithContext(ctx))
		}))
		t.Cleanup(server.Close)
		reply := requestWSHandshake(t, strings.TrimPrefix(server.URL, "http://"), strings.TrimPrefix(upstream.URL, "http://"), nil)
		_ = reply.Body.Close()
		waitForV3Transport(t, done)
		return reply.StatusCode
	case transportInterceptReceipt:
		cache, pool, cfg, _, logger, m := testInterceptSetup(t)
		cfg.FetchProxy.Monitoring.Blocklist = p.CurrentConfig().FetchProxy.Monitoring.Blocklist
		cfg.ResponseScanning = p.CurrentConfig().ResponseScanning
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			out := req.Clone(req.Context())
			target, err := url.Parse(upstream.URL)
			if err != nil {
				return nil, err
			}
			out.URL.Scheme, out.URL.Host = target.Scheme, target.Host
			return upstream.Client().Transport.RoundTrip(out)
		})
		ic := &InterceptContext{
			Proxy: p, TargetHost: testLoopbackIP, TargetPort: "443", RequestID: "test-rt",
			Config: cfg, Scanner: sc, CertCache: cache, Logger: logger, Metrics: m, UpstreamRT: rt,
		}
		if adaptive := p.CurrentConfig().AdaptiveEnforcement; adaptive.Enabled {
			ic.Config.AdaptiveEnforcement = adaptive
			ic.Config.SessionProfiling = p.CurrentConfig().SessionProfiling
			ic.ClientIP = adaptiveSessionKeyHTTPTest
			ic.SessionMgr = p.sessionMgrPtr.Load()
			ic.Recorder = ic.SessionMgr.GetOrCreate(adaptiveSessionKeyHTTPTest)
		}
		if exercise.ctx != nil || exercise.flushError || exercise.http2 {
			// An inner HTTP cancellation can be injected without closing the
			// TLS connection and hiding the refusal from the observer.
			req := request("https://" + testLoopbackIP + "/example")
			newInterceptHandler(ic, rt).ServeHTTP(downstream, req)
			return response.Code
		}
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		tlsConn := tls.Client(clientConn, &tls.Config{RootCAs: pool, ServerName: testLoopbackIP})
		if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = interceptTunnel(t.Context(), proxyConn, ic)
		}()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://"+testLoopbackIP+"/example", nil)
		req.Close = true
		if err := req.Write(tlsConn); err != nil {
			t.Fatal(err)
		}
		reply, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		if err != nil {
			t.Fatal(err)
		}
		waitForInterceptReceipts(t, reply, clientConn, done)
		defer func() { _ = reply.Body.Close() }()
		if _, err := io.Copy(io.Discard, reply.Body); err != nil {
			t.Fatal(err)
		}
		return reply.StatusCode
	default:
		t.Fatalf("unknown surface %q", surface)
	}
	return response.Result().StatusCode
}

func exerciseV3Connect(t *testing.T, p *Proxy, exercise v3TransportExercise, observe func()) int {
	t.Helper()
	target, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if exercise.upstreamError {
		if err := target.Close(); err != nil {
			t.Fatal(err)
		}
	}
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		conn, err := target.Accept()
		if err == nil {
			defer func() { _ = conn.Close() }()
			observe()
		}
	}()
	t.Cleanup(func() {
		_ = target.Close()
		waitForV3Transport(t, accepted)
	})
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		if exercise.ctx != nil {
			r = r.WithContext(exercise.ctx)
		}
		p.handleConnect(w, r)
	}))
	t.Cleanup(server.Close)
	conn := dialProxy(t, strings.TrimPrefix(server.URL, "http://"))
	addr := target.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
		t.Fatal(err)
	}
	reply, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = reply.Body.Close()
	waitForV3Transport(t, done)
	if reply.StatusCode != http.StatusOK {
		_ = target.Close()
	}
	waitForV3Transport(t, accepted)
	return reply.StatusCode
}

func waitForV3Transport(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("transport did not settle")
	}
}

func assertV3TransportEffects(t *testing.T, dir, surface string) {
	t.Helper()
	intents := make(map[string]v3.Action)
	outcomes := make(map[string]v3.Action)
	for _, action := range readV3TransportActions(t, dir) {
		switch action.Phase {
		case "intent":
			if _, exists := intents[action.ActionID]; exists {
				t.Fatalf("duplicate intent for %s", action.ActionID)
			}
			intents[action.ActionID] = action
		case "outcome":
			intent, exists := intents[action.ActionID]
			if !exists || intent.EffectBoundary != action.EffectBoundary {
				t.Fatalf("outcome lacks a prior intent at the same boundary: %+v", action)
			}
			if _, exists := outcomes[action.ActionID]; exists {
				t.Fatalf("duplicate terminal outcome for %s", action.ActionID)
			}
			outcomes[action.ActionID] = action
		}
	}
	if len(intents) != 2 || len(outcomes) != 2 {
		t.Fatalf("expected two settled effects, got %d intents and %d outcomes", len(intents), len(outcomes))
	}
	upstreamBoundary := boundaryUpstreamSend
	if surface == TransportConnect {
		upstreamBoundary = boundaryTunnelOpen
	}
	deliveries := 0
	for _, intent := range intents {
		outcome := outcomes[intent.ActionID]
		if intent.EffectBoundary == boundaryDownstreamDelivery {
			deliveries++
			if intents[intent.ParentActionID].EffectBoundary != upstreamBoundary {
				t.Fatalf("delivery intent does not link to an upstream intent: %+v", intent)
			}
			if !slices.Contains([]string{"completed", "attempt_unknown"}, outcome.OutcomeClass) {
				t.Fatalf("unexpected delivery outcome: %+v", outcome)
			}
		} else if intent.EffectBoundary != upstreamBoundary || outcome.OutcomeClass != "completed" {
			t.Fatalf("expected completed upstream outcome: %+v", outcome)
		}
	}
	if deliveries != 1 {
		t.Fatalf("delivery intents = %d, want 1", deliveries)
	}
}

func readV3TransportActions(t *testing.T, dir string) []v3.Action {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("expected one signed stream: %v (%v)", paths, err)
	}
	return readV3TransportFile(t, paths[0])
}

func readV3TransportFile(t *testing.T, path string) []v3.Action {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var actions []v3.Action
	for line := range bytes.SplitAfterSeq(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		envelope, code := v3.ExportDSSE(line)
		if code != "" {
			t.Fatal(code)
		}
		var decoded struct{ Payload []byte }
		if err := json.Unmarshal(envelope, &decoded); err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Kind string
			Body v3.Action
		}
		if err := json.Unmarshal(decoded.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Kind == "action" {
			actions = append(actions, payload.Body)
		}
	}
	return actions
}

type v3DeliveryObserver struct {
	*httptest.ResponseRecorder
	beforeHeader func()
	flush        func() error
}

func (w *v3DeliveryObserver) WriteHeader(status int) {
	w.beforeHeader()
	w.ResponseRecorder.WriteHeader(status)
}

func (w *v3DeliveryObserver) FlushError() error {
	return w.flush()
}

func TestV3HTTPDeliveryObservations(t *testing.T) {
	flushError := errors.New("downstream flush failed")
	for _, required := range []bool{false, true} {
		for _, tc := range []struct {
			name     string
			http2    bool
			trailers bool
			flushErr error
			want     string
		}{
			{name: "framed", want: "completed"},
			{name: "flush error", flushErr: flushError, want: "attempt_unknown"},
			{name: "http2", http2: true, want: "attempt_unknown"},
			{name: "trailers", trailers: true, want: "attempt_unknown"},
		} {
			t.Run(fmt.Sprintf("required=%t/%s", required, tc.name), func(t *testing.T) {
				p, writer, dir, keys := newTestV3HTTPProxy(t, TransportForward, required, nil)
				req := httptest.NewRequestWithContext(withReceiptEvidenceContext(t.Context()), http.MethodGet, "http://api.vendor.example/example", nil)
				if tc.http2 {
					req.ProtoMajor = 2
				}
				opts := receipt.EmitOpts{
					ActionID: receipt.NewActionID(), Verdict: "allow", Transport: TransportForward,
					Method: req.Method, Target: req.URL.String(),
				}
				upstream, err := p.admitEffect(req.Context(), p.CurrentConfig(), opts, boundaryUpstreamSend)
				if err != nil {
					t.Fatal(err)
				}
				p.confirmObservedEffect(req.Context(), opts, upstream, true)
				if err := p.confirmResponseDecision(p.CurrentConfig(), receipt.EmitOpts{
					Verdict: config.ActionStrip, Layer: "media_policy", Pattern: "example rewrite",
				}, req.Context()); err != nil {
					t.Fatal(err)
				}
				checkPending := func() {
					t.Helper()
					actions := readV3TransportActions(t, dir)
					if len(actions) != 4 || actions[2].Phase != "intent" || actions[3].Phase != "intent" ||
						actions[2].EffectBoundary != boundaryDownstreamDelivery || actions[2].ParentActionID != opts.ActionID ||
						actions[3].ParentActionID != actions[2].ActionID || actions[3].Layer != "media_policy" {
						t.Fatalf("expected an unsettled delivery intent before downstream action, got %+v", actions)
					}
				}
				flushes := 0
				observer := &v3DeliveryObserver{
					ResponseRecorder: httptest.NewRecorder(),
					beforeHeader:     checkPending,
					flush: func() error {
						checkPending()
						flushes++
						return tc.flushErr
					},
				}
				w, finish := p.startReceiptDelivery(observer, req, p.CurrentConfig(), opts)
				w.Header().Set("Content-Length", "7")
				setReceiptDeliveryShield(w, &receipt.ShieldSummary{Pipeline: "html", TotalRewrites: 1})
				if tc.trailers {
					w.Header().Set("Trailer", "X-Example")
				}
				w.WriteHeader(http.StatusOK)
				if _, err := io.WriteString(w, "example"); err != nil {
					t.Fatal(err)
				}
				finish()
				if flushes != 1 || observer.Body.String() != "example" {
					t.Fatalf("downstream observed %d flushes and body %q", flushes, observer.Body)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Verdict != "VALID" {
					t.Fatalf("verification: %+v (%v)", result, err)
				}
				actions := readV3TransportActions(t, dir)
				if len(actions) != 6 || actions[0].EffectBoundary != boundaryUpstreamSend ||
					actions[1].EffectBoundary != boundaryUpstreamSend || actions[1].ActionID != actions[0].ActionID ||
					actions[1].OutcomeClass != "completed" || actions[4].EffectBoundary != boundaryDownstreamDelivery ||
					actions[4].ActionID != actions[2].ActionID || actions[4].OutcomeClass != tc.want ||
					actions[5].ActionID != actions[3].ActionID || actions[5].OutcomeClass != tc.want ||
					actions[2].Shield == nil || actions[2].Shield.TotalRewrites == nil || *actions[2].Shield.TotalRewrites != 1 {
					t.Fatalf("want one delivery outcome %q, got %+v", tc.want, actions)
				}
			})
		}
	}
}

type v3ObserverDialer struct {
	addr string
}

func (d v3ObserverDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.addr)
}

func TestV3FetchRedirectEvidence(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportFetch, required, nil)
			var hits atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hit := hits.Add(1)
				result, err := v3.VerifyPaths(r.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Counts.EffectsUnknown == nil || *result.Counts.EffectsUnknown != 1 ||
					result.Counts.EffectsCompleted == nil || *result.Counts.EffectsCompleted != hit-1 {
					t.Errorf("hop %d had no independent prior receipt: %+v (%v)", hit, result, err)
				}
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/final", http.StatusFound)
					return
				}
				_, _ = io.WriteString(w, "example")
			}))
			t.Cleanup(server.Close)
			const host = "127.0.0.1"
			const origin = "http://" + host
			p.dialer = v3ObserverDialer{addr: server.Listener.Addr().String()}
			p.ContractLoaderPtr().Store(testContractLoader(t, contractruntime.ModeLive,
				contractruntimetest.HTTPEnforceRule("initial-hop", host, "/start", http.MethodGet),
				contractruntimetest.HTTPEnforceRule("redirect-hop", host, "/final", http.MethodGet),
			))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+origin+"/start&agent=agent-a", nil)
			observer := httptest.NewRecorder()
			p.handleFetch(observer, req)
			if observer.Code != http.StatusOK || hits.Load() != 2 {
				t.Fatalf("redirect status=%d requests=%d body=%q", observer.Code, hits.Load(), observer.Body)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			actions := readV3TransportActions(t, dir)
			if len(actions) != 6 || actions[2].ParentActionID != actions[0].ActionID ||
				actions[4].ParentActionID != actions[2].ActionID ||
				actions[0].Contract == nil || actions[0].Contract.RuleID != "initial-hop" ||
				actions[2].Contract == nil || actions[2].Contract.RuleID != "redirect-hop" || actions[2].Target != receipt.SanitizeSignedTarget(origin+"/final", nil) {
				t.Fatalf("wrong redirect or delivery attribution: %+v", actions)
			}
			for i, boundary := range []string{boundaryUpstreamSend, boundaryUpstreamSend, boundaryDownstreamDelivery} {
				intent, outcome := actions[2*i], actions[2*i+1]
				if intent.Phase != "intent" || outcome.Phase != "outcome" ||
					intent.EffectBoundary != boundary || outcome.EffectBoundary != boundary ||
					intent.ActionID != outcome.ActionID || outcome.OutcomeClass != "completed" {
					t.Fatalf("unexpected receipt pair for effect %d: %+v / %+v", i, intent, outcome)
				}
			}
		})
	}
}

func TestV3AdaptiveDeliveryRefusal(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportForward, required, nil)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/example", nil)
			opts := receipt.EmitOpts{
				ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: TransportForward,
				Method: req.Method, Target: req.URL.String(),
			}
			upstream, err := p.admitEffect(req.Context(), p.CurrentConfig(), opts, boundaryUpstreamSend)
			if err != nil {
				t.Fatal(err)
			}
			p.confirmObservedEffect(req.Context(), opts, upstream, true)
			cfg := adaptiveConfigBlockAll()
			observer := httptest.NewRecorder()
			adaptive := &adaptiveRefusalWriter{
				ResponseWriter: observer, cfg: &cfg.AdaptiveEnforcement, transport: TransportForward,
				level: func() int { return 1 },
			}
			w, finish := p.startReceiptDelivery(adaptive, req, cfg, opts)
			_, err = writeSyntheticResponse(w, http.StatusOK, []byte("example content"))
			finish()
			if !errors.Is(err, errReceiptAdaptiveRefusal) || observer.Code != http.StatusForbidden ||
				observer.Header().Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) ||
				strings.Contains(observer.Body.String(), "example content") {
				t.Fatalf("adaptive response status=%d body=%q err=%v", observer.Code, observer.Body, err)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			actions := readV3TransportActions(t, dir)
			if len(actions) != 3 || actions[2].Phase != "decision" || actions[2].Verdict != config.ActionBlock ||
				actions[2].EffectBoundary != boundaryDownstreamDelivery || actions[2].ParentActionID != opts.ActionID {
				t.Fatalf("missing linked adaptive refusal: %+v", actions)
			}
		})
	}
}

func TestV3ReverseEarlyHints(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportReverse, required, nil)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Link", "</style.css>; rel=preload; as=style")
				w.WriteHeader(http.StatusEarlyHints)
				w.Header().Del("Link")
				_, _ = io.WriteString(w, "example")
			}))
			t.Cleanup(backend.Close)
			target, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}
			reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
			reverse.SetOwnerProxy(p)
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				reverse.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			hints := 0
			ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
				Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
					if code == http.StatusEarlyHints && header.Get("Link") != "" {
						hints++
					}
					return nil
				},
			})
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK || string(body) != "example" || hints != 1 {
				t.Fatalf("status=%d hints=%d body=%q read error=%v", resp.StatusCode, hints, body, err)
			}
			waitForV3Transport(t, done)
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			actions := readV3TransportActions(t, dir)
			if len(actions) != 6 || actions[1].EffectBoundary != boundaryDownstreamDelivery ||
				actions[1].Phase != "intent" || actions[2].ActionID != actions[1].ActionID ||
				actions[2].OutcomeClass != "attempt_unknown" || actions[4].ActionID == actions[1].ActionID {
				t.Fatalf("missing separate early hints outcome: %+v", actions)
			}
		})
	}
}

func TestV3ReverseEarlyHintsReceiptRefusal(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportReverse, required, v3AppendFault(3, false))
			cancelled := make(chan bool, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Link", "</style.css>; rel=preload; as=style")
				w.WriteHeader(http.StatusEarlyHints)
				select {
				case <-r.Context().Done():
					cancelled <- true
				case <-time.After(3 * time.Second):
					cancelled <- false
				}
				panic(http.ErrAbortHandler)
			}))
			t.Cleanup(backend.Close)
			target, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}
			reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
			reverse.SetOwnerProxy(p)
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				reverse.ServeHTTP(w, r)
			}))
			t.Cleanup(server.Close)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			hints := 0
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
				Got1xxResponse: func(_ int, _ textproto.MIMEHeader) error {
					hints++
					return nil
				},
			})
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var body ReverseProxyBlockResponse
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusForbidden || hints != 0 ||
				resp.Header.Get(blockreason.HeaderReason) != string(blockreason.ReceiptEmissionFailed) ||
				body.Direction != scanDirectionResponse || body.BlockReason != receiptEmissionBlockReason {
				t.Fatalf("status=%d hints=%d body=%+v", resp.StatusCode, hints, body)
			}
			select {
			case stopped := <-cancelled:
				if !stopped {
					t.Fatal("upstream did not observe cancellation")
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			waitForV3Transport(t, done)
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Integrity != "ok" || result.Completeness != "end_unproven" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			paths, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
			if err != nil || len(paths) != 2 {
				t.Fatalf("expected two streams after writer recovery: %v (%v)", paths, err)
			}
			actions := append(readV3TransportFile(t, paths[0]), readV3TransportFile(t, paths[1])...)
			assertV3BoundaryPair(t, actions, boundaryUpstreamSend, "", "attempt_unknown")
			assertV3BoundaryPair(t, actions, boundaryDownstreamDelivery, "", "not_released")
		})
	}
}

func TestV3CredentialEffectBatch(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportWS, required, nil)
			ctx := withReceiptEvidenceContext(t.Context())
			allow := scanner.CredentialAudienceAllow{
				PatternName: "example audience", Surface: "websocket_frame", Destination: "api.vendor.example",
			}
			collectReceiptCredentialEvidence(ctx, []scanner.CredentialAudienceAllow{allow, allow})
			policyHash := v3.Digest([]byte("producer decision snapshot"))
			opts := receipt.EmitOpts{
				ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: TransportWS, Method: "WS",
				Target: "wss://api.vendor.example", PolicyHash: policyHash,
			}
			token, err := p.admitEffect(ctx, p.CurrentConfig(), opts, boundaryUpstreamSend)
			if err != nil {
				t.Fatal(err)
			}
			if err := token.ConfirmDelivery(ctx, func() (bool, error) {
				actions := readV3TransportActions(t, dir)
				if len(actions) != 2 || actions[0].Phase != "intent" || actions[1].Phase != "intent" ||
					actions[1].ParentActionID != actions[0].ActionID || actions[1].Pattern != allow.PatternName ||
					actions[0].Policy.Hash != policyHash || actions[1].Policy.Hash != policyHash {
					t.Fatalf("frame lacked a primary or supporting intent before send: %+v", actions)
				}
				return true, nil
			}); err != nil {
				t.Fatal(err)
			}
			p.settleEffect(ctx, opts, token)
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil || *result.Counts.EffectsCompleted != 2 {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			actions := readV3TransportActions(t, dir)
			if len(actions) != 4 || actions[2].ActionID != actions[0].ActionID || actions[3].ActionID != actions[1].ActionID ||
				actions[2].OutcomeClass != "completed" || actions[3].OutcomeClass != "completed" {
				t.Fatalf("supporting intent did not settle with the effect: %+v", actions)
			}
		})
	}
}

func TestV3InterceptIssuerQueryBatch(t *testing.T) {
	const targetHost = "elsewhere.vendor.example"
	e := newDelegationEnv(t, func(c *config.Config) {
		c.FetchProxy.Monitoring.IssuedRedirectDelegations[0].TargetOrigins = []string{"https://" + targetHost}
		c.FlightRecorder.RequireReceipts = true
	})
	_, writer, dir, keys := newTestV3HTTPProxy(t, transportInterceptReceipt, true, nil)
	WithV3ReceiptWriter(writer)(e.p)
	rph := newReceiptProxyHelperWithMetrics(t, e.m)
	e.p.receiptEmitterPtr.Store(rph.emitter)
	exerciseJoinedViewAndDelegatedEntropy(t, e, targetHost)
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
	if err != nil || result.Verdict != "VALID" {
		t.Fatalf("verification: %+v (%v)", result, err)
	}

	actions := readV3TransportActions(t, dir)
	for i, send := range actions {
		if send.Phase != "intent" || send.EffectBoundary != boundaryUpstreamSend ||
			i+1 >= len(actions) || actions[i+1].ParentActionID != send.ActionID {
			continue
		}
		if i+6 > len(actions) {
			t.Fatal("intercept send batch is incomplete")
		}
		for offset, pattern := range []string{issuerJoinedViewReceiptKey, issuerQueryReceiptExtensionKey} {
			support := actions[i+1+offset]
			if support.Phase != "intent" || support.Pattern != pattern || support.ParentActionID != send.ActionID {
				t.Fatalf("issuer allowance did not support the intercept send: %+v", support)
			}
		}
		for offset, intent := range actions[i : i+3] {
			outcome := actions[i+3+offset]
			if outcome.ActionID != intent.ActionID || outcome.OutcomeClass != "completed" {
				t.Fatalf("intercept send batch did not settle: %+v", outcome)
			}
		}
		return
	}
	t.Fatal("intercept send lacked supporting issuer allowances")
}

func runV3MatrixUpstreamError(t *testing.T) {
	for _, surface := range []string{TransportFetch, TransportForward, TransportConnect, transportInterceptReceipt, TransportReverse, TransportWS} {
		for _, required := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/required=%t", surface, required), func(t *testing.T) {
				p, writer, dir, keys := newTestV3HTTPProxy(t, surface, required, nil)
				var reached atomic.Int64
				status := exerciseV3Transport(t, p, surface, v3TransportExercise{upstreamError: true}, func() {
					reached.Add(1)
				})
				wantStatus, wantHits := http.StatusBadGateway, int64(1)
				if surface == TransportConnect {
					wantHits = 0
				}
				if surface == TransportWS {
					// Without subprotocol negotiation the client upgrade has
					// finished before the upstream handshake is attempted.
					wantStatus = http.StatusSwitchingProtocols
				}
				if status != wantStatus || reached.Load() != wantHits {
					t.Fatalf("status=%d hits=%d, want %d/%d", status, reached.Load(), wantStatus, wantHits)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Verdict != "VALID" {
					t.Fatalf("verification: %+v (%v)", result, err)
				}
				boundary, class := boundaryUpstreamSend, "attempt_unknown"
				switch surface {
				case TransportConnect:
					boundary = boundaryTunnelOpen
				case TransportWS:
					// An HTTP rejection confirms the handshake reached the peer.
					class = "completed"
				case transportInterceptReceipt:
					// The request-write trace is proof of sending even if
					// the upstream closes before sending response headers.
					class = "completed"
				}
				assertHandshakeOutcome(t, dir, boundary, class)
			})
		}
	}
}

type v3IntentCancelFile struct {
	*os.File
	cancel context.CancelFunc
	syncs  int
}

func (f *v3IntentCancelFile) Sync() error {
	if err := f.File.Sync(); err != nil {
		return err
	}
	f.syncs++
	if f.syncs == 2 {
		f.cancel()
	}
	return nil
}

func runV3MatrixCancellation(t *testing.T) {
	for _, surface := range []string{TransportFetch, TransportForward, TransportConnect, transportInterceptReceipt, TransportReverse, TransportWS} {
		for _, required := range []bool{false, true} {
			for _, afterIntent := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/required=%t/after_intent=%t", surface, required, afterIntent), func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					var createTemp func(string, string) (v3.StreamFile, error)
					if afterIntent {
						createTemp = func(dir, pattern string) (v3.StreamFile, error) {
							f, err := os.CreateTemp(dir, pattern)
							if err != nil {
								return nil, err
							}
							return &v3IntentCancelFile{File: f, cancel: cancel}, nil
						}
					} else {
						cancel()
					}
					p, writer, dir, keys := newTestV3HTTPProxy(t, surface, required, createTemp)
					var reached atomic.Int64
					status := exerciseV3Transport(t, p, surface, v3TransportExercise{ctx: ctx}, func() {
						reached.Add(1)
					})
					if reached.Load() != 0 || status < http.StatusBadRequest || ctx.Err() == nil {
						t.Fatalf("cancelled request status=%d hits=%d context=%v", status, reached.Load(), ctx.Err())
					}
					if err := writer.Close(t.Context(), nil); err != nil {
						t.Fatal(err)
					}
					result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
					if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil || *result.Counts.EffectsCompleted != 0 ||
						result.Counts.EffectsUnknown == nil || *result.Counts.EffectsUnknown != 0 {
						t.Fatalf("verification: %+v (%v)", result, err)
					}
					recorded := result.Counts.Decisions != nil && slices.Contains(*result.Counts.Decisions, v3.StateCount{
						State: "not_released", Count: 1,
					})
					if recorded != afterIntent {
						t.Fatalf("not_released decision present=%t, want %t", recorded, afterIntent)
					}
				})
			}
		}
	}
}

func runV3MatrixDeliveryUncertainty(t *testing.T) {
	for _, surface := range []string{TransportFetch, TransportForward, TransportConnect, transportInterceptReceipt, TransportReverse, TransportWS} {
		for _, required := range []bool{false, true} {
			for _, tc := range []struct {
				name     string
				exercise v3TransportExercise
			}{
				{name: "flush error", exercise: v3TransportExercise{flushError: true}},
				{name: "http2", exercise: v3TransportExercise{http2: true}},
			} {
				t.Run(fmt.Sprintf("%s/required=%t/%s", surface, required, tc.name), func(t *testing.T) {
					if surface == TransportConnect || surface == TransportWS {
						t.Skip("raw handshake delivery has no HTTP body flush or HTTP/2 end-of-stream framing")
					}
					p, writer, dir, keys := newTestV3HTTPProxy(t, surface, required, nil)
					var reached atomic.Int64
					status := exerciseV3Transport(t, p, surface, tc.exercise, func() {
						reached.Add(1)
					})
					if reached.Load() != 1 || status != http.StatusOK {
						t.Fatalf("delivery status=%d upstream hits=%d", status, reached.Load())
					}
					if err := writer.Close(t.Context(), nil); err != nil {
						t.Fatal(err)
					}
					result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
					if err != nil || result.Verdict != "VALID" {
						t.Fatalf("verification: %+v (%v)", result, err)
					}
					assertHandshakeOutcome(t, dir, boundaryDownstreamDelivery, "attempt_unknown")
				})
			}
		}
	}
}

func TestV3ResponseBatchUnavailable(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportForward, required, nil)
			ctx := withReceiptEvidenceContext(t.Context())
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://api.vendor.example", nil)
			opts := receipt.EmitOpts{
				ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: TransportForward,
				Method: req.Method, Target: req.URL.String(),
			}
			token, err := p.admitEffect(ctx, p.CurrentConfig(), opts, boundaryUpstreamSend)
			if err != nil {
				t.Fatal(err)
			}
			p.confirmObservedEffect(ctx, opts, token, true)
			if err := p.confirmResponseDecision(p.CurrentConfig(), receipt.EmitOpts{
				Verdict: config.ActionStrip, Layer: "media_policy", Pattern: "example rewrite",
			}, ctx); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			downstream := httptest.NewRecorder()
			w, finish := p.startReceiptDelivery(downstream, req, p.CurrentConfig(), opts)
			_, err = writeSyntheticResponse(w, http.StatusOK, []byte("example payload"))
			finish()
			if required {
				if err == nil || downstream.Code != http.StatusForbidden || strings.Contains(downstream.Body.String(), "example payload") {
					t.Fatalf("required delivery released after receipt failure: status=%d err=%v", downstream.Code, err)
				}
			} else if err != nil || downstream.Code != http.StatusOK || downstream.Body.String() != "example payload" {
				t.Fatalf("optional delivery was withheld: status=%d err=%v", downstream.Code, err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			actions := readV3TransportActions(t, dir)
			if len(actions) != 2 || actions[1].EffectBoundary != boundaryUpstreamSend || actions[1].OutcomeClass != "completed" {
				t.Fatalf("failed delivery batch recorded a partial decision: %+v", actions)
			}
		})
	}
}

func TestV3ReverseSSERefusal(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportReverse, required, nil, func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.SSEStreaming.Enabled = true
				cfg.ResponseScanning.SSEStreaming.Action = config.ActionBlock
			})
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(headerContentType, "text/event-stream")
				_, _ = io.WriteString(w, fieldLimitSSEBody())
			}))
			t.Cleanup(backend.Close)
			target, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}
			reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
			reverse.SetOwnerProxy(p)
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				defer close(done)
				reverse.ServeHTTP(w, req)
			}))
			t.Cleanup(server.Close)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			waitForV3Transport(t, done)
			if !bytes.Contains(body, []byte("first-event")) || bytes.Contains(body, []byte(withheldFieldEvent)) ||
				resp.Header.Get(blockreason.HeaderRecordedReceipt) != "" {
				t.Fatalf("unexpected SSE delivery: status=%d body=%q", resp.StatusCode, body)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			actions := readV3TransportActions(t, dir)
			refusals := 0
			for _, action := range actions {
				if action.Phase == "decision" && action.Verdict == config.ActionBlock && action.EffectBoundary == boundaryDownstreamDelivery {
					refusals++
				}
			}
			if refusals != 1 {
				t.Fatalf("downstream refusals=%d, want 1", refusals)
			}
		})
	}
}

func runV3MatrixRedirect(t *testing.T) {
	for _, surface := range []string{TransportFetch, TransportForward, TransportConnect, transportInterceptReceipt, TransportReverse, TransportWS} {
		for _, required := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/required=%t", surface, required), func(t *testing.T) {
				if surface == TransportConnect || surface == TransportWS {
					t.Skip("tunnel dial and WebSocket upgrade do not deliver ordinary HTTP redirects")
				}
				p, writer, dir, keys := newTestV3HTTPProxy(t, surface, required, nil)
				var reached atomic.Int64
				status := exerciseV3Transport(t, p, surface, v3TransportExercise{redirect: true}, func() {
					reached.Add(1)
				})
				wantStatus, wantHits := http.StatusFound, int64(1)
				if surface == TransportFetch {
					wantStatus, wantHits = http.StatusOK, 2
				}
				if status != wantStatus || reached.Load() != wantHits {
					t.Fatalf("redirect status=%d upstream hits=%d, want %d/%d", status, reached.Load(), wantStatus, wantHits)
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Verdict != "VALID" {
					t.Fatalf("verification: %+v (%v)", result, err)
				}
				sends, outcomes := int64(0), int64(0)
				for _, action := range readV3TransportActions(t, dir) {
					if action.EffectBoundary == boundaryUpstreamSend && action.Phase == "intent" {
						sends++
					}
					if action.EffectBoundary == boundaryUpstreamSend && action.OutcomeClass == "completed" {
						outcomes++
					}
				}
				if sends != wantHits || outcomes != sends {
					t.Fatalf("redirect send intents=%d completed=%d, want %d", sends, outcomes, wantHits)
				}
			})
		}
	}
}

func runV3MatrixAdaptiveRefusal(t *testing.T) {
	for _, surface := range []string{TransportFetch, TransportForward, TransportConnect, transportInterceptReceipt, TransportReverse, TransportWS} {
		for _, required := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/required=%t", surface, required), func(t *testing.T) {
				settings := adaptiveConfigBlockAll()
				p, writer, dir, keys := newTestV3HTTPProxy(t, surface, required, nil, func(cfg *config.Config) {
					cfg.SessionProfiling = settings.SessionProfiling
					cfg.AdaptiveEnforcement = settings.AdaptiveEnforcement
				})
				for _, key := range []string{adaptiveSessionKeyHTTPTest, testLoopbackIP} {
					escalateRec(p.sessionMgrPtr.Load().GetOrCreate(key), 1)
				}
				var reached atomic.Int64
				status := exerciseV3Transport(t, p, surface, v3TransportExercise{}, func() { reached.Add(1) })
				if status != http.StatusForbidden || reached.Load() != 0 {
					t.Fatalf("adaptive refusal status=%d upstream hits=%d", status, reached.Load())
				}
				if err := writer.Close(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
				if err != nil || result.Verdict != "VALID" || result.Counts.Decisions == nil ||
					!slices.Contains(*result.Counts.Decisions, v3.StateCount{State: "blocked", Count: 1}) {
					t.Fatalf("expected one adaptive refusal: %+v (%v)", result, err)
				}
			})
		}
	}
}

func TestV3ReverseEnvelopeMatchesSend(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, _ := newTestV3HTTPProxy(t, TransportReverse, required, nil)
			headers := make(chan string, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				headers <- req.Header.Get(envelope.HeaderName)
				_, _ = io.WriteString(w, "example")
			}))
			t.Cleanup(backend.Close)
			target, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}
			reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
			reverse.SetOwnerProxy(p)
			var emitter atomic.Pointer[envelope.Emitter]
			emitter.Store(envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash}))
			reverse.SetEnvelopeEmitter(&emitter)
			downstream := httptest.NewRecorder()
			reverse.ServeHTTP(downstream, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
			if downstream.Code != http.StatusOK {
				t.Fatalf("reverse status=%d", downstream.Code)
			}
			var header string
			select {
			case header = <-headers:
			default:
				t.Fatal("upstream was never reached")
			}
			wire, err := envelope.Parse(header)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			actions := readV3TransportActions(t, dir)
			if len(actions) != 4 || actions[0].EffectBoundary != boundaryUpstreamSend || actions[0].ActionID != wire.ReceiptID {
				t.Fatalf("envelope action=%q does not identify the upstream intent", wire.ReceiptID)
			}
		})
	}
}

func TestV3FetchInboundCredentialIsNotSendEvidence(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			p, writer, dir, keys := newTestV3HTTPProxy(t, TransportFetch, required, nil)
			audience := credentialAudienceCarrierCases()[0]
			hits := 0
			p.client.Transport = fetchReceiptTransport{base: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				hits++
				if req.Header.Get("Authorization") != "" {
					t.Error("fetch sent an inbound-only Authorization header")
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
			})}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(audience.target), nil)
			req.Header.Set("Authorization", "Bearer "+audience.credential)
			response := httptest.NewRecorder()
			p.handleFetch(response, req)
			if response.Code != http.StatusOK || hits != 1 {
				t.Fatalf("fetch status=%d upstream hits=%d", response.Code, hits)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			for _, action := range readV3TransportActions(t, dir) {
				if action.Layer == credentialAudienceReceiptExtensionKey {
					t.Fatalf("inbound-only credential was represented as a send: %+v", action)
				}
			}
		})
	}
}

type v3DeliveryFaultObserver struct {
	*httptest.ResponseRecorder
	conn     net.Conn
	flushErr error
}

func (*v3DeliveryFaultObserver) Write([]byte) (int, error) { return 0, nil }
func (w *v3DeliveryFaultObserver) FlushError() error       { return w.flushErr }

func (w *v3DeliveryFaultObserver) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, nil, nil
}

func TestV3DeliveryWriterTransportOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, outcome string
		method        string
		exercise      func(*testing.T, *v3DeliveryWriter)
	}{
		{"short write", "attempt_unknown", http.MethodGet, func(t *testing.T, w *v3DeliveryWriter) {
			if _, err := w.Write([]byte("example")); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write error = %v", err)
			}
		}},
		{"flush error", "attempt_unknown", http.MethodGet, func(t *testing.T, w *v3DeliveryWriter) {
			w.Flush()
			if !errors.Is(w.writeErr, io.ErrClosedPipe) {
				t.Fatalf("flush error = %v", w.writeErr)
			}
		}},
		{"hijack", "attempt_unknown", http.MethodGet, func(t *testing.T, w *v3DeliveryWriter) {
			conn, _, err := w.Hijack()
			if err != nil || conn == nil {
				t.Fatalf("hijack returned %v, %v", conn, err)
			}
			if _, _, err := w.Hijack(); !errors.Is(err, http.ErrNotSupported) {
				t.Fatalf("second hijack error = %v", err)
			}
		}},
		{"head", "attempt_unknown", http.MethodHead, func(_ *testing.T, w *v3DeliveryWriter) {
			w.WriteHeader(http.StatusOK)
		}},
		{"no trailer", "completed", http.MethodGet, func(_ *testing.T, w *v3DeliveryWriter) {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
		}},
		{"trailer prefix", "attempt_unknown", http.MethodGet, func(_ *testing.T, w *v3DeliveryWriter) {
			w.Header().Set("Content-Length", "0")
			w.Header().Set(http.TrailerPrefix+"Example", "value")
			w.WriteHeader(http.StatusOK)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, writer, dir, _ := newTestV3HTTPProxy(t, TransportForward, true, nil)
			req := httptest.NewRequestWithContext(t.Context(), tc.method, "http://api.vendor.example", http.NoBody)
			opts := receipt.EmitOpts{Verdict: config.ActionAllow, Transport: TransportForward, Method: req.Method, Target: req.URL.String()}
			conn, peer := net.Pipe()
			t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
			observer := &v3DeliveryFaultObserver{ResponseRecorder: httptest.NewRecorder(), conn: conn}
			if tc.name == "flush error" || tc.name == "head" {
				observer.flushErr = io.ErrClosedPipe
			}
			w, finish := p.startReceiptDelivery(observer, req, p.CurrentConfig(), opts)
			delivery := w.(*v3DeliveryWriter)
			if delivery.Unwrap() != observer {
				t.Fatal("receipt writer did not preserve its underlying writer")
			}
			tc.exercise(t, delivery)
			finish()
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			assertHandshakeOutcome(t, dir, boundaryDownstreamDelivery, tc.outcome)
		})
	}
}

func TestV3DeliveryAdaptiveRefusalAfterIntent(t *testing.T) {
	for _, path := range []string{"final headers", "early hints", "hijack"} {
		t.Run(path, func(t *testing.T) {
			p, writer, dir, _ := newTestV3HTTPProxy(t, TransportForward, true, nil)
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://api.vendor.example", http.NoBody)
			opts := receipt.EmitOpts{Verdict: config.ActionAllow, Transport: TransportForward, Method: req.Method, Target: req.URL.String()}
			cfg := adaptiveConfigBlockAll()
			observer := httptest.NewRecorder()
			checks := 0
			adaptive := &adaptiveRefusalWriter{
				ResponseWriter: observer, cfg: &cfg.AdaptiveEnforcement, transport: TransportForward,
				level: func() int {
					checks++
					return checks - 1
				},
			}
			w, finish := p.startReceiptDelivery(adaptive, req, cfg, opts)
			delivery := w.(*v3DeliveryWriter)
			delivery.cancel = cancel
			switch path {
			case "final headers":
				delivery.WriteHeader(http.StatusOK)
			case "early hints":
				delivery.WriteHeader(http.StatusEarlyHints)
			case "hijack":
				if conn, _, err := delivery.Hijack(); conn != nil || !errors.Is(err, errReceiptAdaptiveRefusal) {
					t.Fatalf("hijack returned %v, %v", conn, err)
				}
			}
			if err := delivery.FlushError(); !errors.Is(err, errReceiptAdaptiveRefusal) {
				t.Fatalf("flush returned %v", err)
			}
			if conn, _, err := delivery.Hijack(); conn != nil || (path == "final headers" && !errors.Is(err, http.ErrNotSupported)) ||
				(path != "final headers" && !errors.Is(err, errReceiptAdaptiveRefusal)) {
				t.Fatalf("second hijack returned %v, %v", conn, err)
			}
			finish()
			if observer.Code != http.StatusForbidden || !errors.Is(context.Cause(ctx), errReceiptAdaptiveRefusal) {
				t.Fatalf("status=%d cancellation=%v", observer.Code, context.Cause(ctx))
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			assertV3BoundaryPair(t, readV3TransportActions(t, dir), boundaryDownstreamDelivery, "", "not_released")
		})
	}
}

func TestV3FetchAdmissionClosesRequestBody(t *testing.T) {
	p, writer, dir, keys := newTestV3HTTPProxy(t, TransportFetch, true, v3FirstAppendFault(true))
	body := &closeTrackingReadCloser{Reader: strings.NewReader("example")}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example", body)
	opts := receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: TransportFetch,
		Method: req.Method, Target: req.URL.String(),
	}
	req, _ = p.startFetchReceiptEffects(req, p.CurrentConfig(), opts)
	transport := fetchReceiptTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("admission refusal called the upstream transport")
		return nil, nil
	})}
	resp, err := transport.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp != nil || err == nil || !body.closed {
		t.Fatalf("admission refusal returned %v, %v, closed=%t", resp, err, body.closed)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
	if err != nil || result.Verdict != "VALID PREFIX, END UNPROVEN" {
		t.Fatalf("verification: %+v (%v)", result, err)
	}
}

func TestV3DeliveryPreservesKillSwitchRefusal(t *testing.T) {
	p, _, _, _ := newTestV3HTTPProxy(t, TransportForward, true, nil)
	cfg := adaptiveConfigBlockAll()
	recorder := httptest.NewRecorder()
	adaptive := &adaptiveRefusalWriter{
		ResponseWriter: recorder, cfg: &cfg.AdaptiveEnforcement, transport: TransportForward,
		level: func() int { return 1 },
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example", nil)
	w, finish := p.startReceiptDelivery(adaptive, req, cfg, receipt.EmitOpts{Transport: TransportForward})
	defer finish()
	w.Header().Set(blockreason.HeaderReason, string(blockreason.KillSwitchActive))
	w.WriteHeader(http.StatusServiceUnavailable)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get(blockreason.HeaderReason) != string(blockreason.KillSwitchActive) {
		t.Fatalf("kill-switch refusal replaced: status=%d headers=%v", recorder.Code, recorder.Header())
	}
}

func TestV3BufferedResponseEvidence(t *testing.T) {
	for _, tc := range []struct{ surface, action string }{
		{TransportForward, config.ActionWarn},
		{TransportReverse, config.ActionWarn},
		{transportInterceptReceipt, config.ActionWarn},
		{transportInterceptReceipt, config.ActionBlock},
	} {
		t.Run(tc.surface+"/"+tc.action, func(t *testing.T) {
			const marker = "POLICY_MARKER"
			p, writer, dir, _ := newTestV3HTTPProxy(t, tc.surface, false, nil, func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Action = tc.action
				cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response marker", Regex: marker}}
			})
			status := exerciseV3Transport(t, p, tc.surface, v3TransportExercise{ctx: t.Context(), responseBody: marker}, func() {})
			wantStatus := http.StatusOK
			if tc.action == config.ActionBlock {
				wantStatus = http.StatusForbidden
			}
			if status != wantStatus {
				t.Fatalf("status = %d, want %d", status, wantStatus)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			actions := readV3TransportActions(t, dir)
			for _, action := range actions {
				if action.Layer != responseScanLayer || action.Verdict != tc.action || action.EffectBoundary != boundaryDownstreamDelivery {
					continue
				}
				if tc.action == config.ActionBlock && action.Phase == "decision" {
					return
				}
				if tc.action == config.ActionWarn && action.Phase == "intent" {
					for _, candidate := range actions {
						if candidate.ActionID == action.ActionID && candidate.Phase == "outcome" {
							return
						}
					}
				}
			}
			t.Fatalf("missing %s delivery evidence: %+v", tc.action, actions)
		})
	}
}

func v3UnrecoverableIntentFault(beforeFailure func()) func(string, string) (v3.StreamFile, error) {
	opened := false
	return func(dir, pattern string) (v3.StreamFile, error) {
		if opened {
			return nil, errors.New("receipt stream recovery unavailable")
		}
		opened = true
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return &v3AppendFaultFile{File: file, failWrite: true, failAt: 2, beforeWriteFailure: func() {
			beforeFailure()
		}}, nil
	}
}

func TestV3OptionalForwardRechecksTaskAfterReceiptWriteError(t *testing.T) {
	const actor = "bound-worker"
	var rotate func()
	var attempted bool
	p, _, _, _ := newTestV3HTTPProxy(t, TransportForward, false, v3UnrecoverableIntentFault(func() {
		attempted = true
		rotate()
	}), func(cfg *config.Config) {
		cfg.SessionProfiling.Enabled = true
		cfg.Agents = map[string]config.AgentProfile{actor: {}}
	})
	p.approver = nil
	var upstreamCalls int
	p.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalls++
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})
	req := httptest.NewRequestWithContext(edition.WithAgentOverride(t.Context(), actor), http.MethodPost, "http://peer.vendor.example/update", nil)
	_, id := p.resolveAgentFromRequest(req)
	clientIP, _ := requestMeta(req)
	cfg := p.CurrentConfig()
	rec := p.sessionMgrPtr.Load().GetOrCreate(responseTaintSessionKey(cfg, id.Name, clientIP, id.Auth))
	observeHTTPResponseFindings(rec, cfg, "http://status.vendor.example/source", "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	rec.BindTaskSubject("forward:" + actor)
	responseencoding.RequestIdentity(req.Header)
	if err := rec.installTaskPermission(rec.TaskSnapshot().CurrentTaskID, session.TaskPermission{
		Action: forwardRequestTaskAction(req, nil), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	rotate = func() { rec.BeginNewTask("next task") }
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, req)
	if !attempted || w.Code != http.StatusForbidden || upstreamCalls != 0 || !strings.Contains(w.Body.String(), session.TaskApprovalStale) {
		t.Fatalf("write attempted=%t status=%d upstream calls=%d body=%q", attempted, w.Code, upstreamCalls, w.Body)
	}
}

func TestV3ResponseCollectors(t *testing.T) {
	for _, surface := range []string{TransportForward, TransportWS} {
		t.Run(surface, func(t *testing.T) {
			const marker = "POLICY_MARKER"
			p, _, _, _ := newTestV3HTTPProxy(t, surface, false, nil, func(cfg *config.Config) {
				cfg.BrowserShield.Enabled = true
				cfg.BrowserShield.MaxShieldBytes = 1
				cfg.BrowserShield.OversizeAction = config.ShieldOversizeWarn
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Action = config.ActionWarn
				cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response marker", Regex: marker}}
			})
			ctx := withReceiptEvidenceContext(t.Context())
			cfg := p.CurrentConfig()
			layer := responseScanLayer
			if surface == TransportWS {
				relay := &wsRelay{proxy: p, scanner: p.ScannerPtr().Load(), cfg: cfg, scanText: true, targetURL: "ws://api.vendor.example", hostname: "api.vendor.example"}
				if _, blocked := relay.enforceUpstreamTextPayload(ctx, p.logger, []byte(marker), true); blocked {
					t.Fatal("scanner blocked warning")
				}
			} else {
				layer = "shield_oversize"
				_, _, _, blocked := p.applyShieldResponse([]byte("<html>example</html>"), "text/html", make(http.Header), cfg, shieldResponseContext{
					requestContext: ctx, transport: surface, hostname: "api.vendor.example", actx: audit.NewRequestLogContext("example"),
				})
				if blocked != nil {
					t.Fatalf("shield blocked warning: %+v", blocked)
				}
			}
			actions := receiptActionBatch(ctx, cfg, receipt.EmitOpts{Transport: surface, Method: http.MethodGet}, boundaryDownstreamDelivery)
			if len(actions) != 1 || actions[0].Layer != layer {
				t.Fatalf("delivery evidence = %+v, want %s", actions, layer)
			}
		})
	}
}

func TestV3OptionalInterceptRechecksTaskAfterReceiptWriteError(t *testing.T) {
	p, _, _, target, ic := newTaintInterceptFixture(t, nil)
	shared := &SessionState{}
	shared.BeginNewTask("invocation")
	shared.BindTaskSubject("invocation")
	WithTaintRecorder(shared)(p)
	observeHTTPResponseFindings(shared, ic.Config, target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil)
	responseencoding.RequestIdentity(req.Header)
	applyFullResponsePolicy(req.Header, nil)
	if err := shared.installTaskPermission(shared.TaskSnapshot().CurrentTaskID, session.TaskPermission{
		Action: forwardRequestTaskAction(req, nil), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	attempted := false
	_, writer, _, _ := newTestV3HTTPProxy(t, transportInterceptReceipt, false, v3UnrecoverableIntentFault(func() {
		attempted = true
		shared.BeginNewTask("next task")
	}))
	WithV3ReceiptWriter(writer)(p)
	var upstreamCalls int
	handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		upstreamCalls++
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
	}))
	w := interceptTaintRequest(t, handler, http.MethodPost, target)
	if !attempted || w.Code != http.StatusForbidden || upstreamCalls != 0 || !strings.Contains(w.Body.String(), session.TaskApprovalStale) {
		t.Fatalf("write attempted=%t status=%d upstream calls=%d body=%q", attempted, w.Code, upstreamCalls, w.Body)
	}
}

func TestV3AdaptiveRefusalPrecedesReceiptFailure(t *testing.T) {
	for _, status := range []int{http.StatusEarlyHints, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			level := 0
			p, _, _, _ := newTestV3HTTPProxy(t, TransportForward, true, v3UnrecoverableIntentFault(func() { level = 1 }))
			cfg := adaptiveConfigBlockAll()
			recorder := httptest.NewRecorder()
			adaptive := &adaptiveRefusalWriter{
				ResponseWriter: recorder, cfg: &cfg.AdaptiveEnforcement, transport: TransportForward,
				level: func() int { return level },
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example", nil)
			w, finish := p.startReceiptDelivery(adaptive, req, cfg, receipt.EmitOpts{
				Verdict: config.ActionAllow, Transport: TransportForward, Method: req.Method, Target: req.URL.String(),
			})
			defer finish()
			w.WriteHeader(status)
			denied := w.(*v3DeliveryWriter).denied
			if !errors.Is(denied, errReceiptAdaptiveRefusal) || recorder.Code != http.StatusForbidden || recorder.Header().Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) {
				t.Fatalf("adaptive refusal replaced: status=%d headers=%v cause=%v", recorder.Code, recorder.Header(), denied)
			}
		})
	}
}
