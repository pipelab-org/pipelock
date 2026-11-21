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
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type v3AppendFaultFile struct {
	*os.File
	writes, syncs int
	failWrite     bool
}

func (f *v3AppendFaultFile) Write(data []byte) (int, error) {
	f.writes++
	if f.failWrite && f.writes == 2 {
		return 0, errors.New("append failed")
	}
	return f.File.Write(data)
}

func (f *v3AppendFaultFile) Sync() error {
	f.syncs++
	if !f.failWrite && f.syncs == 2 {
		return errors.New("flush failed")
	}
	return f.File.Sync()
}

// The opening record succeeds. One append to that file fails, and the writer
// can publish a successor using the normal filesystem.
func v3FirstAppendFault(failWrite bool) func(string, string) (v3.StreamFile, error) {
	first := true
	return func(dir, pattern string) (v3.StreamFile, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil || !first {
			return file, err
		}
		first = false
		return &v3AppendFaultFile{File: file, failWrite: failWrite}, nil
	}
}

func newTestV3HTTPProxy(t *testing.T, surface string, required bool, createTemp func(string, string) (v3.StreamFile, error)) (*Proxy, *v3.StreamWriter, string, []ed25519.PublicKey) {
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
			}{
				{name: "ok", released: true},
				{name: "intent write failure", fault: v3FirstAppendFault(true)},
				{name: "intent flush failure", fault: v3FirstAppendFault(false)},
				{name: "writer unavailable", closed: true, released: !required},
			} {
				t.Run(fmt.Sprintf("%s/required=%t/%s", surface, required, tc.name), func(t *testing.T) {
					p, writer, dir, keys := newTestV3HTTPProxy(t, surface, required, tc.fault)
					if tc.closed {
						if err := writer.Close(t.Context(), nil); err != nil {
							t.Fatal(err)
						}
					}
					var reached, intentVisible atomic.Int64
					observe := func() {
						reached.Add(1)
						result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
						if err == nil && result.Integrity == "ok" && ((result.Counts.EffectsUnknown != nil && *result.Counts.EffectsUnknown > 0) ||
							(result.Counts.EffectsCompleted != nil && *result.Counts.EffectsCompleted > 0)) {
							intentVisible.Add(1)
						}
					}
					status := exerciseV3Transport(t, p, surface, observe)
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
					if (tc.released || tc.closed) && result.Verdict != "VALID" {
						t.Fatalf("verdict=%s findings=%v", result.Verdict, result.Findings)
					}
					if tc.fault != nil {
						if result.Counts.Decisions == nil || !slices.Contains(*result.Counts.Decisions, v3.StateCount{State: "not_released", Count: 1}) ||
							result.Counts.EffectsCompleted == nil || *result.Counts.EffectsCompleted != 0 {
							t.Fatalf("expected one repaired refusal and zero completed effects: %+v", result)
						}
					}
					if tc.released && !tc.closed {
						assertV3TransportEffects(t, dir)
					}
				})
			}
		}
	}
}

func exerciseV3Transport(t *testing.T, p *Proxy, surface string, observe func()) int {
	t.Helper()
	if surface == TransportConnect {
		return exerciseV3Connect(t, p, observe)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observe()
		if surface == TransportWS {
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set(headerContentType, "text/plain")
		_, _ = io.WriteString(w, "example")
	}))
	t.Cleanup(upstream.Close)
	response := httptest.NewRecorder()
	switch surface {
	case TransportFetch:
		p.handleFetch(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+upstream.URL, nil))
	case TransportForward:
		p.handleForwardHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil))
	case TransportReverse:
		target, err := url.Parse(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		reverse := NewReverseProxy(target, p.ConfigPtr(), p.ScannerPtr(), audit.NewNop(), metrics.New(), nil, nil, nil)
		reverse.SetOwnerProxy(p)
		reverse.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	case TransportWS:
		done := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(done)
			p.handleWebSocket(w, r)
		}))
		t.Cleanup(server.Close)
		reply := requestWSHandshake(t, strings.TrimPrefix(server.URL, "http://"), strings.TrimPrefix(upstream.URL, "http://"), nil)
		_ = reply.Body.Close()
		waitForV3Transport(t, done)
		return reply.StatusCode
	case transportInterceptReceipt:
		cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
		rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			out := req.Clone(req.Context())
			target, err := url.Parse(upstream.URL)
			if err != nil {
				return nil, err
			}
			out.URL.Scheme, out.URL.Host = target.Scheme, target.Host
			return upstream.Client().Transport.RoundTrip(out)
		})
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })
		tlsConn := tls.Client(clientConn, &tls.Config{RootCAs: pool, ServerName: testLoopbackIP})
		if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = interceptTunnel(t.Context(), proxyConn, &InterceptContext{
				Proxy: p, TargetHost: testLoopbackIP, TargetPort: "443", RequestID: "test-rt",
				Config: cfg, Scanner: sc, CertCache: cache, Logger: logger, Metrics: m, UpstreamRT: rt,
			})
		}()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testLoopbackIP+"/example", nil)
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

func exerciseV3Connect(t *testing.T, p *Proxy, observe func()) int {
	t.Helper()
	target, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
	_ = target.Close()
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

func assertV3TransportEffects(t *testing.T, dir string) {
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
	for _, intent := range intents {
		outcome := outcomes[intent.ActionID]
		if intent.EffectBoundary == boundaryDownstreamDelivery {
			if _, exists := intents[intent.ParentActionID]; !exists {
				t.Fatalf("delivery intent does not link to an upstream intent: %+v", intent)
			}
			if !slices.Contains([]string{"completed", "attempt_unknown"}, outcome.OutcomeClass) {
				t.Fatalf("unexpected delivery outcome: %+v", outcome)
			}
		} else if outcome.OutcomeClass != "completed" {
			t.Fatalf("expected completed upstream outcome: %+v", outcome)
		}
	}
}

func readV3TransportActions(t *testing.T, dir string) []v3.Action {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("expected one signed stream: %v (%v)", paths, err)
	}
	data, err := os.ReadFile(filepath.Clean(paths[0]))
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
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/example", nil)
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
				checkPending := func() {
					t.Helper()
					actions := readV3TransportActions(t, dir)
					if len(actions) != 3 || actions[2].Phase != "intent" ||
						actions[2].EffectBoundary != boundaryDownstreamDelivery || actions[2].ParentActionID != opts.ActionID {
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
				if len(actions) != 4 || actions[3].ActionID != actions[2].ActionID || actions[3].OutcomeClass != tc.want {
					t.Fatalf("want one delivery outcome %q, got %+v", tc.want, actions)
				}
			})
		}
	}
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
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+server.URL+"/start", nil)
			observer := httptest.NewRecorder()
			p.handleFetch(observer, req)
			if observer.Code != http.StatusOK || hits.Load() != 2 {
				t.Fatalf("redirect status=%d requests=%d body=%q", observer.Code, hits.Load(), observer.Body)
			}
			if err := writer.Close(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			result, err := v3.VerifyPaths(t.Context(), []string{dir}, v3.Options{Directory: true, Keys: keys})
			if err != nil || result.Verdict != "VALID" || result.Counts.EffectsCompleted == nil || *result.Counts.EffectsCompleted != 3 {
				t.Fatalf("verification: %+v (%v)", result, err)
			}
			actions := readV3TransportActions(t, dir)
			if len(actions) != 6 || actions[2].ParentActionID != actions[0].ActionID ||
				actions[4].ParentActionID != actions[2].ActionID || actions[2].Target != receipt.SanitizeSignedTarget(server.URL+"/final", nil) {
				t.Fatalf("wrong redirect or delivery attribution: %+v", actions)
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
