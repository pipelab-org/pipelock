// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// rotatingStreamWriter rotates the session task inside every client write
// while armed, and signals each flush that follows a body write. A rotation
// inside the last write of an event can only be recorded by the check that
// runs after the write, because no later write of that event exists.
type rotatingStreamWriter struct {
	*httptest.ResponseRecorder
	mu      sync.Mutex
	rotate  func()
	pending bool
	flushed chan struct{}
}

func newRotatingStreamWriter() *rotatingStreamWriter {
	return &rotatingStreamWriter{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{}, 8)}
}

func (w *rotatingStreamWriter) arm(rotate func()) {
	w.mu.Lock()
	w.rotate = rotate
	w.mu.Unlock()
}

func (w *rotatingStreamWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	rotate := w.rotate
	w.pending = true
	w.mu.Unlock()
	if rotate != nil {
		rotate()
	}
	return w.ResponseRecorder.Write(data)
}

func (w *rotatingStreamWriter) Flush() {
	w.ResponseRecorder.Flush()
	w.mu.Lock()
	pending := w.pending
	w.pending = false
	w.mu.Unlock()
	if pending {
		select {
		case w.flushed <- struct{}{}:
		default:
		}
	}
}

func waitStreamFlush(t *testing.T, w *rotatingStreamWriter, done <-chan struct{}) {
	t.Helper()
	select {
	case <-w.flushed:
	case <-done:
		t.Fatal("stream ended before the event was flushed")
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not flush the event")
	}
}

// rotatingWriter rotates on every write for direct DispatchSSEScan calls.
type rotatingWriter struct {
	bytes.Buffer
	rotate func()
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.rotate()
	return w.Buffer.Write(p)
}

type countingFlusher struct{ n int }

func (f *countingFlusher) Flush() { f.n++ }

// Every scanner the dispatcher can pick writes through the delivery hook, with
// and without a flusher. The reverse path calls the dispatcher with a nil
// flusher and a pipe writer.
func TestDispatchSSEScanRecordsDeliveryAcrossTaskRotation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Taint.Enabled = true
	for _, tc := range []struct {
		name string
		opts SSEDispatchOptions
		body string
	}{
		{name: "generic", opts: SSEDispatchOptions{GenericSSE: &config.GenericSSEScanning{Enabled: true, Action: config.ActionWarn, MaxEventBytes: 1024}}, body: "data: one\n\ndata: two\n\n"},
		{name: "passthrough", opts: SSEDispatchOptions{GenericSSE: &config.GenericSSEScanning{Enabled: false}}, body: "data: one\n\ndata: two\n\n"},
		{name: "a2a", opts: SSEDispatchOptions{IsA2A: true, A2A: &config.A2AScanning{Enabled: true, Action: config.ActionWarn}}, body: "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"text\":\"one\"}}\n\n"},
	} {
		for _, withFlusher := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/flusher=%t", tc.name, withFlusher), func(t *testing.T) {
				rec := &SessionState{}
				observe := httpResponseFindingObserver(rec, cfg, "https://"+interceptTaintHost+"/stream", "text/event-stream", "forward_response")
				observe(nil)
				opts := tc.opts
				opts.OnDelivery = func() { observe(nil) }
				var rotations int
				w := &rotatingWriter{rotate: func() {
					rotations++
					rec.BeginNewTask("rotated")
				}}
				var flusher http.Flusher
				counter := &countingFlusher{}
				if withFlusher {
					flusher = counter
				}
				if err := DispatchSSEScan(t.Context(), strings.NewReader(tc.body), w, flusher, ssetestScanner(t), opts); err != nil {
					t.Fatalf("dispatch: %v", err)
				}
				if rotations == 0 || w.Len() == 0 {
					t.Fatalf("no delivery observed: rotations=%d out=%q", rotations, w.String())
				}
				if withFlusher && counter.n == 0 {
					t.Fatal("wrapped flusher did not reach the real flusher")
				}
				// The final rotation happened inside the final write.
				risk := rec.RiskSnapshot()
				if risk.Level != session.TaintExternalUntrusted || len(risk.Sources) != 1 {
					t.Fatalf("risk after rotation inside the last write=%+v, want one untrusted source", risk)
				}
			})
		}
	}
}

func TestDispatchSSEScanWithoutDeliveryHookLeavesWriterUnwrapped(t *testing.T) {
	var out bytes.Buffer
	counter := &countingFlusher{}
	err := DispatchSSEScan(t.Context(), strings.NewReader("data: one\n\n"), &out, counter, ssetestScanner(t),
		SSEDispatchOptions{GenericSSE: &config.GenericSSEScanning{Enabled: true, Action: config.ActionWarn, MaxEventBytes: 1024}})
	if err != nil || !strings.Contains(out.String(), "one") || counter.n == 0 {
		t.Fatalf("dispatch err=%v out=%q flushes=%d", err, out.String(), counter.n)
	}
}

// A task that rotates while a forward or TLS-intercepted SSE stream stays open
// must record the events delivered under the new task: both when the rotation
// lands between events and when it lands inside the write of an event.
func TestHTTPSSETaskRotationMidStream(t *testing.T) {
	for _, intercept := range []bool{false, true} {
		for _, duringWrite := range []bool{false, true} {
			name := map[bool]string{false: "forward", true: "intercept"}[intercept] + "/" + map[bool]string{false: "between_events", true: "during_write"}[duringWrite]
			t.Run(name, func(t *testing.T) {
				p, _, _, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) {
					cfg.Taint.Enabled = true
					cfg.ForwardProxy.Enabled = true
					cfg.ResponseScanning.Action = config.ActionWarn
					cfg.ResponseScanning.SSEStreaming.Enabled = true
					cfg.ResponseScanning.SSEStreaming.Action = config.ActionWarn
					cfg.DNS.HostOverrides = map[string][]string{interceptTaintHost: {"93.184.216.34"}}
				})
				rec := &SessionState{}
				WithTaintRecorder(rec)(p)
				reader, writer := io.Pipe()
				t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
				rt := forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: reader, Request: r}, nil
				})
				handler := newInterceptHandler(ic, rt)
				if !intercept {
					target = strings.Replace(target, "https://", "http://", 1)
					p.client = &http.Client{Transport: rt}
					handler = http.HandlerFunc(p.handleForwardHTTP)
				}
				stream := newRotatingStreamWriter()
				done := make(chan struct{})
				go func() {
					defer close(done)
					defer func() { _ = reader.Close() }()
					handler.ServeHTTP(stream, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
				}()
				t.Cleanup(func() {
					_ = writer.Close()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("stream handler did not finish")
					}
				})

				writeTaintStream(t, writer, "data: first\n\n")
				waitStreamFlush(t, stream, done)
				if risk := rec.RiskSnapshot(); risk.Level != session.TaintExternalUntrusted {
					t.Fatalf("first event delivered without exposure: %+v", risk)
				}
				if duringWrite {
					stream.arm(func() { rec.BeginNewTask("rotated during write") })
				} else {
					rec.BeginNewTask("rotated between events")
				}
				writeTaintStream(t, writer, "data: second\n\n")
				waitStreamFlush(t, stream, done)
				stream.arm(nil)
				select {
				case <-done:
					t.Fatal("stream unexpectedly closed")
				default:
				}
				risk := rec.RiskSnapshot()
				if risk.Level != session.TaintExternalUntrusted || len(risk.Sources) != 1 {
					t.Fatalf("event delivered after task rotation without exposure under the new task: %+v", risk)
				}
			})
		}
	}
}

// The reverse SSE scanner writes into a pipe that httputil.ReverseProxy copies
// to the client. Rotation between events and rotation inside the client write
// must both record the delivered event under the new task.
func TestReverseSSETaskRotationMidStream(t *testing.T) {
	newHarness := func(t *testing.T) (http.Handler, *Proxy, *config.Config, chan struct{}) {
		t.Helper()
		cfg := reverseParityBaseConfig(t)
		cfg.CrossRequestDetection.Enabled = false
		cfg.SessionProfiling.Enabled = true
		cfg.SessionProfiling.MaxSessions = 1000
		cfg.SessionProfiling.DomainBurst = 100
		cfg.SessionProfiling.WindowMinutes = 5
		cfg.SessionProfiling.SessionTTLMinutes = 30
		cfg.SessionProfiling.CleanupIntervalSeconds = 600
		cfg.ResponseScanning.SSEStreaming.Enabled = true
		cfg.ResponseScanning.SSEStreaming.Action = config.ActionWarn
		next := make(chan struct{})
		release := make(chan struct{})
		rp, p, _ := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			for i, event := range []string{"data: first\n\n", "data: second\n\n"} {
				if i > 0 {
					select {
					case <-next:
					case <-r.Context().Done():
						return
					}
				}
				_, _ = fmt.Fprint(w, event)
				if flusher != nil {
					flusher.Flush()
				}
			}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
		t.Cleanup(func() { close(release) })
		return rp, p, cfg, next
	}
	sessionFor := func(t *testing.T, p *Proxy, cfg *config.Config, target, clientIP string) *SessionState {
		t.Helper()
		idReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		resolved := edition.ResolveAgentIdentity(idReq, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
		sm := p.SessionMgrPtr().Load()
		if sm == nil {
			t.Fatal("session manager not initialized")
		}
		return sm.GetOrCreate(responseTaintSessionKey(nil, resolved.Name, clientIP, resolved.Auth))
	}

	t.Run("between_events", func(t *testing.T) {
		rp, p, cfg, next := newHarness(t)
		srv := newIPv4Server(t, rp)
		t.Cleanup(srv.Close)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/stream", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		lines := bufio.NewScanner(resp.Body)
		if got := readNextSSEData(t, lines); got != "first" {
			t.Fatalf("first event=%q", got)
		}
		rec := sessionFor(t, p, cfg, srv.URL+"/stream", "127.0.0.1")
		if countReverseResponseTaintSources(rec) == 0 {
			t.Fatal("first event delivered without its source")
		}
		rec.BeginNewTask("rotated between events")
		close(next)
		if got := readNextSSEData(t, lines); got != "second" {
			t.Fatalf("second event=%q", got)
		}
		if countReverseResponseTaintSources(rec) == 0 {
			t.Fatal("event delivered after task rotation without its source under the new task")
		}
	})

	t.Run("during_client_write", func(t *testing.T) {
		rp, p, cfg, next := newHarness(t)
		target := "http://api.vendor.example/stream"
		rec := sessionFor(t, p, cfg, target, "192.0.2.1")
		stream := newRotatingStreamWriter()
		ctx, cancel := context.WithCancel(t.Context())
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		req.RemoteAddr = "192.0.2.1:1234"
		done := make(chan struct{})
		go func() {
			defer close(done)
			rp.ServeHTTP(stream, req)
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("reverse stream did not finish")
			}
		})
		waitStreamFlush(t, stream, done)
		if countReverseResponseTaintSources(rec) == 0 {
			t.Fatal("first event delivered without its source")
		}
		var rotations atomic.Int32
		stream.arm(func() {
			rotations.Add(1)
			rec.BeginNewTask("rotated during client write")
		})
		close(next)
		waitStreamFlush(t, stream, done)
		stream.arm(nil)
		if rotations.Load() == 0 {
			t.Fatal("no client write was observed for the second event")
		}
		if countReverseResponseTaintSources(rec) == 0 {
			t.Fatal("event delivered across a rotation inside the client write without its source under the new task")
		}
	})
}
