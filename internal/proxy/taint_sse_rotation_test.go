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
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// rotatingStreamWriter rotates the session task inside every client write
// while armed, and signals the flush that completes an event. A rotation
// inside the last write of an event can only be recorded by the check that
// runs after the write, because no later write of that event exists. An event
// can reach the client in several writes, each flushed, so only a flush after
// the blank line that ends the event signals; an earlier flush would leave a
// stale signal that a later wait takes for the next event.
type rotatingStreamWriter struct {
	*httptest.ResponseRecorder
	mu      sync.Mutex
	rotate  func()
	pending bool
	tail    []byte
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
	w.tail = append(w.tail, data...)
	if len(w.tail) > 2 {
		w.tail = w.tail[len(w.tail)-2:]
	}
	w.mu.Unlock()
	if rotate != nil {
		rotate()
	}
	return w.ResponseRecorder.Write(data)
}

func (w *rotatingStreamWriter) Flush() {
	w.ResponseRecorder.Flush()
	w.mu.Lock()
	complete := w.pending && bytes.Equal(w.tail, []byte("\n\n"))
	if complete {
		w.pending = false
	}
	w.mu.Unlock()
	if complete {
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
	case <-time.After(testwait.Deadline(5 * time.Second)):
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

type callbackFlusher struct {
	http.ResponseWriter
	onFlush func()
}

func (f callbackFlusher) Flush() { f.onFlush() }

func TestSSEDeliveryBracketsFlush(t *testing.T) {
	for _, name := range []string{"forward_and_intercept", "reverse"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			observe := func() { calls++ }
			flushed := false
			flusher := callbackFlusher{ResponseWriter: httptest.NewRecorder(), onFlush: func() {
				flushed = true
				if calls != 1 {
					t.Errorf("observations before underlying flush = %d, want 1", calls)
				}
			}}
			if name == "reverse" {
				w := &reverseInformationalGuardWriter{ResponseWriter: flusher, delivery: &reverseDeliveryObserver{observe: observe}}
				if err := w.FlushError(); err != nil {
					t.Fatal(err)
				}
			} else {
				sseDeliveryFlusher{f: flusher, observe: observe}.Flush()
			}
			if !flushed || calls != 2 {
				t.Fatalf("flushed = %t, observations = %d, want true and 2", flushed, calls)
			}
		})
	}
}

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
				observe, _ := httpResponseFindingObserver(rec, cfg, "https://"+interceptTaintHost+"/stream", "text/event-stream", "forward_response")
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
					case <-time.After(testwait.Deadline(5 * time.Second)):
						t.Error("stream handler did not finish")
					}
				})

				writeTaintStream(t, writer, "data: first\n\n")
				waitStreamFlush(t, stream, done)
				if risk := rec.RiskSnapshot(); risk.Level != session.TaintExternalUntrusted {
					t.Fatalf("first event delivered without exposure: %+v", risk)
				}
				var clearedAtRotation atomic.Int32
				if duringWrite {
					stream.arm(func() {
						rec.BeginNewTask("rotated during write")
						// No observer call runs between the rotation and this
						// read: only the session's held exposure can supply it.
						if rec.RiskSnapshot().Level != session.TaintExternalUntrusted {
							clearedAtRotation.Add(1)
						}
					})
				} else {
					rec.BeginNewTask("rotated between events")
				}
				writeTaintStream(t, writer, "data: second\n\n")
				waitStreamFlush(t, stream, done)
				stream.arm(nil)
				if n := clearedAtRotation.Load(); n != 0 {
					t.Fatalf("%d rotations inside a client write left the new task without the open stream's exposure", n)
				}
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
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Error("reverse stream did not finish")
			}
		})
		waitStreamFlush(t, stream, done)
		if countReverseResponseTaintSources(rec) == 0 {
			t.Fatal("first event delivered without its source")
		}
		var rotations, clearedAtRotation atomic.Int32
		stream.arm(func() {
			rotations.Add(1)
			rec.BeginNewTask("rotated during client write")
			if countReverseResponseTaintSources(rec) == 0 {
				clearedAtRotation.Add(1)
			}
		})
		close(next)
		waitStreamFlush(t, stream, done)
		stream.arm(nil)
		if rotations.Load() == 0 {
			t.Fatal("no client write was observed for the second event")
		}
		if n := clearedAtRotation.Load(); n != 0 {
			t.Fatalf("%d rotations inside a client write left the new task without the open stream's source", n)
		}
		if countReverseResponseTaintSources(rec) == 0 {
			t.Fatal("event delivered across a rotation inside the client write without its source under the new task")
		}
	})
}

// A response still being delivered holds its exposure in the session: a task
// rotation re-applies it under the lock that clears risk, so no snapshot taken
// right after the rotation sees a new task without it. Release ends the hold.
func TestResponseExposureHeldAcrossTaskRotation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Taint.Enabled = true
	rec := &SessionState{}
	observe, release := httpResponseFindingObserver(rec, cfg, "https://"+interceptTaintHost+"/stream", "text/event-stream", "forward_response")
	observe(nil)
	observe([]session.HostileFindingKind{session.FindingDLP})

	rec.BeginNewTask("rotated while delivering")
	if risk := rec.RiskSnapshot(); risk.Level != session.TaintExternalHostile || len(risk.Sources) != 1 {
		t.Fatalf("risk right after rotation=%+v, want the held hostile exposure", risk)
	}
	// Repeat observations of an unchanged response do not add sources.
	observe(nil)
	if got := len(rec.RiskSnapshot().Sources); got != 1 {
		t.Fatalf("sources after repeat observation=%d want 1", got)
	}

	release()
	release() // idempotent
	rec.mu.Lock()
	held := len(rec.heldExposure)
	rec.mu.Unlock()
	if held != 0 {
		t.Fatalf("held exposures after release=%d", held)
	}
	rec.BeginNewTask("after delivery")
	if risk := rec.RiskSnapshot(); risk.Level != session.TaintTrusted || len(risk.Sources) != 0 {
		t.Fatalf("risk after rotation past delivery=%+v, want cleared", risk)
	}
	// A late observation after release records without holding again.
	observe([]session.HostileFindingKind{session.FindingDLP})
	rec.mu.Lock()
	held = len(rec.heldExposure)
	rec.mu.Unlock()
	if held != 0 || rec.RiskSnapshot().Level != session.TaintExternalHostile {
		t.Fatalf("late observation held=%d risk=%+v", held, rec.RiskSnapshot())
	}
}

// A session that holds a delivering response's exposure is not evicted, by
// idle cleanup or under capacity pressure; otherwise the next request would
// start from a clean session while the stream keeps writing to the old one.
func TestSessionWithHeldExposureIsNotEvicted(t *testing.T) {
	cfg := testSessionConfig()
	cfg.SessionTTLMinutes = 1
	cfg.MaxSessions = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()
	sess := sm.GetOrCreate(testClientIP)
	pcfg := config.Defaults()
	pcfg.Taint.Enabled = true
	pcfg.Taint.AllowlistedDomains = []string{interceptTaintHost}
	observe, release := httpResponseFindingObserver(sess, pcfg, "https://"+interceptTaintHost+"/stream", "text/event-stream", "forward_response")
	defer release()
	observe(nil)
	sess.mu.Lock()
	sess.lastActivity = time.Now().Add(-time.Hour)
	sess.mu.Unlock()
	if got := sm.GetOrCreate("new-session"); got != nil {
		t.Fatal("admitted a new session at capacity while the existing session held exposure")
	}
	sm.cleanup()
	if got := sm.SessionByKey(testClientIP); got != sess {
		t.Fatal("idle cleanup evicted a session holding a delivering response's exposure")
	}
	release()
	sess.mu.Lock()
	sess.lastActivity = time.Now().Add(-time.Hour)
	sess.mu.Unlock()
	sm.cleanup()
	if got := sm.SessionByKey(testClientIP); got != nil {
		t.Fatal("idle session not evicted after delivery ended")
	}
	if got := sm.GetOrCreate("new-session"); got == nil {
		t.Fatal("new session still refused after delivery released capacity")
	}
}

// Idle cleanup decides eligibility and removes the session in one critical
// section, so a response cannot take its first exposure hold in between: the
// hold would then protect a session cleanup is about to discard.
func TestIdleCleanupDecidesAndRemovesUnderSessionLock(t *testing.T) {
	cfg := testSessionConfig()
	cfg.SessionTTLMinutes = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()
	sess := sm.GetOrCreate(testClientIP)
	sess.mu.Lock()
	sess.lastActivity = time.Now().Add(-time.Hour)
	sess.mu.Unlock()
	var checked bool
	var lockFree bool
	sm.beforeIdleRemoval = func(candidate *SessionState) {
		checked = true
		if candidate.mu.TryLock() {
			lockFree = true
			candidate.mu.Unlock()
		}
	}
	sm.cleanup()
	if !checked {
		t.Fatal("idle cleanup did not reach removal for an idle session")
	}
	if lockFree {
		t.Fatal("idle cleanup released the session lock between its eligibility decision and removal")
	}
	if got := sm.SessionByKey(testClientIP); got != nil {
		t.Fatal("idle session was not removed")
	}
}

// The reverse delivery slot releases a hold immediately when there is no slot
// or delivery already finished, and runs every armed release exactly once.
func TestReverseDeliveryObserverLifecycle(t *testing.T) {
	var released atomic.Int32
	release := func() { released.Add(1) }

	var none *reverseDeliveryObserver
	none.arm(func() { t.Error("nil slot ran an observer") }, release)
	none.arm(nil, nil)
	none.call()
	if released.Load() != 1 {
		t.Fatalf("nil slot releases=%d want 1", released.Load())
	}
	if reverseDeliveryFrom(t.Context()) != nil {
		t.Fatal("context without a slot returned one")
	}

	d := &reverseDeliveryObserver{}
	var observed atomic.Int32
	d.call() // no observer armed yet
	d.arm(func() { observed.Add(1) }, release)
	d.arm(nil, release) // a second release, observer kept
	d.call()
	if observed.Load() != 1 || released.Load() != 1 {
		t.Fatalf("before finish observed=%d released=%d", observed.Load(), released.Load())
	}
	d.finish()
	if released.Load() != 3 {
		t.Fatalf("finish releases=%d want 3", released.Load())
	}
	d.finish() // idempotent
	d.arm(func() { t.Error("finished slot armed an observer") }, release)
	d.call()
	if observed.Load() != 1 {
		t.Fatalf("observer after finish ran: observed=%d", observed.Load())
	}
	if released.Load() != 4 {
		t.Fatalf("arm after finish releases=%d want 4", released.Load())
	}
}

// holdAtFlushWriter records, for every flush, whether the response's exposure
// was still held at that flush, and whether a write is still unflushed.
type holdAtFlushWriter struct {
	*httptest.ResponseRecorder
	rec         *SessionState
	unflushed   bool
	heldAtFlush []int
}

func (w *holdAtFlushWriter) Write(p []byte) (int, error) {
	w.unflushed = true
	return w.ResponseRecorder.Write(p)
}

// Every flush is sampled, so the last outcome flush is checked even when an
// earlier flush already followed the last write.
func (w *holdAtFlushWriter) Flush() {
	w.rec.mu.Lock()
	w.heldAtFlush = append(w.heldAtFlush, len(w.rec.heldExposure))
	w.rec.mu.Unlock()
	w.unflushed = false
	w.ResponseRecorder.Flush()
}

// With receipts required, a buffered response is flushed to the client by the
// outcome path after the handler body. Its exposure must still be held at that
// flush on forward, TLS-intercepted, /fetch and reverse paths, and released
// once the handler returns.
func TestResponseExposureHeldThroughOutcomeFlush(t *testing.T) {
	check := func(t *testing.T, w *holdAtFlushWriter) {
		t.Helper()
		if w.Code != http.StatusOK || w.Body.Len() == 0 {
			t.Fatalf("status=%d body=%q", w.Code, w.Body)
		}
		if w.unflushed || len(w.heldAtFlush) == 0 {
			t.Fatalf("response not flushed after its last write: unflushed=%v flushes=%v", w.unflushed, w.heldAtFlush)
		}
		if last := w.heldAtFlush[len(w.heldAtFlush)-1]; last == 0 {
			t.Fatalf("outcome flush ran after the exposure hold was released: %v", w.heldAtFlush)
		}
		w.rec.mu.Lock()
		held := len(w.rec.heldExposure)
		w.rec.mu.Unlock()
		if held != 0 {
			t.Fatalf("hold not released after the handler returned: %d", held)
		}
	}
	const host = "api.vendor.example"
	for _, surface := range []string{"forward", "intercept", "fetch"} {
		t.Run(surface, func(t *testing.T) {
			_, _, cfg, _, logger, m := testInterceptSetup(t)
			cfg.Taint.Enabled = true
			cfg.ForwardProxy.Enabled = true
			cfg.FlightRecorder.RequireReceipts = true
			cfg.DNS.HostOverrides = map[string][]string{host: {"93.184.216.34"}}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			rph := newReceiptProxyHelper(t)
			t.Cleanup(func() { _ = rph.rec.Close() })
			p, err := New(cfg, logger, sc, m, WithReceiptEmitter(rph.emitter))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			rec := &SessionState{}
			WithTaintRecorder(rec)(p)
			rt := forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("reference material")), Request: r}, nil
			})
			var handler http.Handler
			requestURL := "http://" + host + "/data"
			switch surface {
			case "intercept":
				handler = newInterceptHandler(&InterceptContext{Config: cfg, Scanner: sc, Logger: logger, Metrics: m, TargetHost: host, TargetPort: "443", ClientIP: testLoopbackIP, Proxy: p}, rt)
				requestURL = "https://" + host + "/data"
			case "fetch":
				p.client = &http.Client{Transport: rt}
				handler = http.HandlerFunc(p.handleFetch)
				requestURL = "/fetch?url=" + requestURL
			default:
				p.client = &http.Client{Transport: rt}
				handler = http.HandlerFunc(p.handleForwardHTTP)
			}
			w := &holdAtFlushWriter{ResponseRecorder: httptest.NewRecorder(), rec: rec}
			handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil))
			check(t, w)
		})
	}
	t.Run("reverse", func(t *testing.T) {
		cfg := reverseParityBaseConfig(t)
		cfg.CrossRequestDetection.Enabled = false
		cfg.SessionProfiling.Enabled = true
		cfg.FlightRecorder.RequireReceipts = true
		rp, p, _, _, closeRecorder, _ := newReverseParityHarnessWithReceipts(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "reference material")
		})
		t.Cleanup(closeRecorder)
		target := "http://" + host + "/page"
		idReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		resolved := edition.ResolveAgentIdentity(idReq, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
		rec := p.SessionMgrPtr().Load().GetOrCreate(responseTaintSessionKey(nil, resolved.Name, "192.0.2.1", resolved.Auth))
		w := &holdAtFlushWriter{ResponseRecorder: httptest.NewRecorder(), rec: rec}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		req.RemoteAddr = "192.0.2.1:1234"
		rp.ServeHTTP(w, req)
		check(t, w)
	})
}

// Rotation replays held responses in the order the session recorded them, so
// the most recent source stays the last external source after the rotation.
func TestHeldExposureReplaysInRecordedOrder(t *testing.T) {
	cfg := config.Defaults()
	cfg.Taint.Enabled = true
	cfg.Taint.RecentSources = 1
	for i := range 20 {
		rec := &SessionState{}
		var urls []string
		for j := range 4 {
			u := fmt.Sprintf("https://source-%d.vendor.example/page", j)
			urls = append(urls, u)
			observe, _ := httpResponseFindingObserver(rec, cfg, u, "text/html", "forward_response")
			observe(nil)
		}
		rec.BeginNewTask("rotated")
		risk := rec.RiskSnapshot()
		if risk.LastExternalURL != urls[len(urls)-1] || len(risk.Sources) != 1 || risk.Sources[0].URL != urls[len(urls)-1] {
			t.Fatalf("iteration %d: after rotation last=%q sources=%+v, want the most recent %q", i, risk.LastExternalURL, risk.Sources, urls[len(urls)-1])
		}
	}
}
