// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/diaglog"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type taintSelectiveWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *taintSelectiveWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "MCP taint binding=") {
		w.once.Do(func() { close(w.entered) })
		<-w.release
	}
	return len(p), nil
}

func TestMCPTaintDiagnostics_BlockedLogDoesNotStallAllowedCall(t *testing.T) {
	upstream, calls := principalStateUpstream(t)
	cfg := config.Defaults()
	m := metrics.New()
	opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), TaintCfg: &cfg.Taint, Store: &listenerDiagnosisStore{}, Metrics: m}
	opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
		return ListenerPrincipal{Provider: "test", Subject: "verified"}, nil
	}
	log := &taintSelectiveWriter{entered: make(chan struct{}), release: make(chan struct{})}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunHTTPListenerProxy(ctx, ln, upstream.URL, log, opts) }()
	defer func() {
		close(log.release)
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("listener cleanup stalled")
		}
	}()
	base := "http://" + ln.Addr().String()
	waitForHTTPHealth(t, base)
	for i := range 64 {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/", strings.NewReader(string(principalControlToolCall(1, "read_file", `{}`))))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Protocol-Version", currentMCPVersion)
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", "read_file")
		client := &http.Client{Timeout: 350 * time.Millisecond}
		resp, err := client.Do(req)
		if err != nil {
			select {
			case <-log.entered:
				t.Log("taint diagnostic write entered and never returned before client deadline")
			default:
				t.Error("did not enter taint writer")
			}
			t.Fatalf("allowed call stalled on auxiliary diagnostic: %v; upstream calls=%d", err, calls.Load())
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || calls.Load() != int32(i+1) {
			t.Fatalf("status=%d calls=%d", resp.StatusCode, calls.Load())
		}
	}
	if got := taintDiagnosticMetric(t, m, "listener_principal", "active"); got != "64" {
		t.Fatalf("listener lost context counts: %s", got)
	}
}

func TestMCPTaintDiagnostics_StartupMetricExactlyOnceAndBounded(t *testing.T) {
	cfg := config.Defaults()
	for _, kind := range []string{"nil", "healthy", "error", "wedged"} {
		t.Run(kind, func(t *testing.T) {
			m := metrics.New()
			opts := MCPProxyOpts{TaintCfg: &cfg.Taint, Metrics: m}
			var w io.Writer
			var block *blockingWriter
			switch kind {
			case "healthy":
				w = io.Discard
			case "error":
				w = taintErrorWriter{}
			case "wedged":
				block = newBlockingWriter()
				w = block
				defer block.unblock()
			}
			start := time.Now()
			reportMCPTaintStartup(diaglog.New(w), opts, &taintRecorder{}, "stdio_subprocess")
			elapsed := time.Since(start)
			if elapsed > logFlushGrace+500*time.Millisecond {
				t.Errorf("startup helper took %s", elapsed)
			}
			if got := taintDiagnosticMetric(t, m, "stdio_subprocess", "active"); got != "1" {
				t.Errorf("metric=%s", got)
			}
			t.Logf("writer=%s elapsed=%s active_contexts=1", kind, elapsed)
		})
	}
}

type taintErrorWriter struct{}

func (taintErrorWriter) Write([]byte) (int, error) { return 0, errors.New("sink failed") }

type taintConcurrentWriter struct {
	buf         bytes.Buffer
	bufMu       sync.Mutex
	active      atomic.Int32
	first       sync.Once
	entered     chan struct{}
	overlap     chan struct{}
	release     chan struct{}
	overlapOnce sync.Once
}

func (w *taintConcurrentWriter) Write(p []byte) (int, error) {
	active := w.active.Add(1)
	defer w.active.Add(-1)
	if active > 1 {
		w.overlapOnce.Do(func() { close(w.overlap) })
	}
	isFirst := false
	w.first.Do(func() { isFirst = true; close(w.entered) })
	if isFirst || active > 1 {
		<-w.release
	}
	w.bufMu.Lock()
	defer w.bufMu.Unlock()
	return w.buf.Write(p)
}

func TestMCPTaintDiagnostics_StartupRetainsSharedWriterSerialization(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("subprocess fixture uses a POSIX shell")
	}
	w := &taintConcurrentWriter{entered: make(chan struct{}), overlap: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	defer func() {
		close(w.release)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("proxy cleanup timed out")
		}
	}()
	go func() {
		done <- RunProxy(context.Background(), strings.NewReader(""), io.Discard, w, []string{"/bin/sh", "-c", "echo stderr-write >&2"}, MCPProxyOpts{sessionExitForTest: liveSessionExitHooks()})
	}()
	select {
	case <-w.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("startup write never entered")
	}
	select {
	case <-w.overlap:
		t.Error("startup diagnostic and subprocess stderr concurrently invoked underlying writer despite shared writer contract")
	case err := <-done:
		done <- err
		return
	case <-time.After(2 * time.Second):
		t.Log("no overlapping writer entry observed")
	}
}

type taintRecoveryWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *taintRecoveryWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "taint refusal (") {
		w.once.Do(func() { close(w.entered) })
		<-w.release
	}
	return len(p), nil
}

func TestMCPTaintDiagnostics_BlockedRecoveryLogDoesNotHoldDenialReceipt(t *testing.T) {
	for _, surface := range []string{"http", "stdio"} {
		t.Run(surface, func(t *testing.T) {
			cfg := config.Defaults()
			rec := &taintRecorder{}
			rec.ObserveRisk(session.ClassifyMCPResponseObservation(mcpTaintSourceKind, true, true))
			emitter, r, dir := newTestReceiptEmitter(t)
			w := &taintRecoveryWriter{entered: make(chan struct{}), release: make(chan struct{})}
			opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), InputCfg: newHTTPInputCfg(config.ActionBlock), Rec: rec, TaintCfg: &cfg.Taint, ReceiptEmitter: emitter, Transport: transportMCPHTTP, PolicyHash: mcpTestPolicyHash}
			done := make(chan httpInputDecision, 1)
			go func() {
				msg := principalControlToolCall(1, "execute_command", `{"command":"id"}`)
				if surface == "http" {
					done <- scanHTTPInputDecision(msg, w, "sess", "sess", opts)
					return
				}
				opts.Transport = "mcp_stdio"
				blocked := make(chan BlockedRequest, 1)
				ForwardScannedInput(transport.NewStdioReader(bytes.NewReader(append(msg, '\n'))), transport.NewStdioWriter(io.Discard), w, config.ActionBlock, config.ActionBlock, blocked, nil, nil, opts)
				select {
				case denial := <-blocked:
					done <- httpInputDecision{Blocked: &denial}
				default:
					done <- httpInputDecision{}
				}
			}()
			check := func(d httpInputDecision) {
				t.Helper()
				if d.Blocked == nil || d.Blocked.ErrorCode != -32002 || d.Blocked.ErrorMessage != "pipelock: sensitive_action_after_hostile_external_exposure" {
					t.Errorf("denial=%+v", d.Blocked)
				}
				_ = r.Close()
				n := 0
				for _, entry := range readReceiptEntriesHTTP(t, dir) {
					if entry.Type == actionReceiptEntryType {
						n++
					}
				}
				if n != 1 {
					t.Errorf("action receipts=%d", n)
				} else {
					t.Log("exactly one denial action receipt emitted")
				}
			}
			completed := false
			defer func() {
				close(w.release)
				if !completed {
					select {
					case d := <-done:
						check(d)
					case <-time.After(4 * time.Second):
						t.Error("denial didn't unwind")
					}
				}
			}()
			select {
			case <-w.entered:
			case d := <-done:
				completed = true
				check(d)
				return
			case <-time.After(4 * time.Second):
				t.Fatal("decision and diagnostic stalled unexpectedly")
			}
			select {
			case d := <-done:
				completed = true
				check(d)
			case <-time.After(350 * time.Millisecond):
				t.Error("new recovery diagnostic blocks denial return and its deferred receipt finalizer; release is required")
			}
		})
	}
}

func waitTaintDiagnostic(t *testing.T, w *diaglog.Writer) {
	t.Helper()
	if done := w.Pending(); done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("diagnostic did not finish")
		}
	}
}

func TestMCPTaintDiagnostics_WedgedSinkBoundsGoroutinesAndCountsEveryContext(t *testing.T) {
	cfg := config.Defaults()
	m := metrics.New()
	sink := &taintSelectiveWriter{entered: make(chan struct{}), release: make(chan struct{})}
	w := diaglog.New(sink)
	defer func() { close(sink.release); waitTaintDiagnostic(t, w) }()
	now := time.Now()
	states := newMCPListenerClientStates(nil)
	states.taintReporter = newMCPListenerDegradationReporter(0, func() time.Time { return now })
	opts := MCPProxyOpts{TaintCfg: &cfg.Taint, Metrics: m}
	states.reportTaint(w, opts, nil, "listener_stateless")
	select {
	case <-sink.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("diagnostic sink was not reached")
	}
	countDrainers := func() int {
		stacks := make([]byte, 1<<20)
		n := runtime.Stack(stacks, true)
		return strings.Count(string(stacks[:n]), "internal/diaglog.(*Writer).Emit.func1()")
	}
	if got := countDrainers(); got != 1 {
		t.Fatalf("initial diagnostic goroutines=%d, want 1", got)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10000 {
			now = now.Add(listenerDegradationReportInterval)
			states.reportTaint(w, opts, nil, "listener_stateless")
			mcpTaintBlockMessage(taintDecision{}, w)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("repeated contexts stalled on the log sink")
	}
	if got := countDrainers(); got != 1 {
		t.Fatalf("wedged diagnostic goroutines=%d after repeated contexts, want 1", got)
	}
	if got := taintDiagnosticMetric(t, m, "listener_stateless", "inactive"); got != "10001" {
		t.Fatalf("busy log lost metrics: %s", got)
	}
}
